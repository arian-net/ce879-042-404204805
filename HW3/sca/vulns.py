"""Vulnerability analysis via the OSV.dev database.

For every dependency with a resolved version we run a batched OSV query,
then fetch full advisory records to extract CVE ids, severity (GHSA label
or computed CVSS v3 base score), a description, and the fixed versions."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from packaging.version import InvalidVersion, Version

from .cvss import cvss3_base_score, is_cve, severity_from_score
from .http import HTTP
from .models import Dependency, Ecosystem, Severity, Vulnerability


def version_sort_key(v: str):
    """Sort versions numerically when possible (lexicographic puts 1.9 > 1.10)."""
    try:
        return (0, Version(v), "")
    except InvalidVersion:
        return (1, Version("0"), v)

log = logging.getLogger("sca.vulns")

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
BATCH_SIZE = 250


def scan_dependencies(deps: list[Dependency]) -> list[Vulnerability]:
    queryable = [d for d in deps if d.version]
    skipped = len(deps) - len(queryable)
    if skipped:
        log.info("%d dependencies without a resolved version were not scanned", skipped)

    vuln_ids_per_dep: dict[int, list[str]] = {}
    for start in range(0, len(queryable), BATCH_SIZE):
        chunk = queryable[start:start + BATCH_SIZE]
        payload = {"queries": [_osv_query(d) for d in chunk]}
        data = HTTP.post_json(OSV_BATCH_URL, payload, timeout=60)
        if data is None:
            log.warning("OSV batch query failed for %d packages", len(chunk))
            continue
        for i, res in enumerate(data.get("results") or []):
            ids = [v["id"] for v in res.get("vulns") or [] if v.get("id")]
            if ids:
                vuln_ids_per_dep[start + i] = ids

    # fetch advisory details (deduplicated across packages)
    all_ids = sorted({vid for ids in vuln_ids_per_dep.values() for vid in ids})
    details: dict[str, Optional[dict]] = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(HTTP.get_json, OSV_VULN_URL.format(id=vid)): vid
            for vid in all_ids
        }
        for fut in as_completed(futures):
            details[futures[fut]] = fut.result()

    vulnerabilities: list[Vulnerability] = []
    for idx, ids in vuln_ids_per_dep.items():
        dep = queryable[idx]
        for vid in ids:
            vuln = _build_vulnerability(vid, details.get(vid), dep)
            vulnerabilities.append(vuln)
            dep.vulnerabilities.append(vuln)
    vulnerabilities.sort(key=lambda v: (v.severity.rank, v.package))
    return vulnerabilities


def _osv_query(dep: Dependency) -> dict:
    name = dep.canonical_name if dep.ecosystem == Ecosystem.PYPI else dep.name
    return {
        "package": {"name": name, "ecosystem": dep.ecosystem.value},
        "version": dep.version,
    }


def _build_vulnerability(
    vid: str, record: Optional[dict], dep: Dependency
) -> Vulnerability:
    vuln = Vulnerability(
        id=vid, package=dep.name, package_version=dep.version or "?",
        ecosystem=dep.ecosystem.value,
    )
    if not record:
        return vuln
    aliases = record.get("aliases") or []
    vuln.aliases = aliases
    vuln.cve_ids = [a for a in aliases if is_cve(a)]
    if is_cve(vid):
        vuln.cve_ids.insert(0, vid)
    vuln.summary = (record.get("summary") or "").strip()
    vuln.details = (record.get("details") or "").strip()[:600]
    if not vuln.summary:
        vuln.summary = vuln.details.split("\n")[0][:200] or f"Advisory {vid}"
    vuln.references = [
        r.get("url") for r in record.get("references") or [] if r.get("url")
    ][:5]

    # severity: prefer CVSS v3 vector; fall back to GHSA severity label
    score: Optional[float] = None
    vector: Optional[str] = None
    for sev in record.get("severity") or []:
        if sev.get("type") in ("CVSS_V3",):
            vector = sev.get("score")
            score = cvss3_base_score(vector or "")
            if score is not None:
                break
    label: Optional[str] = severity_from_score(score)
    db_specific = record.get("database_specific") or {}
    if label is None and isinstance(db_specific.get("severity"), str):
        label = db_specific["severity"].upper().replace("MODERATE", "MEDIUM")
    vuln.cvss_score = score
    vuln.cvss_vector = vector
    if label in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        vuln.severity = Severity(label)

    # fixed versions from affected ranges matching this package
    fixed: list[str] = []
    for affected in record.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("ecosystem") != dep.ecosystem.value:
            continue
        pkg_name = (pkg.get("name") or "").lower().replace("_", "-")
        dep_name = dep.canonical_name.lower()
        if pkg_name != dep_name and pkg.get("name") != dep.name:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed.append(event["fixed"])
    vuln.fixed_versions = sorted(set(fixed), key=version_sort_key)
    return vuln
