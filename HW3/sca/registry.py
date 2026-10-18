"""Package-registry clients.

Responsibilities:
  1. Resolve concrete versions for direct dependencies declared with ranges.
  2. Resolve transitive dependencies online (deps.dev, PyPI fallback) when the
     repository ships no lockfile.
  3. Fetch per-package metadata (license, release history, deprecation) used
     by the health and license analysis stages.
"""

from __future__ import annotations

import logging
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .dependencies import ExtractionResult
from .http import HTTP
from .models import Dependency, Ecosystem

log = logging.getLogger("sca.registry")

MAX_WORKERS = 12
MAX_TRANSITIVE = 800  # safety cap for online resolution


@dataclass
class PackageMetadata:
    found: bool = False
    latest_version: Optional[str] = None
    license: Optional[str] = None
    license_source: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    repo_url: Optional[str] = None
    release_dates: list[tuple[str, str]] = field(default_factory=list)  # (version, iso date)
    deprecated: bool = False
    deprecation_message: Optional[str] = None
    yanked_latest: bool = False
    maintainers: Optional[int] = None


_metadata_cache: dict[str, PackageMetadata] = {}


def _quote(name: str) -> str:
    return urllib.parse.quote(name, safe="")


# --------------------------------------------------------------------------
# metadata fetchers
# --------------------------------------------------------------------------

def get_metadata(dep: Dependency) -> PackageMetadata:
    key = dep.key
    if key in _metadata_cache:
        return _metadata_cache[key]
    fetchers = {
        Ecosystem.PYPI: _pypi_metadata,
        Ecosystem.NPM: _npm_metadata,
        Ecosystem.CARGO: _cargo_metadata,
        Ecosystem.PACKAGIST: _packagist_metadata,
        Ecosystem.RUBYGEMS: _rubygems_metadata,
        Ecosystem.MAVEN: _depsdev_metadata,
        Ecosystem.GO: _depsdev_metadata,
    }
    try:
        meta = fetchers[dep.ecosystem](dep)
    except Exception as exc:
        log.debug("metadata fetch failed for %s: %s", key, exc)
        meta = PackageMetadata()
    _metadata_cache[key] = meta
    return meta


def prefetch_metadata(deps: list[Dependency]) -> None:
    """Fetch metadata for many packages concurrently (fills the cache)."""
    todo = [d for d in deps if d.key not in _metadata_cache]
    if not todo:
        return
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {pool.submit(get_metadata, d): d.key for d in todo}
        for fut in as_completed(futures):
            fut.exception()  # swallow; get_metadata already handles errors


def _pypi_metadata(dep: Dependency) -> PackageMetadata:
    data = HTTP.get_json(f"https://pypi.org/pypi/{_quote(dep.canonical_name)}/json")
    if not data:
        return PackageMetadata()
    info = data.get("info") or {}
    meta = PackageMetadata(found=True)
    meta.latest_version = info.get("version")
    meta.description = (info.get("summary") or "")[:300]
    meta.homepage = info.get("home_page") or (info.get("project_urls") or {}).get("Homepage")
    urls = info.get("project_urls") or {}
    for key in ("Source", "Source Code", "Repository", "Code", "GitHub", "Homepage"):
        u = urls.get(key)
        if u and "github.com" in (u or ""):
            meta.repo_url = u
            break
    # license: PEP 639 expression > classifiers > free-text license field
    lic = info.get("license_expression")
    if lic:
        meta.license, meta.license_source = lic, "license_expression"
    else:
        classifiers = [c for c in info.get("classifiers") or [] if c.startswith("License ::")]
        if classifiers:
            meta.license = _license_from_classifier(classifiers)
            meta.license_source = "classifier"
        elif info.get("license") and len(info["license"]) < 120:
            meta.license, meta.license_source = info["license"].strip(), "license_field"
    releases = data.get("releases") or {}
    for version, files in releases.items():
        dates = [f.get("upload_time_iso_8601") or f.get("upload_time")
                 for f in files or [] if isinstance(f, dict)]
        dates = [d for d in dates if d]
        if dates:
            meta.release_dates.append((version, min(dates)))
    if meta.latest_version:
        latest_files = releases.get(meta.latest_version) or []
        if latest_files and all(f.get("yanked") for f in latest_files):
            meta.yanked_latest = True
    meta.deprecated = "Development Status :: 7 - Inactive" in (info.get("classifiers") or [])
    return meta


_CLASSIFIER_TO_SPDX = {
    "MIT License": "MIT",
    "Apache Software License": "Apache-2.0",
    "BSD License": "BSD-3-Clause",
    "ISC License (ISCL)": "ISC",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "GNU General Public License v2 (GPLv2)": "GPL-2.0-only",
    "GNU General Public License v2 or later (GPLv2+)": "GPL-2.0-or-later",
    "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU General Public License v3 or later (GPLv3+)": "GPL-3.0-or-later",
    "GNU Lesser General Public License v2 or later (LGPLv2+)": "LGPL-2.1-or-later",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only",
    "GNU Affero General Public License v3": "AGPL-3.0-only",
    "GNU Affero General Public License v3 or later (AGPLv3+)": "AGPL-3.0-or-later",
    "Python Software Foundation License": "PSF-2.0",
    "The Unlicense (Unlicense)": "Unlicense",
    "Zope Public License": "ZPL-2.1",
}


def _license_from_classifier(classifiers: list[str]) -> str:
    names = [c.split("::")[-1].strip() for c in classifiers]
    mapped = [_CLASSIFIER_TO_SPDX.get(n, n) for n in names if n != "OSI Approved"]
    # multiple license classifiers conventionally mean dual licensing (a choice)
    return " OR ".join(dict.fromkeys(mapped)) if mapped else "UNKNOWN"


def _npm_metadata(dep: Dependency) -> PackageMetadata:
    data = HTTP.get_json(f"https://registry.npmjs.org/{_quote(dep.name)}")
    if not data:
        return PackageMetadata()
    meta = PackageMetadata(found=True)
    meta.latest_version = (data.get("dist-tags") or {}).get("latest")
    meta.description = (data.get("description") or "")[:300]
    lic = data.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    if lic:
        meta.license, meta.license_source = str(lic), "registry"
    repo = data.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    if isinstance(repo, str):
        meta.repo_url = repo
    meta.homepage = data.get("homepage")
    for version, date in (data.get("time") or {}).items():
        if version not in ("created", "modified"):
            meta.release_dates.append((version, date))
    versions = data.get("versions") or {}
    latest_meta = versions.get(meta.latest_version or "") or {}
    if latest_meta.get("deprecated"):
        meta.deprecated = True
        meta.deprecation_message = str(latest_meta["deprecated"])[:200]
    meta.maintainers = len(data.get("maintainers") or []) or None
    return meta


def _cargo_metadata(dep: Dependency) -> PackageMetadata:
    data = HTTP.get_json(f"https://crates.io/api/v1/crates/{_quote(dep.name)}")
    if not data:
        return PackageMetadata()
    crate = data.get("crate") or {}
    meta = PackageMetadata(found=True)
    meta.latest_version = crate.get("max_stable_version") or crate.get("max_version")
    meta.description = (crate.get("description") or "")[:300]
    meta.homepage = crate.get("homepage")
    meta.repo_url = crate.get("repository")
    for v in data.get("versions") or []:
        if v.get("num") and v.get("created_at"):
            meta.release_dates.append((v["num"], v["created_at"]))
        if v.get("num") == meta.latest_version and v.get("license"):
            meta.license, meta.license_source = v["license"], "registry"
    return meta


def _packagist_metadata(dep: Dependency) -> PackageMetadata:
    data = HTTP.get_json(f"https://repo.packagist.org/p2/{dep.name}.json")
    if not data:
        return PackageMetadata()
    versions = ((data.get("packages") or {}).get(dep.name)) or []
    if not versions:
        return PackageMetadata()
    meta = PackageMetadata(found=True)
    latest = versions[0]
    meta.latest_version = str(latest.get("version") or "").lstrip("v") or None
    meta.description = (latest.get("description") or "")[:300]
    lic = latest.get("license")
    if lic:
        meta.license = " OR ".join(lic) if isinstance(lic, list) else str(lic)
        meta.license_source = "registry"
    meta.repo_url = latest.get("source", {}).get("url") if isinstance(latest.get("source"), dict) else None
    for v in versions:
        if v.get("version") and v.get("time"):
            meta.release_dates.append((str(v["version"]).lstrip("v"), v["time"]))
    if latest.get("abandoned"):
        meta.deprecated = True
        repl = latest["abandoned"]
        meta.deprecation_message = (
            f"abandoned; use {repl}" if isinstance(repl, str) else "abandoned")
    return meta


def _rubygems_metadata(dep: Dependency) -> PackageMetadata:
    data = HTTP.get_json(f"https://rubygems.org/api/v1/gems/{_quote(dep.name)}.json")
    if not data:
        return PackageMetadata()
    meta = PackageMetadata(found=True)
    meta.latest_version = data.get("version")
    meta.description = (data.get("info") or "")[:300]
    meta.homepage = data.get("homepage_uri")
    meta.repo_url = data.get("source_code_uri")
    if data.get("licenses"):
        meta.license = " OR ".join(data["licenses"])
        meta.license_source = "registry"
    versions = HTTP.get_json(
        f"https://rubygems.org/api/v1/versions/{_quote(dep.name)}.json")
    for v in versions or []:
        if v.get("number") and v.get("created_at"):
            meta.release_dates.append((v["number"], v["created_at"]))
    return meta


def _depsdev_metadata(dep: Dependency) -> PackageMetadata:
    system = dep.ecosystem.depsdev_system
    if not system:
        return PackageMetadata()
    name = _quote(dep.name)
    data = HTTP.get_json(f"https://api.deps.dev/v3/systems/{system}/packages/{name}")
    if not data:
        return PackageMetadata()
    is_go = dep.ecosystem == Ecosystem.GO
    meta = PackageMetadata(found=True)
    for v in data.get("versions") or []:
        version = (v.get("versionKey") or {}).get("version")
        published = v.get("publishedAt")
        if version and is_go:
            # normalize to the tool-wide convention (go.mod parser strips "v")
            version = version.lstrip("v")
        if version and published:
            meta.release_dates.append((version, published))
        if v.get("isDefault"):
            meta.latest_version = version
    version_for_license = dep.version or meta.latest_version
    if version_for_license:
        if is_go and not version_for_license.startswith("v"):
            # deps.dev requires the "v" prefix for Go module versions
            version_for_license = f"v{version_for_license}"
        vdata = HTTP.get_json(
            f"https://api.deps.dev/v3/systems/{system}/packages/{name}"
            f"/versions/{_quote(version_for_license)}")
        if vdata:
            licenses = vdata.get("licenses") or []
            if licenses:
                meta.license = " AND ".join(licenses)
                meta.license_source = "deps.dev"
            for link in vdata.get("links") or []:
                if link.get("label") == "SOURCE_REPO":
                    meta.repo_url = link.get("url")
    return meta


# --------------------------------------------------------------------------
# version resolution for direct deps declared with ranges
# --------------------------------------------------------------------------

def resolve_missing_versions(deps: list[Dependency]) -> None:
    todo = [d for d in deps if not d.version]
    if not todo:
        return
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        list(pool.map(_resolve_one_version, todo))


def _resolve_one_version(dep: Dependency) -> None:
    meta = get_metadata(dep)
    if not meta.found:
        return
    candidates = [v for v, _ in meta.release_dates] or (
        [meta.latest_version] if meta.latest_version else [])
    chosen: Optional[str] = None
    if dep.ecosystem == Ecosystem.PYPI and dep.requirement:
        chosen = _best_pypi_version(candidates, dep.requirement)
    elif dep.ecosystem == Ecosystem.NPM and dep.requirement:
        chosen = _best_semver_version(candidates, dep.requirement)
    if not chosen:
        chosen = meta.latest_version
        dep.version_resolved_from = "registry-latest"
    else:
        dep.version_resolved_from = "registry-range"
    dep.version = chosen


def _best_pypi_version(candidates: list[str], spec: str) -> Optional[str]:
    try:
        sset = SpecifierSet(spec)
    except InvalidSpecifier:
        return None
    parsed = []
    for c in candidates:
        try:
            parsed.append(Version(c))
        except InvalidVersion:
            continue
    matching = [v for v in parsed if v in sset and not v.is_prerelease]
    if not matching:
        matching = [v for v in parsed if v in sset]
    return str(max(matching)) if matching else None


_SEMVER_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)")


def _best_semver_version(candidates: list[str], range_spec: str) -> Optional[str]:
    """Small npm range matcher: ^, ~, exact, >=, x-ranges, *; best effort."""
    range_spec = range_spec.strip()
    stable = [c for c in candidates if _SEMVER_RE.match(c) and "-" not in c]

    def parse(v: str) -> tuple[int, int, int]:
        m = _SEMVER_RE.match(v)
        return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (0, 0, 0)

    def newest(matches: list[str]) -> Optional[str]:
        return max(matches, key=parse) if matches else None

    if range_spec in ("*", "latest", "x", ""):
        return newest(stable)
    m = re.match(r"^([\^~]?)v?(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", range_spec)
    if not m:
        return None
    op, maj = m.group(1), int(m.group(2))
    minor = m.group(3) if m.group(3) not in (None, "x", "*") else None
    patch = m.group(4) if m.group(4) not in (None, "x", "*") else None
    lo: tuple[int, int, int] = (maj, int(minor or 0), int(patch or 0))
    if op == "^":
        hi = (maj + 1, 0, 0) if maj > 0 else (0, int(minor or 0) + 1, 0)
    elif op == "~" or (minor is not None and patch is None):
        hi = (maj, int(minor or 0) + 1, 0)
    elif minor is None:
        hi = (maj + 1, 0, 0)
    else:  # exact
        hi = (lo[0], lo[1], lo[2] + 1)
    matches = [c for c in stable if lo <= parse(c) < hi]
    return newest(matches)


# --------------------------------------------------------------------------
# online transitive resolution (no lockfile available)
# --------------------------------------------------------------------------

def resolve_transitive_online(extraction: ExtractionResult) -> None:
    """Approximate the transitive closure using deps.dev resolved graphs,
    falling back to naive PyPI requires_dist recursion."""
    direct = [d for d in extraction.dependencies.values() if d.direct]
    resolve_missing_versions(direct)

    used_depsdev = False
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(_depsdev_dependencies, d): d
            for d in direct
            if d.version and d.ecosystem.depsdev_system
        }
        for fut in as_completed(futures):
            parent = futures[fut]
            try:
                nodes = fut.result()
            except Exception as exc:
                log.debug("deps.dev resolution failed for %s: %s", parent.key, exc)
                continue
            if nodes is None:
                continue
            used_depsdev = True
            for node in nodes:
                if len(extraction.dependencies) >= MAX_TRANSITIVE:
                    break
                node.parents = [parent.name]
                node.source_file = f"resolved via deps.dev (from {parent.name})"
                extraction.add(node)

    if used_depsdev:
        extraction.resolution = "deps.dev"
        return

    # fallback: naive recursive PyPI resolution
    pypi_direct = [d for d in direct if d.ecosystem == Ecosystem.PYPI and d.version]
    if pypi_direct:
        _naive_pypi_resolution(extraction, pypi_direct)
        extraction.resolution = "registry"
    elif direct and extraction.resolution == "none":
        # a "go.mod" resolution already carries the module graph, so only
        # warn when the analysis really is limited to direct dependencies
        extraction.warnings.append(
            "no lockfile and online transitive resolution unavailable; "
            "analysis covers direct dependencies only")


def _depsdev_dependencies(dep: Dependency) -> Optional[list[Dependency]]:
    system = dep.ecosystem.depsdev_system
    version = dep.version or ""
    if dep.ecosystem == Ecosystem.GO and not version.startswith("v"):
        version = f"v{version}"
    url = (f"https://api.deps.dev/v3/systems/{system}/packages/{_quote(dep.name)}"
           f"/versions/{_quote(version)}:dependencies")
    data = HTTP.get_json(url)
    if not data:
        return None
    out: list[Dependency] = []
    for node in data.get("nodes") or []:
        if node.get("relation") == "SELF":
            continue
        vk = node.get("versionKey") or {}
        name, version = vk.get("name"), vk.get("version")
        if not name or not version:
            continue
        if dep.ecosystem == Ecosystem.GO:
            version = version.lstrip("v")
        out.append(Dependency(
            name=name, ecosystem=dep.ecosystem, version=version,
            direct=False, scope=dep.scope, version_resolved_from="deps.dev",
        ))
    return out


def _naive_pypi_resolution(
    extraction: ExtractionResult, roots: list[Dependency]
) -> None:
    seen: set[str] = {d.canonical_name for d in roots}
    frontier = list(roots)
    depth = 0
    while frontier and depth < 10 and len(extraction.dependencies) < MAX_TRANSITIVE:
        depth += 1
        next_frontier: list[Dependency] = []
        for dep in frontier:
            data = HTTP.get_json(
                f"https://pypi.org/pypi/{_quote(dep.canonical_name)}/{_quote(dep.version or '')}/json")
            if not data:
                continue
            for raw in (data.get("info") or {}).get("requires_dist") or []:
                try:
                    from packaging.requirements import Requirement
                    req = Requirement(raw)
                except Exception:
                    continue
                if req.marker and "extra" in str(req.marker):
                    continue  # skip extras we did not ask for
                child = Dependency(
                    name=req.name, ecosystem=Ecosystem.PYPI,
                    requirement=str(req.specifier) or None, direct=False,
                    scope=dep.scope, parents=[dep.name],
                    source_file=f"resolved via PyPI (from {dep.name})",
                )
                if child.canonical_name in seen:
                    existing = extraction.dependencies.get(child.key)
                    if existing and dep.name not in existing.parents:
                        existing.parents.append(dep.name)
                    continue
                seen.add(child.canonical_name)
                _resolve_one_version(child)
                child.version_resolved_from = "registry"
                extraction.add(child)
                next_frontier.append(child)
        frontier = next_frontier
