"""Risk assessment & recommendation engine.

Scoring model (documented — see README/report):

  Each analysis category contributes a weighted sub-score, capped so a single
  noisy category cannot saturate the result:

    vulnerabilities  sum of severity weights (C=10 H=6 M=3 L=1)      cap 40
    secrets          active real secret 12, historical real 6,
                     likely placeholder 0.1 (capped at 2 in total)   cap 40
    cicd             severity weights of findings                    cap 20
    docker           severity weights of findings                    cap 15
    licenses         incompatibility 5, strong copyleft 3,
                     weak copyleft 0.5, missing licenses 1           cap 15
    health           deprecated 4, not-on-registry 3, abandoned 1.5,
                     yanked 2, stale/outdated 0.25                   cap 15

  Repeated findings of the same rule (e.g. ten Dockerfiles all missing USER)
  count full weight once, then 50% each — many instances of one issue are
  one process problem, not N independent risks.

  Overall risk level:
    score  <  10   LOW
    score  <  25   MEDIUM
    score  <  50   HIGH
    score  >= 50   CRITICAL

  Rule overrides (floor, applied after scoring):
    - any ACTIVE non-placeholder secret            -> at least HIGH
    - any CRITICAL vulnerability                   -> at least HIGH
    - any CRITICAL CI/CD finding                   -> at least HIGH
"""

from __future__ import annotations

import logging

from .models import AnalysisResult, Finding, Severity
from .vulns import version_sort_key

log = logging.getLogger("sca.risk")

LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
THRESHOLDS = [(50.0, "CRITICAL"), (25.0, "HIGH"), (10.0, "MEDIUM"), (0.0, "LOW")]
CAPS = {"vulnerabilities": 40.0, "secrets": 40.0, "cicd": 20.0,
        "docker": 15.0, "licenses": 15.0, "health": 15.0}


def assess(result: AnalysisResult) -> None:
    breakdown: dict[str, float] = {}

    breakdown["vulnerabilities"] = min(
        sum(v.severity.weight for v in result.vulnerabilities),
        CAPS["vulnerabilities"])

    secret_score = placeholder_score = 0.0
    active_real = historical_real = placeholders = 0
    for s in result.secrets:
        if s.likely_placeholder:
            placeholders += 1
            placeholder_score += 0.1
        elif s.in_head:
            active_real += 1
            secret_score += 12.0
        else:
            historical_real += 1
            secret_score += 6.0
    # placeholder matches (docs/tests example values) are hygiene noise, not
    # incidents — they contribute at most 2 points in total
    secret_score += min(placeholder_score, 2.0)
    breakdown["secrets"] = min(secret_score, CAPS["secrets"])

    breakdown["cicd"] = min(
        _diminishing(result.cicd_findings, lambda f: f.severity.weight),
        CAPS["cicd"])
    breakdown["docker"] = min(
        _diminishing(result.docker_findings, lambda f: f.severity.weight),
        CAPS["docker"])

    lic = result.license_report
    lic_score = 5.0 * len(lic.incompatibilities)
    for f in lic.findings:
        if f.rule_id == "LICENSE_RESTRICTIVE":
            lic_score += 3.0 if f.severity == Severity.MEDIUM else 0.5
        elif f.rule_id in ("LICENSE_DEPS_MISSING", "LICENSE_PROJECT_MISSING"):
            lic_score += 1.0
    breakdown["licenses"] = min(lic_score, CAPS["licenses"])

    health_weights = {
        "HEALTH_DEPRECATED": 4.0, "HEALTH_NOT_ON_REGISTRY": 3.0,
        "HEALTH_ABANDONED": 1.5, "HEALTH_YANKED": 2.0,
    }
    breakdown["health"] = min(
        _diminishing(result.health_findings,
                     lambda f: health_weights.get(f.rule_id, 0.25)),
        CAPS["health"])

    score = round(sum(breakdown.values()), 1)
    level = next(lvl for threshold, lvl in THRESHOLDS if score >= threshold)

    # rule overrides (floors)
    floors: list[tuple[bool, str, str]] = [
        (active_real > 0, "HIGH",
         f"{active_real} live secret(s) present in the current tree"),
        (any(v.severity == Severity.CRITICAL for v in result.vulnerabilities),
         "HIGH", "a CRITICAL-severity vulnerability is present"),
        (any(f.severity == Severity.CRITICAL for f in result.cicd_findings),
         "HIGH", "a CRITICAL CI/CD misconfiguration is present"),
    ]
    for condition, floor, why in floors:
        if condition and LEVELS.index(level) < LEVELS.index(floor):
            level = floor
            result.risk_reasoning.append(
                f"Risk floor applied: {why}, so the overall level cannot be "
                f"below {floor}.")

    result.risk_score = score
    result.risk_level = level
    result.risk_breakdown = breakdown
    result.risk_reasoning = _reasoning(result, breakdown,
                                       active_real, historical_real,
                                       placeholders) + result.risk_reasoning
    result.recommendations = _recommendations(result)


def _diminishing(findings: list[Finding], weight_fn) -> float:
    """Full weight for the first finding of each rule, half for repeats."""
    seen: dict[str, int] = {}
    total = 0.0
    for f in findings:
        n = seen.get(f.rule_id, 0)
        total += weight_fn(f) * (1.0 if n == 0 else 0.5)
        seen[f.rule_id] = n + 1
    return total


def _reasoning(
    result: AnalysisResult, breakdown: dict[str, float],
    active_real: int, historical_real: int, placeholders: int,
) -> list[str]:
    reasons: list[str] = []
    sev_count = {s: 0 for s in Severity}
    for v in result.vulnerabilities:
        sev_count[v.severity] += 1
    if result.vulnerabilities:
        worst = [f"{n} {s.value}" for s, n in sev_count.items() if n]
        vuln_pkgs = sorted({v.package for v in result.vulnerabilities})
        reasons.append(
            f"{len(result.vulnerabilities)} known vulnerabilities "
            f"({', '.join(worst)}) affect {len(vuln_pkgs)} package(s): "
            f"{', '.join(vuln_pkgs[:6])}"
            + ("…" if len(vuln_pkgs) > 6 else "")
            + f" — contributes {breakdown['vulnerabilities']:.1f} points.")
    else:
        reasons.append("No known vulnerabilities were found in resolved dependencies.")

    if result.secrets:
        reasons.append(
            f"Secret scan over {result.repo.commit_count or '?'} commits found "
            f"{active_real} active, {historical_real} historical and "
            f"{placeholders} likely-placeholder matches — contributes "
            f"{breakdown['secrets']:.1f} points.")
    else:
        reasons.append("No secrets were detected in the full git history.")

    high_cicd = [f for f in result.cicd_findings
                 if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    if result.cicd_findings:
        reasons.append(
            f"CI/CD review raised {len(result.cicd_findings)} findings "
            f"({len(high_cicd)} high/critical), mostly "
            f"{_top_rules(result.cicd_findings)} — contributes "
            f"{breakdown['cicd']:.1f} points.")
    if result.docker_findings:
        reasons.append(
            f"Docker review raised {len(result.docker_findings)} findings "
            f"({_top_rules(result.docker_findings)}) — contributes "
            f"{breakdown['docker']:.1f} points.")
    elif not result.dockerfiles:
        reasons.append("No Dockerfile exists in the repository, so no container "
                       "risks apply.")

    lic = result.license_report
    if lic.incompatibilities:
        reasons.append(
            f"{len(lic.incompatibilities)} license incompatibilities were found "
            f"— contributes {breakdown['licenses']:.1f} points.")
    elif lic.restrictive or lic.missing_license:
        reasons.append(
            f"Licensing: {len(lic.restrictive)} restrictive and "
            f"{len(lic.missing_license)} missing dependency licenses — "
            f"contributes {breakdown['licenses']:.1f} points.")

    unhealthy = [f for f in result.health_findings
                 if f.rule_id in ("HEALTH_DEPRECATED", "HEALTH_ABANDONED",
                                  "HEALTH_NOT_ON_REGISTRY")]
    if unhealthy:
        reasons.append(
            f"Dependency health: {len(unhealthy)} deprecated/abandoned/"
            f"unresolvable packages — contributes {breakdown['health']:.1f} points.")
    return reasons


def _top_rules(findings: list[Finding]) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
    top = sorted(counts.items(), key=lambda kv: -kv[1])[:2]
    return ", ".join(f"{rule.lower()} ×{n}" for rule, n in top)


def _recommendations(result: AnalysisResult) -> list[dict[str, str]]:
    recs: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(severity: Severity, category: str, issue: str, action: str) -> None:
        key = f"{category}:{issue}"
        if key in seen:
            return
        seen.add(key)
        recs.append({
            "priority": severity.value, "category": category,
            "issue": issue, "recommendation": action,
        })

    # vulnerabilities: group by package, recommend the minimal safe upgrade
    by_pkg: dict[str, list] = {}
    for v in result.vulnerabilities:
        by_pkg.setdefault(f"{v.package}@{v.package_version}", []).append(v)
    for pkg, vulns in by_pkg.items():
        worst = min(vulns, key=lambda v: v.severity.rank)
        fixes = sorted({f for v in vulns for f in v.fixed_versions},
                       key=version_sort_key)
        ids = ", ".join(sorted({v.display_id for v in vulns})[:4])
        action = (
            f"Upgrade {pkg.split('@')[0]} to {fixes[-1]} or newer (fixes {ids})."
            if fixes else
            f"No fixed release is published for {ids}; apply vendor mitigations "
            f"or replace the package.")
        add(worst.severity, "vulnerability",
            f"{pkg} has {len(vulns)} known vulnerabilit"
            f"{'y' if len(vulns) == 1 else 'ies'} ({ids})", action)

    for s in result.secrets:
        if s.likely_placeholder:
            continue
        sev = Severity.CRITICAL if s.in_head else Severity.HIGH
        add(sev, "secret",
            f"{s.secret_type} in {s.file_path} (commit {s.commit[:10]}, {s.status})",
            f"Revoke and rotate this credential immediately — git history is "
            f"public even after deletion. Then purge it from history "
            f"(git filter-repo / BFG) and add pre-commit secret scanning "
            f"(e.g. gitleaks) to prevent recurrence.")
    placeholder_count = sum(1 for s in result.secrets if s.likely_placeholder)
    if placeholder_count:
        add(Severity.LOW, "secret",
            f"{placeholder_count} likely-placeholder secret matches in "
            "tests/docs/examples",
            "Review the flagged matches once to confirm they are dummy values; "
            "keep obviously fake values clearly labelled (e.g. 'example-key') "
            "so scanners and reviewers can dismiss them quickly.")

    for f in result.docker_findings + result.cicd_findings + \
            result.license_report.findings + result.health_findings:
        loc = f" [{f.location}]" if f.location else ""
        add(f.severity, f.category, f.title + loc, f.recommendation)

    priority_order = {s.value: s.rank for s in Severity}
    recs.sort(key=lambda r: priority_order.get(r["priority"], 9))
    return recs
