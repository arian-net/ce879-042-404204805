"""Dependency health analysis.

Metrics (documented in the report):
  M1  days since the latest release on the package registry
  M2  release cadence: number of releases in the last 365 days
  M3  total number of releases (project maturity signal)
  M4  deprecation / abandonment flag from the registry
      (npm "deprecated", Packagist "abandoned", PyPI "Development Status ::
      7 - Inactive" classifier, latest release yanked)
  M5  version lag: dependency pinned far behind the latest release

Status classification:
  DEPRECATED  registry explicitly marks the package deprecated/abandoned
  ABANDONED   last release more than 3 years ago
  STALE       last release 1.5–3 years ago
  AGING       last release 0.5–1.5 years ago AND <2 releases in last year
  HEALTHY     otherwise
  UNKNOWN     no registry data available
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

from .models import Dependency, Finding, HealthInfo, Severity
from .registry import get_metadata, prefetch_metadata

log = logging.getLogger("sca.health")

ABANDONED_DAYS = 3 * 365
STALE_DAYS = 548           # ~18 months
AGING_DAYS = 183           # ~6 months


def _parse_date(value: str) -> Optional[datetime]:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def analyze_health(deps: list[Dependency]) -> list[Finding]:
    prefetch_metadata(deps)
    now = datetime.now(timezone.utc)
    findings: list[Finding] = []

    for dep in deps:
        meta = get_metadata(dep)
        health = HealthInfo()
        dep.health = health
        if not meta.found:
            health.notes.append("package not found on its registry")
            findings.append(Finding(
                category="health", rule_id="HEALTH_NOT_ON_REGISTRY",
                severity=Severity.MEDIUM,
                title=f"{dep.name}: not found on the public registry",
                description=(
                    f"Dependency '{dep.name}' ({dep.ecosystem.value}) could not be "
                    "found on its public registry. It may be internal/private — "
                    "a classic dependency-confusion attack surface."),
                location=dep.source_file,
                recommendation=(
                    f"Verify where '{dep.name}' is expected to come from. If it is a "
                    "private package, ensure the install configuration pins the "
                    "private registry (scoped registry / --index-url) so a public "
                    "package with the same name cannot be substituted."),
                metadata={"package": dep.name},
            ))
            continue

        dep.latest_version = meta.latest_version
        dated = [(_parse_date(dt), v) for v, dt in meta.release_dates]
        dated = [(d, v) for d, v in dated if d is not None]
        if dated:
            last_date = max(d for d, _ in dated)
            health.last_release_date = last_date.date().isoformat()
            health.days_since_last_release = (now - last_date).days
            health.releases_last_year = sum(
                1 for d, _ in dated if (now - d).days <= 365)
            health.total_releases = len(dated)
        health.deprecated = meta.deprecated
        health.yanked = meta.yanked_latest
        health.deprecation_message = meta.deprecation_message

        health.status = _classify(health)

        if health.status == "DEPRECATED":
            msg = f" Registry message: {health.deprecation_message}" \
                if health.deprecation_message else ""
            findings.append(Finding(
                category="health", rule_id="HEALTH_DEPRECATED",
                severity=Severity.HIGH,
                title=f"{dep.name}: deprecated by its maintainers",
                description=(
                    f"'{dep.name}' {dep.version or ''} is explicitly marked "
                    f"deprecated/abandoned on its registry.{msg} Deprecated packages "
                    "receive no security fixes."),
                location=dep.source_file,
                recommendation=(
                    f"Migrate off '{dep.name}'. "
                    + (f"The maintainers suggest: {health.deprecation_message}."
                       if health.deprecation_message else
                       "Find a maintained alternative or fork and patch internally.")),
                metadata={"package": dep.name},
            ))
        elif health.status == "ABANDONED":
            findings.append(Finding(
                category="health", rule_id="HEALTH_ABANDONED",
                severity=Severity.MEDIUM,
                title=f"{dep.name}: appears abandoned "
                      f"(no release in {health.days_since_last_release} days)",
                description=(
                    f"The last release of '{dep.name}' was on "
                    f"{health.last_release_date}, more than 3 years ago. "
                    "Vulnerabilities found in it are unlikely to be fixed upstream."),
                location=dep.source_file,
                recommendation=(
                    f"Evaluate whether '{dep.name}' is still needed; prefer an "
                    "actively maintained alternative, or accept and document the risk."),
                metadata={"package": dep.name},
            ))
        elif health.status == "STALE" and dep.direct:
            findings.append(Finding(
                category="health", rule_id="HEALTH_STALE",
                severity=Severity.LOW,
                title=f"{dep.name}: stale "
                      f"(no release in {health.days_since_last_release} days)",
                description=(
                    f"'{dep.name}' has had no release since {health.last_release_date} "
                    "and shows little maintenance activity."),
                location=dep.source_file,
                recommendation=f"Monitor '{dep.name}' for abandonment and plan an exit strategy.",
                metadata={"package": dep.name},
            ))

        if health.yanked:
            findings.append(Finding(
                category="health", rule_id="HEALTH_YANKED",
                severity=Severity.MEDIUM,
                title=f"{dep.name}: latest release is yanked",
                description=(
                    f"The latest release of '{dep.name}' was yanked from the registry, "
                    "usually because it is broken or harmful."),
                location=dep.source_file,
                recommendation=f"Pin '{dep.name}' to the most recent non-yanked release.",
                metadata={"package": dep.name},
            ))

        # M5: version lag for direct, pinned dependencies
        if (dep.direct and dep.version and meta.latest_version
                and dep.version != meta.latest_version):
            lag_days = _lag_days(dep.version, meta.latest_version, meta.release_dates, now)
            if lag_days is not None and lag_days > 2 * 365:
                findings.append(Finding(
                    category="health", rule_id="HEALTH_OUTDATED_PIN",
                    severity=Severity.LOW,
                    title=f"{dep.name}: pinned version is {lag_days // 365}+ years old",
                    description=(
                        f"'{dep.name}' resolves to {dep.version} while the latest "
                        f"release is {meta.latest_version}. Old versions miss both "
                        "bug fixes and silent security hardening."),
                    location=dep.source_file,
                    recommendation=f"Upgrade '{dep.name}' from {dep.version} "
                                   f"to {meta.latest_version}.",
                    metadata={"package": dep.name},
                ))
    return findings


def _classify(health: HealthInfo) -> str:
    if health.deprecated:
        return "DEPRECATED"
    days = health.days_since_last_release
    if days is None:
        return "UNKNOWN"
    if days > ABANDONED_DAYS:
        return "ABANDONED"
    if days > STALE_DAYS:
        return "STALE"
    if days > AGING_DAYS and (health.releases_last_year or 0) < 2:
        return "AGING"
    return "HEALTHY"


def _lag_days(
    current: str, latest: str, release_dates: list[tuple[str, str]], now
) -> Optional[int]:
    dates = {v: _parse_date(dt) for v, dt in release_dates}
    cur = dates.get(current)
    if cur is None:
        return None
    return (now - cur).days


def health_summary(deps: list[Dependency]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for dep in deps:
        status = dep.health.status if dep.health else "UNKNOWN"
        counts[status] = counts.get(status, 0) + 1
    return counts
