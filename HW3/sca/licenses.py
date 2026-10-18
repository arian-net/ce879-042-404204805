"""License analysis.

- identify the project's primary license (GitHub API, manifest metadata,
  LICENSE file content heuristics)
- extract dependency licenses from registry metadata
- flag missing/unspecified licenses
- highlight restrictive (copyleft) or unusual licenses
- report license incompatibilities between the project and its dependencies
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Optional

from .models import Dependency, Finding, LicenseReport, RepoInfo, Severity
from .registry import get_metadata, prefetch_metadata

log = logging.getLogger("sca.licenses")

PERMISSIVE = {
    "MIT", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "BSD-4-CLAUSE", "ISC",
    "0BSD", "PSF-2.0", "ZLIB", "X11", "UNLICENSE", "CC0-1.0", "WTFPL",
    "ARTISTIC-2.0", "BSL-1.0", "MIT-0", "APACHE SOFTWARE LICENSE", "PYTHON-2.0",
    "BLUEOAK-1.0.0",
}
WEAK_COPYLEFT = {
    "LGPL-2.0-ONLY", "LGPL-2.0-OR-LATER", "LGPL-2.1-ONLY", "LGPL-2.1-OR-LATER",
    "LGPL-3.0-ONLY", "LGPL-3.0-OR-LATER", "LGPL-2.1", "LGPL-3.0",
    "MPL-2.0", "MPL-1.1", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1",
    "OSL-3.0", "EUPL-1.2", "CECILL-C",
}
STRONG_COPYLEFT = {
    "GPL-2.0-ONLY", "GPL-2.0-OR-LATER", "GPL-3.0-ONLY", "GPL-3.0-OR-LATER",
    "GPL-2.0", "GPL-3.0", "AGPL-3.0-ONLY", "AGPL-3.0-OR-LATER", "AGPL-3.0",
    "AGPL-1.0", "SSPL-1.0", "CECILL-2.1",
}
# project licenses that cannot include GPL-2.0-only code
_GPL2_INCOMPATIBLE_HOSTS = {"APACHE-2.0"}


def categorize(license_id: Optional[str]) -> str:
    if not license_id or license_id.upper() in ("UNKNOWN", "NOASSERTION", "NONE", "UNLICENSED"):
        return "unknown"
    # SPDX expressions: take the *most* restrictive part for AND,
    # the least restrictive for OR (the consumer can choose).
    expr = license_id.upper().replace("(", " ").replace(")", " ")
    if " OR " in expr:
        cats = [categorize(part.strip()) for part in expr.split(" OR ")]
        for pick in ("permissive", "weak-copyleft", "strong-copyleft"):
            if pick in cats:
                return pick
        return cats[0] if cats else "unknown"
    if " AND " in expr:
        cats = [categorize(part.strip()) for part in expr.split(" AND ")]
        for pick in ("strong-copyleft", "weak-copyleft"):
            if pick in cats:
                return pick
        if all(c == "permissive" for c in cats):
            return "permissive"
        return "other"
    token = expr.strip().rstrip("+")
    if token in PERMISSIVE or token.rstrip("+") in PERMISSIVE:
        return "permissive"
    if token in WEAK_COPYLEFT:
        return "weak-copyleft"
    if token in STRONG_COPYLEFT:
        return "strong-copyleft"
    for name in PERMISSIVE:
        if token.startswith(name):
            return "permissive"
    if token.startswith(("ARTISTIC", "BSD", "APACHE", "MIT", "ZLIB", "PSF")):
        return "permissive"
    if token.startswith(("LGPL", "MPL", "EPL", "CDDL")):
        return "weak-copyleft"
    if token.startswith(("AGPL", "GPL", "SSPL")):
        return "strong-copyleft"
    return "other"


_LICENSE_FILE_PATTERNS = (
    (re.compile(r"Permission is hereby granted, free of charge", re.I), "MIT"),
    (re.compile(r"Apache License,?\s*Version 2\.0", re.I), "Apache-2.0"),
    (re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE.*Version 3", re.I | re.S), "AGPL-3.0-only"),
    (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 3", re.I | re.S), "LGPL-3.0-only"),
    (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE.*Version 2\.1", re.I | re.S), "LGPL-2.1-only"),
    (re.compile(r"GNU GENERAL PUBLIC LICENSE.*Version 3", re.I | re.S), "GPL-3.0-only"),
    (re.compile(r"GNU GENERAL PUBLIC LICENSE.*Version 2", re.I | re.S), "GPL-2.0-only"),
    (re.compile(r"Mozilla Public License,?\s*(?:Version\s*)?2\.0", re.I), "MPL-2.0"),
    (re.compile(r"Redistribution and use in source and binary forms.*neither the name",
                re.I | re.S), "BSD-3-Clause"),
    (re.compile(r"Redistribution and use in source and binary forms", re.I), "BSD-2-Clause"),
    (re.compile(r"Internet Systems Consortium|ISC License", re.I), "ISC"),
    (re.compile(r"This is free and unencumbered software released into the public domain",
                re.I), "Unlicense"),
    (re.compile(r"Boost Software License", re.I), "BSL-1.0"),
)


def detect_project_license(repo: RepoInfo) -> tuple[Optional[str], Optional[str]]:
    """Return (license_id, source)."""
    if repo.github_license_spdx:
        return repo.github_license_spdx, "GitHub API"
    root = Path(repo.local_path or ".")
    # manifest declarations
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            import tomllib
            data = tomllib.loads(pyproject.read_text(errors="replace"))
            lic = (data.get("project") or {}).get("license")
            if isinstance(lic, str) and len(lic) < 60:
                return lic, "pyproject.toml"
            if isinstance(lic, dict) and lic.get("text") and len(lic["text"]) < 60:
                return lic["text"], "pyproject.toml"
        except Exception:
            pass
    package_json = root / "package.json"
    if package_json.exists():
        try:
            import json
            lic = json.loads(package_json.read_text(errors="replace")).get("license")
            if isinstance(lic, str):
                return lic, "package.json"
        except Exception:
            pass
    # LICENSE file content
    for candidate in ("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE",
                      "COPYING", "LICENSE.rst"):
        f = root / candidate
        if f.exists():
            text = f.read_text(errors="replace")[:8000]
            for pattern, spdx in _LICENSE_FILE_PATTERNS:
                if pattern.search(text):
                    return spdx, f"{candidate} (content match)"
            return "UNKNOWN", f"{candidate} (unrecognized text)"
    return None, None


def analyze_licenses(repo: RepoInfo, deps: list[Dependency]) -> LicenseReport:
    report = LicenseReport()
    lic, source = detect_project_license(repo)
    report.project_license = lic
    report.project_license_source = source
    report.project_license_category = categorize(lic)

    if lic is None:
        report.findings.append(Finding(
            category="license", rule_id="LICENSE_PROJECT_MISSING",
            severity=Severity.MEDIUM,
            title="Project has no detectable license",
            description=(
                "No LICENSE file or license declaration was found. Without a "
                "license the project is 'all rights reserved' by default, which "
                "blocks legal reuse and redistribution."),
            recommendation="Add a LICENSE file with an explicit OSI-approved license.",
        ))

    prefetch_metadata(deps)
    for dep in deps:
        meta = get_metadata(dep)
        if meta.license and not dep.license:
            dep.license = meta.license
            dep.license_source = meta.license_source
        report.dependency_licenses[dep.name] = dep.license or "UNKNOWN"
        cat = categorize(dep.license)
        entry = {
            "package": dep.name, "version": dep.version or "?",
            "license": dep.license or "UNKNOWN", "category": cat,
            "direct": str(dep.direct),
        }
        if not dep.license:
            report.missing_license.append(dep.name)
        elif cat == "strong-copyleft":
            report.restrictive.append(entry)
        elif cat == "weak-copyleft":
            report.restrictive.append(entry)
        elif cat == "other":
            report.unusual.append(entry)

    if report.missing_license:
        sample = ", ".join(report.missing_license[:8])
        more = f" (+{len(report.missing_license) - 8} more)" \
            if len(report.missing_license) > 8 else ""
        report.findings.append(Finding(
            category="license", rule_id="LICENSE_DEPS_MISSING",
            severity=Severity.LOW,
            title=f"{len(report.missing_license)} dependencies without a "
                  "declared license",
            description=(
                f"No license metadata could be determined for: {sample}{more}. "
                "Undeclared licenses default to 'all rights reserved' and are a "
                "legal/compliance risk."),
            recommendation=(
                "Inspect these packages' repositories manually and record their "
                "actual licenses; replace packages that truly have none."),
        ))

    project_cat = report.project_license_category
    for entry in report.restrictive:
        cat = entry["category"]
        pkg, dep_lic = entry["package"], entry["license"]
        incompatible = False
        reason = ""
        if cat == "strong-copyleft":
            if project_cat in ("permissive", "unknown", "other", "weak-copyleft"):
                incompatible = True
                reason = (
                    f"'{pkg}' is {dep_lic} (strong copyleft). Distributing this "
                    f"{lic or 'unlicensed'} project with a {dep_lic} dependency "
                    "generally requires relicensing the combined work under "
                    f"{dep_lic.split('-')[0]} terms.")
            if "AGPL" in dep_lic.upper():
                reason += (" AGPL additionally triggers source-disclosure "
                           "obligations for network/SaaS use.")
        if (lic or "").upper() in _GPL2_INCOMPATIBLE_HOSTS and \
                dep_lic.upper().startswith("GPL-2.0") and "LATER" not in dep_lic.upper():
            incompatible = True
            reason = (f"Apache-2.0 is incompatible with GPL-2.0-only "
                      f"('{pkg}'): the two licenses cannot be combined in one work.")
        if incompatible:
            item = {"package": pkg, "license": dep_lic,
                    "project_license": lic or "none", "reason": reason.strip()}
            report.incompatibilities.append(item)
            report.findings.append(Finding(
                category="license", rule_id="LICENSE_INCOMPATIBLE",
                severity=Severity.MEDIUM,
                title=f"License conflict: {pkg} ({dep_lic}) vs project "
                      f"({lic or 'no license'})",
                description=reason.strip(),
                recommendation=(
                    f"Replace '{pkg}' with a permissively-licensed alternative, "
                    "isolate it behind a separate process/service boundary, or "
                    "adopt a compatible project license after legal review."),
                metadata={"package": pkg},
            ))
        elif cat in ("strong-copyleft", "weak-copyleft"):
            report.findings.append(Finding(
                category="license", rule_id="LICENSE_RESTRICTIVE",
                severity=Severity.LOW if cat == "weak-copyleft" else Severity.MEDIUM,
                title=f"Restrictive license: {pkg} is {dep_lic}",
                description=(
                    f"'{pkg}' uses {dep_lic} ({cat}). This imposes obligations "
                    "(source disclosure of modifications, license preservation) "
                    "when the project is distributed."),
                recommendation=(
                    f"Confirm the usage of '{pkg}' complies with {dep_lic} "
                    "(dynamic linking / unmodified use is usually fine for weak "
                    "copyleft); document the obligation in your compliance records."),
                metadata={"package": pkg},
            ))

    return report
