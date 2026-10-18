"""Report generation: JSON (machine-readable), Markdown (human-readable),
and a console summary."""

from __future__ import annotations

import json
import logging
from collections import Counter
from pathlib import Path

from .health import health_summary
from .http import utcnow_iso
from .models import AnalysisResult, Severity

log = logging.getLogger("sca.report")

_LEVEL_EMOJI = {"LOW": "🟢", "MEDIUM": "🟡", "HIGH": "🟠", "CRITICAL": "🔴"}


def write_json(result: AnalysisResult, path: str | Path) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = {"generated_at": utcnow_iso(), **result.to_dict()}
    # RepoInfo.local_path is machine-specific noise in a shareable report
    doc.get("repo", {}).pop("local_path", None)
    p.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    return str(p)


def write_markdown(result: AnalysisResult, path: str | Path) -> str:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(render_markdown(result))
    return str(p)


def render_markdown(result: AnalysisResult) -> str:
    r = result.repo
    deps = result.dependencies
    direct = [d for d in deps if d.direct]
    lines: list[str] = []
    add = lines.append

    add(f"# Supply Chain Security Report — {r.full_name}")
    add("")
    add(f"- **Repository:** {r.url}")
    if r.description:
        add(f"- **Description:** {r.description}")
    add(f"- **Analyzed commit:** `{(r.head_commit or 'unknown')[:12]}` "
        f"on branch `{r.default_branch or '?'}` "
        f"({r.commit_count or '?'} commits in history)")
    if r.stars is not None:
        add(f"- **GitHub:** {r.stars}★, {r.forks} forks, "
            f"{r.open_issues} open issues"
            + (", **ARCHIVED**" if r.archived else ""))
    add(f"- **Generated:** {utcnow_iso()}")
    add("")

    # ---- risk assessment ------------------------------------------------
    emoji = _LEVEL_EMOJI.get(result.risk_level or "", "")
    add("## 1. Risk Assessment")
    add("")
    add(f"### Overall risk level: {emoji} **{result.risk_level}** "
        f"(score {result.risk_score})")
    add("")
    add("| Category | Score contribution |")
    add("|---|---|")
    for cat, score in sorted(result.risk_breakdown.items(), key=lambda kv: -kv[1]):
        add(f"| {cat} | {score:.1f} |")
    add("")
    add("**Reasoning:**")
    add("")
    for reason in result.risk_reasoning:
        add(f"- {reason}")
    add("")
    add("*Scoring criteria: severity-weighted findings per category "
        "(CRITICAL=10, HIGH=6, MEDIUM=3, LOW=1; active secrets 12, historical 6, "
        "placeholders ≤2 total), "
        "each category capped (vulns/secrets 40, CI/CD 20, Docker/licenses/health 15); "
        "repeated findings of the same rule count 50% after the first. "
        "Bands: <10 LOW, <25 MEDIUM, <50 HIGH, ≥50 CRITICAL. Floors: an active "
        "secret, a CRITICAL vulnerability or a CRITICAL CI/CD finding each force "
        "at least HIGH.*")
    add("")

    # ---- components -----------------------------------------------------
    add("## 2. Component & Dependency Analysis")
    add("")
    eco_counts = Counter(d.ecosystem.value for d in deps)
    add(f"- **Total components:** {len(deps)} "
        f"({len(direct)} direct, {len(deps) - len(direct)} transitive)")
    add(f"- **Ecosystems:** " + ", ".join(f"{e} ({n})" for e, n in eco_counts.most_common()))
    add(f"- **Transitive resolution:** {result.transitive_resolution}")
    if result.sbom_path:
        add(f"- **SBOM:** CycloneDX 1.5 → `{Path(result.sbom_path).name}`")
    add("")
    add("### Direct dependencies")
    add("")
    add("| Package | Ecosystem | Declared | Resolved | Scope | License | Health |")
    add("|---|---|---|---|---|---|---|")
    for d in sorted(direct, key=lambda d: d.name.lower()):
        health = d.health.status if d.health else "?"
        add(f"| {d.name} | {d.ecosystem.value} | `{d.requirement or '*'}` "
            f"| {d.version or '?'} | {d.scope} | {d.license or 'UNKNOWN'} | {health} |")
    add("")

    # ---- vulnerabilities --------------------------------------------------
    add("## 3. Vulnerability Analysis")
    add("")
    if result.vulnerabilities:
        sev_counts = Counter(v.severity.value for v in result.vulnerabilities)
        add(f"**{len(result.vulnerabilities)} known vulnerabilities** — "
            + ", ".join(f"{sev_counts[s]} {s}" for s in
                        ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev_counts.get(s)))
        add("")
        add("| Package | Version | ID (CVE) | Severity | CVSS | Fixed in | Summary |")
        add("|---|---|---|---|---|---|---|")
        for v in result.vulnerabilities:
            fixed = ", ".join(v.fixed_versions[-2:]) or "—"
            cvss = f"{v.cvss_score}" if v.cvss_score is not None else "—"
            osv_id = v.id if v.id != v.display_id else ""
            ident = v.display_id + (f" ({osv_id})" if osv_id else "")
            summary = v.summary.replace("|", "\\|")[:110]
            add(f"| {v.package} | {v.package_version} | {ident} "
                f"| {v.severity.value} | {cvss} | {fixed} | {summary} |")
    else:
        add("No known vulnerabilities were found in the resolved dependency set "
            "(source: OSV.dev).")
    add("")

    # ---- health -----------------------------------------------------------
    add("## 4. Dependency Health Analysis")
    add("")
    counts = health_summary(deps)
    add("| Status | Count |")
    add("|---|---|")
    for status in ("HEALTHY", "AGING", "STALE", "ABANDONED", "DEPRECATED", "UNKNOWN"):
        if counts.get(status):
            add(f"| {status} | {counts[status]} |")
    add("")
    add("*Metrics: days since last release, releases in the last 365 days, total "
        "releases, registry deprecation/yanked flags, version lag. "
        "Classification: DEPRECATED (registry flag), ABANDONED (>3y since last "
        "release), STALE (18–36 months), AGING (6–18 months with <2 releases/yr), "
        "otherwise HEALTHY.*")
    add("")
    problem_findings = [f for f in result.health_findings]
    if problem_findings:
        add("### Health findings")
        add("")
        for f in sorted(problem_findings, key=lambda f: f.severity.rank):
            add(f"- **[{f.severity.value}] {f.title}** — {f.description}")
    add("")

    # ---- licenses -----------------------------------------------------------
    lic = result.license_report
    add("## 5. License Analysis")
    add("")
    add(f"- **Project license:** {lic.project_license or 'NOT FOUND'} "
        f"({lic.project_license_category or '?'}; source: "
        f"{lic.project_license_source or '—'})")
    known = sum(1 for v in lic.dependency_licenses.values() if v != "UNKNOWN")
    add(f"- **Dependency licenses identified:** {known}/{len(lic.dependency_licenses)}")
    add(f"- **Missing/unspecified:** {len(lic.missing_license)}"
        + (f" — {', '.join(lic.missing_license[:10])}"
           + ("…" if len(lic.missing_license) > 10 else "")
           if lic.missing_license else ""))
    add("")
    lic_counts = Counter(lic.dependency_licenses.values())
    add("| License | Packages |")
    add("|---|---|")
    for license_id, n in lic_counts.most_common(15):
        add(f"| {license_id} | {n} |")
    add("")
    if lic.restrictive:
        add("### Restrictive / copyleft licenses")
        add("")
        for e in lic.restrictive:
            add(f"- **{e['package']}** {e['version']}: {e['license']} "
                f"({e['category']}, {'direct' if e['direct'] == 'True' else 'transitive'})")
        add("")
    if lic.unusual:
        add("### Unusual / non-standard licenses")
        add("")
        for e in lic.unusual[:20]:
            add(f"- **{e['package']}** {e['version']}: {e['license']}")
        add("")
    if lic.incompatibilities:
        add("### ⚠️ License incompatibilities")
        add("")
        for inc in lic.incompatibilities:
            add(f"- **{inc['package']}** ({inc['license']}) vs project "
                f"({inc['project_license']}): {inc['reason']}")
        add("")
    elif lic.project_license:
        add("No incompatibilities were detected between the project license and "
            "its dependencies.")
        add("")

    # ---- secrets ------------------------------------------------------------
    add("## 6. Secret Detection (full git history)")
    add("")
    if result.secrets:
        real = [s for s in result.secrets if not s.likely_placeholder]
        placeholder = [s for s in result.secrets if s.likely_placeholder]
        add(f"**{len(result.secrets)} matches** — {len(real)} likely real, "
            f"{len(placeholder)} likely placeholders (test/docs/example values).")
        add("")
        add("| Type | Location | Commit | Date | Status | Placeholder? |")
        add("|---|---|---|---|---|---|")
        for s in result.secrets[:60]:
            date = (s.commit_date or "?")[:10]
            add(f"| {s.secret_type} | `{s.file_path}:{s.line}` "
                f"| `{s.commit[:10]}` | {date} "
                f"| {'ACTIVE' if s.in_head else 'historical'} "
                f"| {'likely' if s.likely_placeholder else 'no'} |")
        if len(result.secrets) > 60:
            add(f"| … | +{len(result.secrets) - 60} more in report.json | | | | |")
    else:
        add(f"No secrets were detected across "
            f"{result.repo.commit_count or '?'} commits of history.")
    add("")

    # ---- docker ------------------------------------------------------------
    add("## 7. Docker Security Analysis")
    add("")
    if not result.dockerfiles:
        add("No Dockerfile was found in the repository — container checks were "
            "skipped.")
    else:
        add(f"Analyzed: {', '.join('`' + d + '`' for d in result.dockerfiles)}")
        add("")
        _findings_table(add, result.docker_findings)
    add("")

    # ---- cicd -------------------------------------------------------------
    add("## 8. CI/CD Security Analysis")
    add("")
    if not result.workflow_files:
        add("No CI/CD pipeline definitions were found.")
    else:
        add(f"Analyzed {len(result.workflow_files)} pipeline files.")
        add("")
        _findings_table(add, result.cicd_findings)
    add("")

    # ---- recommendations -----------------------------------------------------
    add("## 9. Recommendations")
    add("")
    if result.recommendations:
        add("| Priority | Category | Issue | Recommendation |")
        add("|---|---|---|---|")
        for rec in result.recommendations:
            issue = rec["issue"].replace("|", "\\|")
            action = rec["recommendation"].replace("|", "\\|")
            add(f"| {rec['priority']} | {rec['category']} | {issue} | {action} |")
    else:
        add("No actionable issues were discovered.")
    add("")

    if result.warnings:
        add("## Analysis warnings")
        add("")
        for w in result.warnings:
            add(f"- {w}")
        add("")
    return "\n".join(lines)


def _findings_table(add, findings) -> None:
    if not findings:
        add("No issues found.")
        return
    add("| Severity | Rule | Finding | Location |")
    add("|---|---|---|---|")
    for f in sorted(findings, key=lambda f: f.severity.rank):
        add(f"| {f.severity.value} | `{f.rule_id}` "
            f"| {f.title.replace('|', chr(92) + '|')} | `{f.location or '—'}` |")


# ---------------------------------------------------------------------------
# console summary
# ---------------------------------------------------------------------------

def print_console_summary(result: AnalysisResult) -> None:
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:
        _print_plain(result)
        return

    console = Console()
    color = {"LOW": "green", "MEDIUM": "yellow",
             "HIGH": "dark_orange", "CRITICAL": "red"}.get(result.risk_level or "", "white")
    deps = result.dependencies
    direct = sum(1 for d in deps if d.direct)
    sev = Counter(v.severity.value for v in result.vulnerabilities)
    real_secrets = [s for s in result.secrets if not s.likely_placeholder]

    console.print(Panel(
        f"[bold {color}]{_LEVEL_EMOJI.get(result.risk_level or '', '')} "
        f"OVERALL RISK: {result.risk_level}[/]  (score {result.risk_score})\n"
        f"[dim]{result.repo.full_name} @ {(result.repo.head_commit or '?')[:12]}[/]",
        title="sca — supply chain analysis", expand=False))

    table = Table(show_header=True, header_style="bold")
    table.add_column("Stage")
    table.add_column("Result")
    table.add_row("Components",
                  f"{len(deps)} ({direct} direct / {len(deps) - direct} transitive), "
                  f"resolution: {result.transitive_resolution}")
    table.add_row("Vulnerabilities",
                  ", ".join(f"{sev[s]} {s}" for s in
                            ("CRITICAL", "HIGH", "MEDIUM", "LOW") if sev.get(s))
                  or "none found")
    table.add_row("Secrets",
                  f"{len(real_secrets)} likely real / "
                  f"{len(result.secrets) - len(real_secrets)} placeholders"
                  if result.secrets else "none found")
    table.add_row("Docker",
                  f"{len(result.docker_findings)} findings in "
                  f"{len(result.dockerfiles)} Dockerfile(s)"
                  if result.dockerfiles else "no Dockerfile")
    table.add_row("CI/CD",
                  f"{len(result.cicd_findings)} findings in "
                  f"{len(result.workflow_files)} pipeline file(s)"
                  if result.workflow_files else "no pipelines found")
    lic = result.license_report
    table.add_row("Licenses",
                  f"project: {lic.project_license or 'NOT FOUND'}; "
                  f"{len(lic.incompatibilities)} incompatibilities, "
                  f"{len(lic.missing_license)} missing")
    counts = health_summary(deps)
    table.add_row("Health", ", ".join(f"{v} {k}" for k, v in counts.items()))
    console.print(table)

    top: list[dict[str, str]] = []
    seen_actions: set[str] = set()
    for rec in result.recommendations:
        if rec["recommendation"] not in seen_actions:
            seen_actions.add(rec["recommendation"])
            top.append(rec)
        if len(top) == 5:
            break
    if top:
        console.print("\n[bold]Top recommendations:[/]")
        for i, rec in enumerate(top, 1):
            console.print(f"  {i}. [{color}][{rec['priority']}][/] {rec['recommendation']}")


def _print_plain(result: AnalysisResult) -> None:
    print(f"\n=== OVERALL RISK: {result.risk_level} (score {result.risk_score}) ===")
    print(f"Repository: {result.repo.full_name}")
    print(f"Components: {len(result.dependencies)}  "
          f"Vulnerabilities: {len(result.vulnerabilities)}  "
          f"Secrets: {len(result.secrets)}  "
          f"Docker findings: {len(result.docker_findings)}  "
          f"CI/CD findings: {len(result.cicd_findings)}")
    for reason in result.risk_reasoning:
        print(f"  - {reason}")
