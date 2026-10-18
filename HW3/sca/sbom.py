"""SBOM generation in CycloneDX 1.5 JSON format."""

from __future__ import annotations

import json
import uuid
from pathlib import Path

from . import __version__
from .http import utcnow_iso
from .models import AnalysisResult, Dependency


def _component(dep: Dependency) -> dict:
    comp: dict = {
        "type": "library",
        "bom-ref": dep.purl,
        "name": dep.name,
        "purl": dep.purl,
    }
    if dep.version:
        comp["version"] = dep.version
    if dep.description:
        comp["description"] = dep.description
    if dep.license:
        # emit as expression when it looks like one, else as name
        if any(tok in dep.license for tok in (" AND ", " OR ", " WITH ")):
            comp["licenses"] = [{"expression": dep.license}]
        else:
            comp["licenses"] = [{"license": {"name": dep.license}}]
    comp["scope"] = "excluded" if dep.scope in ("dev", "test", "build") else (
        "optional" if dep.scope == "optional" else "required")
    props = [
        {"name": "sca:direct", "value": str(dep.direct).lower()},
        {"name": "sca:scope", "value": dep.scope},
    ]
    if dep.source_file:
        props.append({"name": "sca:source", "value": dep.source_file})
    comp["properties"] = props
    return comp


def generate_cyclonedx(result: AnalysisResult, output_path: str | Path) -> str:
    repo = result.repo
    root_ref = f"pkg:github/{repo.full_name}@{(repo.head_commit or 'HEAD')[:12]}" \
        if repo.owner else (repo.name or "root-project")

    by_ref = {d.purl: d for d in result.dependencies}
    dependencies_section = [{
        "ref": root_ref,
        "dependsOn": sorted(d.purl for d in result.dependencies if d.direct),
    }]
    # lockfile parent edges -> dependency graph entries
    name_to_purl = {d.canonical_name: d.purl for d in result.dependencies}
    for dep in result.dependencies:
        children = [
            name_to_purl[c.canonical_name]
            for c in result.dependencies
            if dep.canonical_name in [p.lower().replace("_", "-") for p in c.parents]
        ]
        if children:
            dependencies_section.append(
                {"ref": dep.purl, "dependsOn": sorted(set(children))})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": utcnow_iso(),
            "tools": [{
                "vendor": "sca",
                "name": "supply-chain-analyzer",
                "version": __version__,
            }],
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": repo.full_name,
                "version": (repo.head_commit or "HEAD")[:12],
                **({"description": repo.description} if repo.description else {}),
                "externalReferences": [{"type": "vcs", "url": repo.url}],
                **({"licenses": [{"license": {"id": result.license_report.project_license}}]}
                   if result.license_report.project_license
                   and result.license_report.project_license != "UNKNOWN" else {}),
            },
        },
        "components": [_component(d) for d in sorted(
            result.dependencies, key=lambda d: (not d.direct, d.name.lower()))],
        "dependencies": dependencies_section,
    }

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(bom, indent=2))
    return str(path)
