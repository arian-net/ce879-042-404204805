"""Dependency extraction: direct dependencies from manifests, transitive
dependencies from lockfiles (exact) or online resolution (approximate,
handled later by sca.registry when no lockfile exists).

Supported ecosystems:
  PyPI      requirements*.txt, pyproject.toml (PEP 621 / Poetry / PEP 735),
            setup.py, setup.cfg, Pipfile + uv.lock, poetry.lock,
            Pipfile.lock, pdm.lock
  npm       package.json + package-lock.json, yarn.lock (v1/berry),
            pnpm-lock.yaml
  Maven     pom.xml (with <properties> interpolation)
  Gradle    build.gradle / build.gradle.kts (best effort)
  Go        go.mod (direct + "// indirect" transitive)
  Cargo     Cargo.toml + Cargo.lock
  Composer  composer.json + composer.lock
  RubyGems  Gemfile.lock
"""

from __future__ import annotations

import configparser
import json
import logging
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from packaging.requirements import InvalidRequirement, Requirement

from .models import Dependency, Ecosystem

log = logging.getLogger("sca.deps")

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "env", ".env",
    ".tox", ".nox", "dist", "build", "target", "vendor", "third_party",
    "site-packages", ".mypy_cache", ".pytest_cache", ".idea", ".vscode",
}
MAX_WALK_DEPTH = 4

MANIFEST_NAMES = {
    "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
    "package.json", "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "Cargo.toml", "composer.json",
}
LOCKFILE_NAMES = {
    "uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock",
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
    "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum",
}
_REQUIREMENTS_RE = re.compile(r"^requirements[\w.-]*\.(txt|in)$", re.IGNORECASE)


class ExtractionResult:
    def __init__(self) -> None:
        self.dependencies: dict[str, Dependency] = {}
        self.resolution: str = "none"       # lockfile | go.mod | registry | deps.dev | none
        self.warnings: list[str] = []
        self.self_names: set[str] = set()   # the project's own package names
        self.manifests_found: list[str] = []
        self.lockfiles_found: list[str] = []

    def add(self, dep: Dependency) -> None:
        if dep.canonical_name in {n.lower() for n in self.self_names}:
            return
        existing = self.dependencies.get(dep.key)
        if existing is None:
            self.dependencies[dep.key] = dep
            return
        # merge: manifests win for direct/requirement/scope, lockfiles for version
        if dep.direct and not existing.direct:
            existing.direct = True
            existing.scope = dep.scope
            existing.requirement = dep.requirement or existing.requirement
        if dep.version and not existing.version:
            existing.version = dep.version
            existing.version_resolved_from = dep.version_resolved_from
        if dep.requirement and not existing.requirement:
            existing.requirement = dep.requirement
        if dep.source_file and dep.source_file not in (existing.source_file or ""):
            existing.source_file = f"{existing.source_file}, {dep.source_file}" \
                if existing.source_file else dep.source_file
        for p in dep.parents:
            if p not in existing.parents:
                existing.parents.append(p)


# --------------------------------------------------------------------------
# discovery
# --------------------------------------------------------------------------

def _find_files(root: Path) -> list[Path]:
    found: list[Path] = []

    def walk(d: Path, depth: int) -> None:
        if depth > MAX_WALK_DEPTH:
            return
        try:
            entries = sorted(d.iterdir())
        except OSError:
            return
        for entry in entries:
            if entry.is_dir():
                if entry.name in SKIP_DIRS or entry.name.startswith("."):
                    continue
                walk(entry, depth + 1)
            elif entry.is_file():
                name = entry.name
                if (name in MANIFEST_NAMES or name in LOCKFILE_NAMES
                        or _REQUIREMENTS_RE.match(name)):
                    found.append(entry)

    walk(root, 0)
    return found


def extract_dependencies(repo_path: str | Path) -> ExtractionResult:
    root = Path(repo_path)
    result = ExtractionResult()
    files = _find_files(root)

    # identify the project's own package names first so we can exclude them
    for f in files:
        try:
            if f.name == "pyproject.toml":
                data = tomllib.loads(f.read_text(errors="replace"))
                for n in (
                    (data.get("project") or {}).get("name"),
                    ((data.get("tool") or {}).get("poetry") or {}).get("name"),
                ):
                    if n:
                        result.self_names.add(str(n).lower())
            elif f.name == "package.json":
                data = json.loads(f.read_text(errors="replace"))
                if data.get("name") and f.parent == root:
                    result.self_names.add(str(data["name"]).lower())
        except Exception:
            continue

    parsers = {
        "pyproject.toml": _parse_pyproject,
        "setup.py": _parse_setup_py,
        "setup.cfg": _parse_setup_cfg,
        "Pipfile": _parse_pipfile,
        "package.json": _parse_package_json,
        "pom.xml": _parse_pom_xml,
        "build.gradle": _parse_gradle,
        "build.gradle.kts": _parse_gradle,
        "go.mod": _parse_go_mod,
        "Cargo.toml": _parse_cargo_toml,
        "composer.json": _parse_composer_json,
        # lockfiles
        "uv.lock": _parse_uv_lock,
        "poetry.lock": _parse_poetry_lock,
        "Pipfile.lock": _parse_pipfile_lock,
        "pdm.lock": _parse_pdm_lock,
        "package-lock.json": _parse_package_lock,
        "npm-shrinkwrap.json": _parse_package_lock,
        "yarn.lock": _parse_yarn_lock,
        "pnpm-lock.yaml": _parse_pnpm_lock,
        "Cargo.lock": _parse_cargo_lock,
        "composer.lock": _parse_composer_lock,
        "Gemfile.lock": _parse_gemfile_lock,
    }

    # parse manifests before lockfiles so direct/scope information lands first
    ordered = sorted(files, key=lambda f: (f.name in LOCKFILE_NAMES, len(f.parts)))
    for f in ordered:
        rel = str(f.relative_to(root))
        parser = parsers.get(f.name)
        if parser is None and _REQUIREMENTS_RE.match(f.name):
            parser = _parse_requirements_txt
        if parser is None:
            continue
        try:
            n_before = len(result.dependencies)
            parser(f, rel, result)
            is_lock = f.name in LOCKFILE_NAMES
            (result.lockfiles_found if is_lock else result.manifests_found).append(rel)
            if is_lock and len(result.dependencies) > n_before:
                result.resolution = "lockfile"
            log.debug("parsed %s (+%d deps)", rel, len(result.dependencies) - n_before)
        except Exception as exc:
            result.warnings.append(f"failed to parse {rel}: {exc}")
            log.warning("failed to parse %s: %s", rel, exc)

    if not result.manifests_found and not result.lockfiles_found:
        result.warnings.append("no dependency manifests found in the repository")
    return result


# --------------------------------------------------------------------------
# Python
# --------------------------------------------------------------------------

def _add_py_requirement(
    result: ExtractionResult, raw: str, rel: str, scope: str, direct: bool = True
) -> None:
    raw = raw.strip()
    if not raw or raw.startswith(("#", "-")) or raw.startswith(("./", "/", "file:")):
        return
    try:
        req = Requirement(raw)
    except InvalidRequirement:
        # tolerate simple "name" / "name==1.0" lines that confuse packaging
        m = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)$", raw)
        if not m:
            return
        req_name, spec = m.group(1), m.group(2).strip()
        result.add(Dependency(
            name=req_name, ecosystem=Ecosystem.PYPI, requirement=spec or None,
            direct=direct, scope=scope, source_file=rel,
        ))
        return
    if req.url:  # direct URL requirement — record without version resolution
        result.add(Dependency(
            name=req.name, ecosystem=Ecosystem.PYPI, requirement=req.url,
            direct=direct, scope=scope, source_file=rel,
        ))
        return
    spec = str(req.specifier) if req.specifier else None
    version = None
    resolved_from = None
    if req.specifier and len(req.specifier) == 1:
        s = next(iter(req.specifier))
        if s.operator in ("==", "==="):
            version = s.version
            resolved_from = "pinned"
    result.add(Dependency(
        name=req.name, ecosystem=Ecosystem.PYPI, version=version,
        requirement=spec, direct=direct, scope=scope, source_file=rel,
        version_resolved_from=resolved_from,
    ))


def _parse_requirements_txt(path: Path, rel: str, result: ExtractionResult) -> None:
    scope = "dev" if re.search(r"dev|test|lint|doc", path.name, re.I) else "runtime"
    for line in path.read_text(errors="replace").splitlines():
        line = line.split(" #")[0].strip().rstrip("\\").strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement", "-c ", "--constraint",
                            "-e ", "--editable", "--index-url", "-i ",
                            "--extra-index-url", "--find-links", "-f ",
                            "--no-binary", "--only-binary", "--hash", "--trusted-host")):
            continue  # includes are discovered independently by the file walk
        _add_py_requirement(result, line, rel, scope)


def _parse_pyproject(path: Path, rel: str, result: ExtractionResult) -> None:
    data = tomllib.loads(path.read_text(errors="replace"))
    project = data.get("project") or {}
    for raw in project.get("dependencies") or []:
        _add_py_requirement(result, raw, rel, "runtime")
    for group, reqs in (project.get("optional-dependencies") or {}).items():
        scope = "dev" if re.search(r"dev|test|lint|doc", group, re.I) else "optional"
        for raw in reqs or []:
            _add_py_requirement(result, raw, rel, scope)
    # PEP 735 dependency groups
    for group, entries in (data.get("dependency-groups") or {}).items():
        for raw in entries or []:
            if isinstance(raw, str):
                _add_py_requirement(result, raw, rel, "dev")
    # Poetry
    poetry = (data.get("tool") or {}).get("poetry") or {}
    _parse_poetry_dep_table(poetry.get("dependencies") or {}, rel, "runtime", result)
    _parse_poetry_dep_table(poetry.get("dev-dependencies") or {}, rel, "dev", result)
    for group_name, group in (poetry.get("group") or {}).items():
        scope = "dev" if re.search(r"dev|test|lint|doc", group_name, re.I) else "optional"
        _parse_poetry_dep_table((group or {}).get("dependencies") or {}, rel, scope, result)
    # build system requirements are part of the supply chain too
    for raw in (data.get("build-system") or {}).get("requires") or []:
        _add_py_requirement(result, raw, rel, "build")


def _parse_poetry_dep_table(
    table: dict, rel: str, scope: str, result: ExtractionResult
) -> None:
    for name, spec in table.items():
        if name.lower() == "python":
            continue
        requirement, version = None, None
        if isinstance(spec, str):
            requirement = spec
            m = re.match(r"^=?=?(\d[\w.!+-]*)$", spec)
            if m:
                version = m.group(1)
        elif isinstance(spec, dict):
            requirement = spec.get("version")
            if spec.get("path") or spec.get("url") or spec.get("git"):
                requirement = requirement or str(
                    spec.get("git") or spec.get("url") or spec.get("path"))
        result.add(Dependency(
            name=name, ecosystem=Ecosystem.PYPI, version=version,
            requirement=requirement, direct=True, scope=scope, source_file=rel,
            version_resolved_from="pinned" if version else None,
        ))


_SETUP_LIST_RE = re.compile(
    r"install_requires\s*=\s*\[(.*?)\]", re.DOTALL)
_SETUP_STR_RE = re.compile(r"""['"]([^'"]+)['"]""")


def _parse_setup_py(path: Path, rel: str, result: ExtractionResult) -> None:
    text = path.read_text(errors="replace")
    m = _SETUP_LIST_RE.search(text)
    if m:
        for raw in _SETUP_STR_RE.findall(m.group(1)):
            _add_py_requirement(result, raw, rel, "runtime")
    m = re.search(r"extras_require\s*=\s*\{(.*?)\}", text, re.DOTALL)
    if m:
        for raw in _SETUP_STR_RE.findall(m.group(1)):
            if re.match(r"^[A-Za-z0-9_.-]+\s*[<>=!~;\[]?", raw) and " " not in raw[:20]:
                _add_py_requirement(result, raw, rel, "optional")


def _parse_setup_cfg(path: Path, rel: str, result: ExtractionResult) -> None:
    cfg = configparser.ConfigParser()
    cfg.read_string(path.read_text(errors="replace"))
    if cfg.has_option("options", "install_requires"):
        for raw in cfg.get("options", "install_requires").splitlines():
            _add_py_requirement(result, raw, rel, "runtime")
    if cfg.has_section("options.extras_require"):
        for _, value in cfg.items("options.extras_require"):
            for raw in value.splitlines():
                _add_py_requirement(result, raw, rel, "optional")


def _parse_pipfile(path: Path, rel: str, result: ExtractionResult) -> None:
    data = tomllib.loads(path.read_text(errors="replace"))
    for section, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, spec in (data.get(section) or {}).items():
            requirement = spec if isinstance(spec, str) else (
                spec.get("version") if isinstance(spec, dict) else None)
            if requirement == "*":
                requirement = None
            version = None
            if requirement and re.match(r"^==\s*(\S+)$", requirement):
                version = requirement.replace("==", "").strip()
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.PYPI, version=version,
                requirement=requirement, direct=True, scope=scope, source_file=rel,
                version_resolved_from="pinned" if version else None,
            ))


def _parse_uv_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    data = tomllib.loads(path.read_text(errors="replace"))
    packages = data.get("package") or []
    self_names = {n.lower() for n in result.self_names}
    editable = {
        (p.get("name") or "").lower()
        for p in packages
        if isinstance(p.get("source"), dict)
        and ("editable" in p["source"] or "virtual" in p["source"])
    }
    skip = self_names | editable
    # forward edges -> reverse map for parents
    parents: dict[str, list[str]] = {}
    for p in packages:
        pname = (p.get("name") or "").lower()
        for d in p.get("dependencies") or []:
            dname = (d.get("name") if isinstance(d, dict) else str(d)).lower()
            parents.setdefault(dname, []).append(pname)
    for p in packages:
        name = p.get("name")
        if not name or name.lower() in skip:
            continue
        result.add(Dependency(
            name=name, ecosystem=Ecosystem.PYPI, version=p.get("version"),
            direct=False, scope="runtime", source_file=rel,
            version_resolved_from="lockfile",
            parents=[x for x in parents.get(name.lower(), []) if x not in skip][:8],
        ))


def _parse_poetry_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    data = tomllib.loads(path.read_text(errors="replace"))
    packages = data.get("package") or []
    parents: dict[str, list[str]] = {}
    for p in packages:
        pname = (p.get("name") or "").lower()
        for dname in (p.get("dependencies") or {}):
            parents.setdefault(dname.lower(), []).append(pname)
    for p in packages:
        name = p.get("name")
        if not name:
            continue
        scope = "dev" if p.get("category") == "dev" else "runtime"
        result.add(Dependency(
            name=name, ecosystem=Ecosystem.PYPI, version=p.get("version"),
            direct=False, scope=scope, source_file=rel,
            version_resolved_from="lockfile",
            parents=parents.get(name.lower(), [])[:8],
        ))


def _parse_pipfile_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    data = json.loads(path.read_text(errors="replace"))
    for section, scope in (("default", "runtime"), ("develop", "dev")):
        for name, spec in (data.get(section) or {}).items():
            version = None
            if isinstance(spec, dict) and isinstance(spec.get("version"), str):
                version = spec["version"].lstrip("=")
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.PYPI, version=version,
                direct=False, scope=scope, source_file=rel,
                version_resolved_from="lockfile",
            ))


def _parse_pdm_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    data = tomllib.loads(path.read_text(errors="replace"))
    for p in data.get("package") or []:
        name = p.get("name")
        if not name:
            continue
        result.add(Dependency(
            name=name, ecosystem=Ecosystem.PYPI, version=p.get("version"),
            direct=False, scope="runtime", source_file=rel,
            version_resolved_from="lockfile",
        ))


# --------------------------------------------------------------------------
# npm / yarn / pnpm
# --------------------------------------------------------------------------

def _parse_package_json(path: Path, rel: str, result: ExtractionResult) -> None:
    data = json.loads(path.read_text(errors="replace"))
    sections = (
        ("dependencies", "runtime"), ("devDependencies", "dev"),
        ("optionalDependencies", "optional"), ("peerDependencies", "optional"),
    )
    for section, scope in sections:
        for name, requirement in (data.get(section) or {}).items():
            if not isinstance(requirement, str):
                continue
            if requirement.startswith(("file:", "link:", "workspace:")):
                continue
            version = requirement if re.match(r"^\d[\w.+-]*$", requirement) else None
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.NPM, version=version,
                requirement=requirement, direct=True, scope=scope, source_file=rel,
                version_resolved_from="pinned" if version else None,
            ))


def _parse_package_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    data = json.loads(path.read_text(errors="replace"))
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfile v2/v3
        for pkg_path, meta in packages.items():
            if not pkg_path or not isinstance(meta, dict):
                continue
            name = meta.get("name")
            if not name and "node_modules/" in pkg_path:
                name = pkg_path.rsplit("node_modules/", 1)[-1]
            if not name or meta.get("link"):
                continue
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.NPM, version=meta.get("version"),
                direct=False, scope="dev" if meta.get("dev") else "runtime",
                source_file=rel, version_resolved_from="lockfile",
            ))
        return
    # lockfile v1: nested "dependencies" tree
    def walk(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.NPM, version=meta.get("version"),
                direct=False, scope="dev" if meta.get("dev") else "runtime",
                source_file=rel, version_resolved_from="lockfile",
            ))
            walk(meta.get("dependencies") or {})
    walk(data.get("dependencies") or {})


_YARN_V1_HEADER = re.compile(r'^"?((?:@[^@/"]+/)?[^@/"]+)@')


def _parse_yarn_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    text = path.read_text(errors="replace")
    if "__metadata:" in text and yaml is not None:  # yarn berry
        data = yaml.safe_load(text) or {}
        for key, meta in data.items():
            if key == "__metadata" or not isinstance(meta, dict):
                continue
            m = _YARN_V1_HEADER.match(str(key).split(",")[0].strip())
            if m and meta.get("version"):
                result.add(Dependency(
                    name=m.group(1), ecosystem=Ecosystem.NPM,
                    version=str(meta["version"]), direct=False,
                    source_file=rel, version_resolved_from="lockfile",
                ))
        return
    current: Optional[str] = None
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t", "#")):
            m = _YARN_V1_HEADER.match(line.split(",")[0].strip())
            current = m.group(1) if m else None
        elif current and line.strip().startswith("version"):
            vm = re.search(r'version\s+"?([^"\s]+)"?', line)
            if vm:
                result.add(Dependency(
                    name=current, ecosystem=Ecosystem.NPM, version=vm.group(1),
                    direct=False, source_file=rel, version_resolved_from="lockfile",
                ))
                current = None


def _parse_pnpm_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    if yaml is None:
        raise RuntimeError("PyYAML required for pnpm-lock.yaml")
    data = yaml.safe_load(path.read_text(errors="replace")) or {}
    for key in (data.get("packages") or {}):
        k = str(key).strip("/")
        k = re.sub(r"\(.*\)$", "", k)  # strip peer-dep suffixes
        if "@" not in k[1:]:
            continue
        name, _, version = k.rpartition("@")
        if name and version:
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.NPM, version=version,
                direct=False, source_file=rel, version_resolved_from="lockfile",
            ))


# --------------------------------------------------------------------------
# Maven / Gradle
# --------------------------------------------------------------------------

def _strip_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_pom_xml(path: Path, rel: str, result: ExtractionResult) -> None:
    tree = ET.parse(path)
    root = tree.getroot()
    props: dict[str, str] = {}
    for el in root.iter():
        if _strip_ns(el.tag) == "properties":
            for child in el:
                if child.text:
                    props[_strip_ns(child.tag)] = child.text.strip()

    def interp(value: Optional[str]) -> Optional[str]:
        if not value:
            return value
        return re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)),
                      value.strip())

    for el in root.iter():
        if _strip_ns(el.tag) != "dependency":
            continue
        fields = {_strip_ns(c.tag): (c.text or "").strip() for c in el}
        group, artifact = interp(fields.get("groupId")), interp(fields.get("artifactId"))
        if not group or not artifact:
            continue
        version = interp(fields.get("version"))
        if version and version.startswith("${"):
            version = None
        scope = fields.get("scope") or "runtime"
        scope = "test" if scope == "test" else ("optional" if scope == "provided" else "runtime")
        result.add(Dependency(
            name=f"{group}:{artifact}", ecosystem=Ecosystem.MAVEN, version=version,
            requirement=fields.get("version"), direct=True, scope=scope,
            source_file=rel, version_resolved_from="pinned" if version else None,
        ))


_GRADLE_DEP_RE = re.compile(
    r"""(?:implementation|api|compileOnly|runtimeOnly|testImplementation|
        testRuntimeOnly|annotationProcessor|classpath)\s*[\(\s]\s*
        ['"]([\w.-]+):([\w.-]+):([\w.+\[\],-]+)['"]""",
    re.VERBOSE,
)


def _parse_gradle(path: Path, rel: str, result: ExtractionResult) -> None:
    for group, artifact, version in _GRADLE_DEP_RE.findall(path.read_text(errors="replace")):
        scope = "test" if "test" in group.lower() else "runtime"
        result.add(Dependency(
            name=f"{group}:{artifact}", ecosystem=Ecosystem.MAVEN,
            version=version if re.match(r"^\d", version) else None,
            requirement=version, direct=True, scope=scope, source_file=rel,
            version_resolved_from="pinned" if re.match(r"^\d", version) else None,
        ))


# --------------------------------------------------------------------------
# Go / Cargo / Composer / RubyGems
# --------------------------------------------------------------------------

def _parse_go_mod(path: Path, rel: str, result: ExtractionResult) -> None:
    text = path.read_text(errors="replace")
    in_block = False
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line.startswith(")"):
            in_block = False
            continue
        m = None
        if in_block:
            m = re.match(r"^([\w./~-]+)\s+v([\w.+-]+)(\s*//\s*indirect)?", line)
        elif line.startswith("require "):
            m = re.match(r"^require\s+([\w./~-]+)\s+v([\w.+-]+)(\s*//\s*indirect)?", line)
        if m:
            indirect = bool(m.group(3))
            if indirect and result.resolution == "none":
                # go.mod (Go >= 1.17) records the module graph itself
                result.resolution = "go.mod"
            result.add(Dependency(
                name=m.group(1), ecosystem=Ecosystem.GO, version=m.group(2),
                direct=not indirect, scope="runtime", source_file=rel,
                version_resolved_from="lockfile",
            ))


def _parse_cargo_toml(path: Path, rel: str, result: ExtractionResult) -> None:
    data = tomllib.loads(path.read_text(errors="replace"))
    sections = (
        ("dependencies", "runtime"), ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    )
    for section, scope in sections:
        for name, spec in (data.get(section) or {}).items():
            requirement = spec if isinstance(spec, str) else (
                spec.get("version") if isinstance(spec, dict) else None)
            if isinstance(spec, dict) and (spec.get("path") or spec.get("git")):
                continue
            version = requirement if requirement and re.match(r"^\d[\w.+-]*$", requirement) else None
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.CARGO, version=version,
                requirement=requirement, direct=True, scope=scope, source_file=rel,
            ))


def _parse_cargo_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    data = tomllib.loads(path.read_text(errors="replace"))
    for p in data.get("package") or []:
        name, version = p.get("name"), p.get("version")
        if name and name.lower() not in {n.lower() for n in result.self_names}:
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.CARGO, version=version,
                direct=False, source_file=rel, version_resolved_from="lockfile",
            ))


def _parse_composer_json(path: Path, rel: str, result: ExtractionResult) -> None:
    data = json.loads(path.read_text(errors="replace"))
    if data.get("name"):
        result.self_names.add(str(data["name"]).lower())
    for section, scope in (("require", "runtime"), ("require-dev", "dev")):
        for name, requirement in (data.get(section) or {}).items():
            if name == "php" or name.startswith("ext-") or "/" not in name:
                continue
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.PACKAGIST,
                requirement=requirement, direct=True, scope=scope, source_file=rel,
            ))


def _parse_composer_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    data = json.loads(path.read_text(errors="replace"))
    for section, scope in (("packages", "runtime"), ("packages-dev", "dev")):
        for p in data.get(section) or []:
            name = p.get("name")
            if not name:
                continue
            result.add(Dependency(
                name=name, ecosystem=Ecosystem.PACKAGIST,
                version=str(p.get("version") or "").lstrip("v") or None,
                direct=False, scope=scope, source_file=rel,
                version_resolved_from="lockfile",
            ))


def _parse_gemfile_lock(path: Path, rel: str, result: ExtractionResult) -> None:
    text = path.read_text(errors="replace")
    direct: set[str] = set()
    m = re.search(r"^DEPENDENCIES\n((?:^ {2}\S.*\n?)+)", text, re.MULTILINE)
    if m:
        for line in m.group(1).splitlines():
            dm = re.match(r"^ {2}([\w-]+)", line)
            if dm:
                direct.add(dm.group(1))
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            if line and not line.startswith(" "):
                in_specs = False
                continue
            pm = re.match(r"^ {4}([\w-]+) \(([\w.+-]+)\)", line)
            if pm:
                name, version = pm.group(1), pm.group(2)
                result.add(Dependency(
                    name=name, ecosystem=Ecosystem.RUBYGEMS, version=version,
                    direct=name in direct, source_file=rel,
                    version_resolved_from="lockfile",
                ))
