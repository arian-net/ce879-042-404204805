"""Shared data model for all analysis stages."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> float:
        return {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 6.0,
            Severity.MEDIUM: 3.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.0,
        }[self]

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


class Ecosystem(str, enum.Enum):
    """Package ecosystems, named to match OSV.dev / purl conventions."""

    PYPI = "PyPI"
    NPM = "npm"
    MAVEN = "Maven"
    GO = "Go"
    CARGO = "crates.io"
    PACKAGIST = "Packagist"
    RUBYGEMS = "RubyGems"

    @property
    def purl_type(self) -> str:
        return {
            Ecosystem.PYPI: "pypi",
            Ecosystem.NPM: "npm",
            Ecosystem.MAVEN: "maven",
            Ecosystem.GO: "golang",
            Ecosystem.CARGO: "cargo",
            Ecosystem.PACKAGIST: "composer",
            Ecosystem.RUBYGEMS: "gem",
        }[self]

    @property
    def depsdev_system(self) -> Optional[str]:
        return {
            Ecosystem.PYPI: "pypi",
            Ecosystem.NPM: "npm",
            Ecosystem.MAVEN: "maven",
            Ecosystem.GO: "go",
            Ecosystem.CARGO: "cargo",
        }.get(self)


@dataclass
class Dependency:
    name: str
    ecosystem: Ecosystem
    version: Optional[str] = None          # resolved/pinned version if known
    requirement: Optional[str] = None      # raw declared constraint (e.g. ">=2.0,<3")
    direct: bool = True
    scope: str = "runtime"                 # runtime | dev | optional | test
    source_file: Optional[str] = None      # manifest/lockfile it came from
    version_resolved_from: Optional[str] = None  # lockfile | pinned | registry-latest | deps.dev
    parents: list[str] = field(default_factory=list)  # names of dependents (graph edge)

    # enrichment (filled in by later stages)
    license: Optional[str] = None
    license_source: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    latest_version: Optional[str] = None
    health: Optional[HealthInfo] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.ecosystem.value}:{self.canonical_name}"

    @property
    def canonical_name(self) -> str:
        if self.ecosystem == Ecosystem.PYPI:
            return self.name.lower().replace("_", "-").replace(".", "-")
        return self.name

    @property
    def purl(self) -> str:
        name = self.name
        if self.ecosystem == Ecosystem.PYPI:
            name = self.canonical_name
        version = f"@{self.version}" if self.version else ""
        if self.ecosystem == Ecosystem.MAVEN and ":" in name:
            group, artifact = name.split(":", 1)
            return f"pkg:maven/{group}/{artifact}{version}"
        return f"pkg:{self.ecosystem.purl_type}/{name}{version}"


@dataclass
class HealthInfo:
    status: str = "UNKNOWN"                # HEALTHY | AGING | STALE | ABANDONED | DEPRECATED | UNKNOWN
    last_release_date: Optional[str] = None
    days_since_last_release: Optional[int] = None
    releases_last_year: Optional[int] = None
    total_releases: Optional[int] = None
    deprecated: bool = False
    yanked: bool = False
    deprecation_message: Optional[str] = None
    notes: list[str] = field(default_factory=list)


@dataclass
class Vulnerability:
    id: str                                # OSV id (GHSA-..., PYSEC-..., CVE-...)
    package: str
    package_version: str
    ecosystem: str
    cve_ids: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    summary: str = ""
    details: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)

    @property
    def display_id(self) -> str:
        """Prefer a CVE id when one exists."""
        return self.cve_ids[0] if self.cve_ids else self.id


@dataclass
class SecretFinding:
    secret_type: str
    file_path: str
    line: Optional[int]
    match_preview: str                     # redacted preview of the match
    commit: str
    commit_author: Optional[str]
    commit_date: Optional[str]
    in_head: bool                          # still present in the current tree?
    likely_placeholder: bool = False
    entropy: Optional[float] = None

    @property
    def status(self) -> str:
        if self.in_head:
            return "ACTIVE (present in current tree)"
        return "HISTORICAL (removed from current tree, still in git history)"


@dataclass
class Finding:
    """Generic finding used by Docker / CI/CD / license / health / risk stages."""

    category: str                          # e.g. "docker", "cicd", "license", "secret", "vulnerability"
    rule_id: str                           # e.g. "DOCKER_LATEST_TAG"
    severity: Severity
    title: str
    description: str
    location: Optional[str] = None         # file[:line]
    recommendation: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class LicenseReport:
    project_license: Optional[str] = None
    project_license_source: Optional[str] = None
    project_license_category: Optional[str] = None
    dependency_licenses: dict[str, str] = field(default_factory=dict)
    missing_license: list[str] = field(default_factory=list)
    restrictive: list[dict[str, str]] = field(default_factory=list)
    unusual: list[dict[str, str]] = field(default_factory=list)
    incompatibilities: list[dict[str, str]] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)


@dataclass
class RepoInfo:
    url: str
    owner: Optional[str] = None
    name: Optional[str] = None
    local_path: Optional[str] = None
    default_branch: Optional[str] = None
    head_commit: Optional[str] = None
    commit_count: Optional[int] = None
    description: Optional[str] = None
    stars: Optional[int] = None
    forks: Optional[int] = None
    open_issues: Optional[int] = None
    archived: Optional[bool] = None
    pushed_at: Optional[str] = None
    created_at: Optional[str] = None
    github_license_spdx: Optional[str] = None

    @property
    def full_name(self) -> str:
        if self.owner and self.name:
            return f"{self.owner}/{self.name}"
        return self.name or self.url


@dataclass
class AnalysisResult:
    """Aggregate of every stage — input to the risk engine and reports."""

    repo: RepoInfo
    dependencies: list[Dependency] = field(default_factory=list)
    transitive_resolution: str = "none"    # lockfile | go.mod | deps.dev | registry | none
    sbom_path: Optional[str] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    secrets: list[SecretFinding] = field(default_factory=list)
    docker_findings: list[Finding] = field(default_factory=list)
    dockerfiles: list[str] = field(default_factory=list)
    cicd_findings: list[Finding] = field(default_factory=list)
    workflow_files: list[str] = field(default_factory=list)
    license_report: LicenseReport = field(default_factory=LicenseReport)
    health_findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    # risk engine output
    risk_level: Optional[str] = None
    risk_score: Optional[float] = None
    risk_reasoning: list[str] = field(default_factory=list)
    risk_breakdown: dict[str, float] = field(default_factory=dict)
    recommendations: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        def convert(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):
                return {k: convert(v) for k, v in asdict(obj).items()}
            if isinstance(obj, dict):
                return {k: convert(v) for k, v in obj.items()}
            if isinstance(obj, list):
                return [convert(v) for v in obj]
            return obj

        return convert(self)  # type: ignore[return-value]
