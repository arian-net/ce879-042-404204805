"""Command-line interface and pipeline orchestration."""

from __future__ import annotations

import argparse
import logging
import shutil
import sys
import time
from pathlib import Path

from . import __version__
from .cicd import analyze_cicd
from .dependencies import extract_dependencies
from .docker import analyze_docker
from .health import analyze_health
from .licenses import analyze_licenses
from .llm import generate_executive_summary
from .models import AnalysisResult
from .registry import resolve_missing_versions, resolve_transitive_online
from .repo import RepoError, acquire_repo
from .report import print_console_summary, write_json, write_markdown
from .risk import assess
from .sbom import generate_cyclonedx
from .secrets import scan_repository
from .vulns import scan_dependencies

log = logging.getLogger("sca")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sca",
        description="Software supply chain security analyzer: dependency/SBOM/"
                    "vulnerability/license/health analysis, git-history secret "
                    "detection, Docker & CI/CD review, and risk assessment for "
                    "a GitHub repository.",
    )
    parser.add_argument("repo_url", help="GitHub repository URL to analyze")
    parser.add_argument(
        "--local-path", metavar="DIR",
        help="use an existing local clone instead of cloning (offline testing)")
    parser.add_argument(
        "-o", "--output-dir", default="output",
        help="directory for reports and SBOM (default: ./output/<repo>)")
    parser.add_argument(
        "--skip-secrets", action="store_true",
        help="skip the git-history secret scan (fastest stage to skip on huge repos)")
    parser.add_argument(
        "--skip-health", action="store_true",
        help="skip dependency health metadata collection")
    parser.add_argument(
        "--llm-summary", action="store_true",
        help="BONUS: generate an LLM executive summary "
             "(needs OPENROUTER_API_KEY, or ANTHROPIC_API_KEY + "
             "'pip install anthropic')")
    parser.add_argument(
        "--keep-clone", action="store_true",
        help="keep the temporary clone instead of deleting it")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--version", action="version", version=f"sca {__version__}")
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)-14s %(levelname)-7s %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    started = time.time()

    # ---- stage 0: acquire repository -----------------------------------
    log.info("[0/8] Acquiring repository %s", args.repo_url)
    try:
        repo = acquire_repo(args.repo_url, local_path=args.local_path)
    except RepoError as exc:
        log.error("cannot acquire repository: %s", exc)
        return 2
    result = AnalysisResult(repo=repo)
    repo_path = Path(repo.local_path)  # type: ignore[arg-type]
    cloned_temp = args.local_path is None

    out_dir = Path(args.output_dir) / (repo.name or "repository")
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        # ---- stage 1: dependency extraction -----------------------------
        log.info("[1/8] Extracting dependencies (manifests + lockfiles)")
        extraction = extract_dependencies(repo_path)
        if extraction.resolution in ("none", "go.mod") and extraction.dependencies:
            log.info("      no lockfile found; resolving transitive deps online")
            resolve_transitive_online(extraction)
        resolve_missing_versions(list(extraction.dependencies.values()))
        result.warnings.extend(extraction.warnings)
        result.dependencies = sorted(
            extraction.dependencies.values(),
            key=lambda d: (not d.direct, d.name.lower()))
        result.transitive_resolution = extraction.resolution
        direct_n = sum(1 for d in result.dependencies if d.direct)
        log.info("      %d dependencies (%d direct, %d transitive; resolution: %s)",
                 len(result.dependencies), direct_n,
                 len(result.dependencies) - direct_n, extraction.resolution)

        # ---- stage 2: license analysis (also fetches registry metadata) --
        log.info("[2/8] Analyzing licenses (project + %d dependencies)",
                 len(result.dependencies))
        result.license_report = analyze_licenses(repo, result.dependencies)

        # ---- stage 3: dependency health ----------------------------------
        if args.skip_health:
            log.info("[3/8] Dependency health: skipped (--skip-health)")
        else:
            log.info("[3/8] Analyzing dependency health")
            result.health_findings = analyze_health(result.dependencies)

        # ---- stage 4: SBOM ------------------------------------------------
        log.info("[4/8] Generating CycloneDX SBOM")
        result.sbom_path = generate_cyclonedx(result, out_dir / "sbom.cyclonedx.json")

        # ---- stage 5: vulnerabilities -------------------------------------
        log.info("[5/8] Querying OSV.dev for known vulnerabilities")
        result.vulnerabilities = scan_dependencies(result.dependencies)
        log.info("      %d vulnerabilities found", len(result.vulnerabilities))

        # ---- stage 6: secrets ---------------------------------------------
        if args.skip_secrets:
            log.info("[6/8] Secret scan: skipped (--skip-secrets)")
        else:
            log.info("[6/8] Scanning full git history for secrets "
                     "(%s commits)", repo.commit_count or "?")
            result.secrets = scan_repository(repo_path)
            log.info("      %d secret findings", len(result.secrets))

        # ---- stage 7: docker + ci/cd ----------------------------------------
        log.info("[7/8] Analyzing Dockerfiles and CI/CD pipelines")
        result.docker_findings, result.dockerfiles = analyze_docker(repo_path)
        result.cicd_findings, result.workflow_files = analyze_cicd(repo_path)
        log.info("      %d Dockerfile(s): %d findings; %d pipeline file(s): %d findings",
                 len(result.dockerfiles), len(result.docker_findings),
                 len(result.workflow_files), len(result.cicd_findings))

        # ---- stage 8: risk assessment ----------------------------------------
        log.info("[8/8] Risk assessment & recommendations")
        assess(result)

        # ---- outputs ------------------------------------------------------
        json_path = write_json(result, out_dir / "report.json")
        md_path = write_markdown(result, out_dir / "report.md")

        if args.llm_summary:
            log.info("[bonus] Generating LLM executive summary")
            summary = generate_executive_summary(result)
            if summary:
                exec_path = out_dir / "executive_summary.md"
                exec_path.write_text(
                    f"# Executive Security Report — {repo.full_name}\n\n{summary}\n")
                log.info("        written to %s", exec_path)
            else:
                log.warning("        LLM summary unavailable (see log above)")

        print_console_summary(result)
        print(f"\nOutputs ({time.time() - started:.0f}s total):")
        print(f"  SBOM (CycloneDX): {result.sbom_path}")
        print(f"  JSON report:      {json_path}")
        print(f"  Markdown report:  {md_path}")
        if args.llm_summary and (out_dir / "executive_summary.md").exists():
            print(f"  Executive report: {out_dir / 'executive_summary.md'}")

        return 0
    finally:
        if cloned_temp and not args.keep_clone:
            shutil.rmtree(repo_path, ignore_errors=True)


def main() -> None:
    try:
        sys.exit(run())
    except KeyboardInterrupt:
        print("\ninterrupted")
        sys.exit(130)
