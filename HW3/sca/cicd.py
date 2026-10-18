"""CI/CD security analysis for GitHub Actions workflows (plus a basic
GitLab CI check): SHA pinning, floating branches, dangerous triggers,
script injection, token permissions, remote scripts piped to shells."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore[assignment]

from .models import Finding, Severity

log = logging.getLogger("sca.cicd")

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_BRANCH_REFS = {"main", "master", "develop", "dev", "trunk", "latest", "HEAD"}
_OFFICIAL_PREFIXES = ("actions/", "github/")

# expressions attacker-controllable when interpolated into `run:` scripts
_INJECTABLE_CONTEXT_RE = re.compile(
    r"\$\{\{\s*(github\.event\.(?:issue|pull_request|comment|review|discussion)"
    r"\.(?:title|body)|github\.event\.pull_request\.head\.(?:ref|label)|"
    r"github\.head_ref|github\.event\.commits.*?\.message|"
    r"github\.event\.head_commit\.message|"
    r"github\.event\.(?:sender|pull_request\.user|issue\.user)\.login)\s*\}\}")

_CURL_PIPE_RE = re.compile(
    r"(curl|wget)[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b")


def analyze_cicd(repo_root: str | Path) -> tuple[list[Finding], list[str]]:
    root = Path(repo_root)
    findings: list[Finding] = []
    files: list[str] = []

    workflow_dir = root / ".github" / "workflows"
    if workflow_dir.is_dir():
        for wf in sorted(workflow_dir.iterdir()):
            if wf.suffix not in (".yml", ".yaml") or not wf.is_file():
                continue
            rel = str(wf.relative_to(root))
            files.append(rel)
            try:
                findings.extend(_analyze_workflow(wf, rel))
            except Exception as exc:
                log.warning("failed to analyze workflow %s: %s", rel, exc)

    gitlab_ci = root / ".gitlab-ci.yml"
    if gitlab_ci.is_file():
        files.append(".gitlab-ci.yml")
        try:
            findings.extend(_analyze_gitlab_ci(gitlab_ci))
        except Exception as exc:
            log.warning("failed to analyze .gitlab-ci.yml: %s", exc)

    return findings, files


def _iter_scripts(jobs: dict) -> list[str]:
    """Collect every script body a workflow executes: step `run:` values and
    the `script:` input of actions/github-script steps."""
    scripts: list[str] = []
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict):
                continue
            if isinstance(step.get("run"), str):
                scripts.append(step["run"])
            uses = step.get("uses") or ""
            with_block = step.get("with") or {}
            if "github-script" in str(uses) and isinstance(with_block, dict) \
                    and isinstance(with_block.get("script"), str):
                scripts.append(with_block["script"])
    return scripts


def _load_yaml(path: Path) -> Optional[dict]:
    if yaml is None:
        return None
    data = yaml.safe_load(path.read_text(errors="replace"))
    return data if isinstance(data, dict) else None


def _analyze_workflow(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    text = path.read_text(errors="replace")
    # a workflow with broken YAML must not lose the text-based checks
    # (action pinning, curl|sh, hardcoded secrets, ...)
    yaml_error: Optional[str] = None
    try:
        doc = _load_yaml(path) or {}
    except Exception as exc:
        doc = {}
        yaml_error = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        findings.append(Finding(
            category="cicd", rule_id="CICD_UNPARSEABLE_YAML",
            severity=Severity.LOW,
            title=f"Workflow {path.name} is not valid YAML",
            description=(
                f"The workflow could not be parsed as YAML ({yaml_error}). Only "
                "text-based checks were applied to this file; structural checks "
                "(token permissions, precise script-injection analysis) were skipped."),
            location=rel,
            recommendation="Fix the YAML syntax so the workflow can be fully "
                           "analyzed (GitHub Actions would reject this file too).",
        ))

    # YAML quirk: the `on:` key parses as boolean True
    triggers = doc.get("on", doc.get(True, {}))
    trigger_names: set[str] = set()
    if isinstance(triggers, str):
        trigger_names = {triggers}
    elif isinstance(triggers, list):
        trigger_names = {str(t) for t in triggers}
    elif isinstance(triggers, dict):
        trigger_names = {str(k) for k in triggers}
    if yaml_error and re.search(r"\bpull_request_target\b", text):
        trigger_names.add("pull_request_target")

    jobs = doc.get("jobs") or {}
    if not isinstance(jobs, dict):
        jobs = {}

    # ---- action pinning -------------------------------------------------
    for line_no, line in enumerate(text.splitlines(), 1):
        m = re.search(r"^\s*-?\s*uses:\s*([^\s#]+)", line)
        if not m:
            continue
        uses = m.group(1).strip("\"'")
        loc = f"{rel}:{line_no}"
        if uses.startswith(("./", "docker://")):
            if uses.startswith("docker://") and (":latest" in uses or ":" not in uses.split("docker://")[1]):
                findings.append(Finding(
                    category="cicd", rule_id="CICD_DOCKER_LATEST",
                    severity=Severity.MEDIUM,
                    title=f"Workflow uses floating Docker image: {uses}",
                    description="The container action floats on ':latest'; its "
                                "content can change between runs.",
                    location=loc,
                    recommendation="Pin the docker:// action to a version tag and "
                                   "sha256 digest.",
                ))
            continue
        if "@" not in uses:
            continue
        action, ref = uses.rsplit("@", 1)
        official = action.startswith(_OFFICIAL_PREFIXES)
        if _SHA_RE.match(ref):
            continue  # full SHA pin: best practice
        if ref in _BRANCH_REFS:
            findings.append(Finding(
                category="cicd", rule_id="CICD_ACTION_BRANCH_REF",
                severity=Severity.HIGH,
                title=f"Action pinned to a floating branch: {uses}",
                description=(
                    f"'{action}' is referenced at branch '{ref}'. Every workflow "
                    "run fetches whatever that branch currently points to — a "
                    "compromised or malicious update executes in your CI with "
                    "access to the repository and its secrets."),
                location=loc,
                recommendation=(
                    f"Pin '{action}' to a full commit SHA, e.g. "
                    f"'{action}@<40-char-sha> # {ref}'."),
                metadata={"action": action, "ref": ref},
            ))
        else:
            findings.append(Finding(
                category="cicd", rule_id="CICD_ACTION_TAG_REF",
                severity=Severity.LOW if official else Severity.MEDIUM,
                title=f"Action pinned to a mutable tag: {uses}",
                description=(
                    f"'{action}' is referenced by tag '{ref}'. Git tags are mutable: "
                    "the action owner (or an attacker with push access) can move the "
                    "tag to malicious code without any change on your side."
                    + ("" if official else " This is a third-party action, which "
                       "raises the impact of a hijacked tag.")),
                location=loc,
                recommendation=(
                    f"Pin '{action}' to the full commit SHA of '{ref}': "
                    f"'{action}@<sha> # {ref}'. Dependabot/Renovate can keep "
                    "SHA pins updated."),
                metadata={"action": action, "ref": ref},
            ))

    # ---- dangerous triggers ---------------------------------------------
    if "pull_request_target" in trigger_names:
        checks_out_head = bool(re.search(
            r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text))
        findings.append(Finding(
            category="cicd", rule_id="CICD_PULL_REQUEST_TARGET",
            severity=Severity.CRITICAL if checks_out_head else Severity.LOW,
            title=f"pull_request_target trigger in {path.name}"
                  + (" with PR-head checkout" if checks_out_head else ""),
            description=(
                "'pull_request_target' runs with a write-scoped token and access "
                "to repository secrets"
                + (", and this workflow checks out the untrusted PR head — a "
                   "malicious fork PR can exfiltrate secrets or push code."
                   if checks_out_head else
                   ". This workflow does not check out the PR head (common for "
                   "labeling/triage automation), but the trigger remains a "
                   "sensitive surface: any future step that executes "
                   "PR-controlled content gains access to secrets.")),
            location=rel,
            recommendation=(
                "Prefer the 'pull_request' trigger. If write access is required, "
                "never check out or execute PR-controlled code in the same job, "
                "and gate execution on a maintainer label."),
        ))

    # ---- script injection -------------------------------------------------
    # inspect only real script bodies (run: steps and github-script's
    # `script:` input) from the parsed YAML — attacker-controlled expressions
    # elsewhere (e.g. checkout `ref:` inputs) are not shell-interpolated.
    # when the YAML is unparseable, fall back to scanning the whole file.
    for script_text in (_iter_scripts(jobs) if not yaml_error else [text]):
        for m in _INJECTABLE_CONTEXT_RE.finditer(script_text):
            snippet = m.group(0)
            offset = text.find(snippet)
            line_no = text.count("\n", 0, offset) + 1 if offset >= 0 else None
            loc = f"{rel}:{line_no}" if line_no else rel
            findings.append(Finding(
                category="cicd", rule_id="CICD_SCRIPT_INJECTION",
                severity=Severity.HIGH,
                title=f"Possible script injection via {m.group(1).split('.')[-1]!r}",
                description=(
                    f"The expression '${{{{ {m.group(1)} }}}}' is interpolated into "
                    "a CI script. This value is attacker-controlled (e.g. PR title "
                    "or branch name) and is substituted *before* the script runs, "
                    "allowing arbitrary command injection in CI."),
                location=loc,
                recommendation=(
                    "Pass the value through an environment variable instead: "
                    "'env: SAFE_VALUE: ${{ ... }}' and reference \"$SAFE_VALUE\" "
                    "in the script."),
            ))

    # ---- token permissions ---------------------------------------------
    has_top_permissions = "permissions" in doc
    jobs_with_perms = sum(
        1 for j in jobs.values() if isinstance(j, dict) and "permissions" in j)
    if not has_top_permissions and jobs_with_perms < len(jobs):
        findings.append(Finding(
            category="cicd", rule_id="CICD_NO_PERMISSIONS",
            severity=Severity.LOW,
            title=f"No explicit GITHUB_TOKEN permissions in {path.name}",
            description=(
                "The workflow does not restrict the GITHUB_TOKEN. Depending on "
                "repository settings the default token may have write access to "
                "contents, packages and pull-requests — more than most jobs need."),
            location=rel,
            recommendation="Add a least-privilege block, e.g. "
                           "'permissions:\\n  contents: read' at the workflow top level.",
        ))

    # ---- remote code piped into shells ----------------------------------
    for m in _CURL_PIPE_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        findings.append(Finding(
            category="cicd", rule_id="CICD_CURL_PIPE_SH",
            severity=Severity.MEDIUM,
            title="CI step pipes a remote script into a shell",
            description=(
                "A workflow step downloads a script and executes it immediately. "
                "The remote content is fetched unpinned at run time — if the host "
                "is compromised, arbitrary code runs inside CI with its secrets."),
            location=f"{rel}:{line_no}",
            recommendation=(
                "Vendor the script into the repository (or pin a checksum) and "
                "execute the reviewed copy."),
        ))

    # ---- hardcoded secrets in env ----------------------------------------
    for m in re.finditer(
            r"(?i)^\s*(\w*(?:password|token|secret|api_?key)\w*):\s*"
            r"['\"]?(?!\$\{\{)([A-Za-z0-9_/+.=-]{12,})['\"]?\s*$",
            text, re.MULTILINE):
        line_no = text.count("\n", 0, m.start()) + 1
        findings.append(Finding(
            category="cicd", rule_id="CICD_HARDCODED_SECRET",
            severity=Severity.HIGH,
            title=f"Possible hardcoded credential '{m.group(1)}' in workflow",
            description=(
                f"'{m.group(1)}' is assigned a literal value in {path.name} instead "
                "of a secrets reference; anyone with read access to the repository "
                "can use it."),
            location=f"{rel}:{line_no}",
            recommendation="Move the value to repository/organization Secrets and "
                           "reference it as '${{ secrets.NAME }}'.",
        ))

    # ---- self-hosted runners ---------------------------------------------
    if re.search(r"runs-on:.*self-hosted", text):
        findings.append(Finding(
            category="cicd", rule_id="CICD_SELF_HOSTED",
            severity=Severity.INFO,
            title=f"Workflow {path.name} uses self-hosted runners",
            description=(
                "Self-hosted runners on a public repository can be reached by fork "
                "PR workflows; a persistent compromise of the runner machine "
                "affects every subsequent build."),
            location=rel,
            recommendation="Restrict self-hosted runners to private repos or gate "
                           "fork PRs with required approval.",
        ))

    return findings


def _analyze_gitlab_ci(path: Path) -> list[Finding]:
    findings: list[Finding] = []
    text = path.read_text(errors="replace")
    for m in re.finditer(r"image:\s*([^\s#]+)", text):
        image = m.group(1).strip("\"'")
        if image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]:
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append(Finding(
                category="cicd", rule_id="CICD_GITLAB_LATEST_IMAGE",
                severity=Severity.MEDIUM,
                title=f"GitLab CI job image floats: {image}",
                description="The CI job image is not pinned to a version/digest.",
                location=f".gitlab-ci.yml:{line_no}",
                recommendation=f"Pin '{image}' to a version tag and digest.",
            ))
    for m in _CURL_PIPE_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        findings.append(Finding(
            category="cicd", rule_id="CICD_CURL_PIPE_SH",
            severity=Severity.MEDIUM,
            title="GitLab CI pipes a remote script into a shell",
            description="A CI script downloads and immediately executes remote code.",
            location=f".gitlab-ci.yml:{line_no}",
            recommendation="Vendor and review the script instead of piping it to a shell.",
        ))
    return findings
