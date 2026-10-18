"""Docker security analysis: parse every Dockerfile in the repository and
flag insecure configurations (floating base images, root user, etc.)."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from .models import Finding, Severity

log = logging.getLogger("sca.docker")

_DOCKERFILE_NAME_RE = re.compile(r"^(Dockerfile[\w.-]*|[\w.-]*\.dockerfile)$", re.I)
_SECRET_VAR_RE = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|credential)")


def find_dockerfiles(root: Path) -> list[Path]:
    out: list[Path] = []
    for p in root.rglob("*"):
        if len(p.relative_to(root).parts) > 4:
            continue
        if p.is_file() and _DOCKERFILE_NAME_RE.match(p.name) and ".git" not in p.parts:
            out.append(p)
    return sorted(out)


def _parse_instructions(text: str) -> list[tuple[int, str, str]]:
    """Return (line_number, INSTRUCTION, arguments) with continuations joined."""
    instructions: list[tuple[int, str, str]] = []
    pending = ""
    start_line = 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not pending:
            if not line or line.startswith("#"):
                continue
            start_line = i
        pending += (" " if pending else "") + line.rstrip("\\").strip()
        if line.endswith("\\"):
            continue
        m = re.match(r"^(\w+)\s*(.*)$", pending)
        if m:
            instructions.append((start_line, m.group(1).upper(), m.group(2)))
        pending = ""
    return instructions


def analyze_dockerfile(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    text = path.read_text(errors="replace")
    instructions = _parse_instructions(text)
    if not instructions:
        return findings

    # split into build stages (multi-stage): the checks that matter for the
    # runtime image (USER, EXPOSE) apply to the final stage
    stages: list[list[tuple[int, str, str]]] = []
    for inst in instructions:
        if inst[1] == "FROM":
            stages.append([])
        if stages:
            stages[-1].append(inst)
    final_stage = stages[-1] if stages else instructions
    stage_aliases = set()
    for _, kind, args in instructions:
        if kind == "FROM":
            m = re.search(r"\bAS\s+(\S+)", args, re.I)
            if m:
                stage_aliases.add(m.group(1).lower())

    for line, kind, args in instructions:
        loc = f"{rel}:{line}"
        if kind == "FROM":
            image = args.split()[0] if args.split() else ""
            if image.lower() in stage_aliases or image.startswith("$"):
                continue  # references a previous stage or a build arg
            base = image.split("@")[0]
            last_segment = base.rsplit("/", 1)[-1]
            tag = last_segment.split(":", 1)[1] if ":" in last_segment else None
            if "@sha256:" in image:
                pass  # digest-pinned: ideal
            elif tag is None:
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_NO_TAG",
                    severity=Severity.MEDIUM,
                    title=f"Base image without a tag: {image}",
                    description=(
                        f"'FROM {image}' has no tag, which implicitly means "
                        "':latest'. The image content can change between builds — "
                        "a mutable, unauditable supply chain input."),
                    location=loc,
                    recommendation=(
                        f"Pin the base image to a specific version tag, ideally a "
                        f"digest: 'FROM {image}:<version>@sha256:<digest>'."),
                ))
            elif tag == "latest":
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_LATEST_TAG",
                    severity=Severity.MEDIUM,
                    title=f"Base image uses the 'latest' tag: {image}",
                    description=(
                        f"'FROM {image}' floats on ':latest'; every build may pull "
                        "a different, unreviewed image — builds are not reproducible "
                        "and a compromised upstream image propagates instantly."),
                    location=loc,
                    recommendation=(
                        f"Replace ':latest' with a specific version tag and pin the "
                        f"digest: '{base.split(':')[0]}:<version>@sha256:<digest>'."),
                ))
            else:
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_NO_DIGEST",
                    severity=Severity.INFO,
                    title=f"Base image tag not digest-pinned: {image}",
                    description=(
                        "Tags are mutable; only a sha256 digest guarantees the exact "
                        "same base image every build."),
                    location=loc,
                    recommendation=f"Append '@sha256:<digest>' to '{image}'.",
                ))
        elif kind == "USER":
            if args.strip().split(":")[0] in ("root", "0"):
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_USER_ROOT",
                    severity=Severity.HIGH,
                    title="Container explicitly runs as root",
                    description=f"'USER {args}' sets the runtime user to root; a "
                                "container escape or app compromise yields root.",
                    location=loc,
                    recommendation="Create and switch to an unprivileged user "
                                   "(e.g. 'USER app').",
                ))
        elif kind == "ADD":
            if re.search(r"https?://", args):
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_ADD_URL",
                    severity=Severity.MEDIUM,
                    title="ADD fetches a remote URL at build time",
                    description=(
                        f"'ADD {args[:80]}' downloads remote content without "
                        "integrity verification into the image."),
                    location=loc,
                    recommendation=(
                        "Use 'RUN curl/wget' with an explicit checksum verification "
                        "step, or vendor the file into the repository."),
                ))
            else:
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_ADD_INSTEAD_OF_COPY",
                    severity=Severity.INFO,
                    title="ADD used where COPY suffices",
                    description="ADD auto-extracts archives and has URL semantics; "
                                "COPY is explicit and safer.",
                    location=loc,
                    recommendation="Replace ADD with COPY unless archive extraction "
                                   "is intended.",
                ))
        elif kind in ("ENV", "ARG"):
            m = _SECRET_VAR_RE.search(args.split("=")[0] if "=" in args else args)
            value_part = args.split("=", 1)[1].strip() if "=" in args else ""
            if m and value_part and not value_part.startswith("$") and len(value_part) > 4:
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_SECRET_IN_ENV",
                    severity=Severity.HIGH,
                    title=f"Possible hardcoded secret in {kind} instruction",
                    description=(
                        f"'{kind} {args[:60]}...' appears to embed a credential; "
                        "ENV/ARG values are baked into image layers and readable "
                        "by anyone who can pull the image."),
                    location=loc,
                    recommendation=(
                        "Pass secrets at runtime (orchestrator secrets, mounted "
                        "files) or use BuildKit 'RUN --mount=type=secret'."),
                ))
        elif kind == "RUN":
            if re.search(r"(curl|wget)[^|;&]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", args):
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_CURL_PIPE_SH",
                    severity=Severity.HIGH,
                    title="Remote script piped directly into a shell",
                    description=(
                        f"'RUN {args[:80]}...' executes an unverified remote script "
                        "at build time — full remote code execution in the build."),
                    location=loc,
                    recommendation=(
                        "Download the script, verify its checksum/signature, review "
                        "it, then execute a vendored copy."),
                ))
            if re.search(r"--no-check-certificate|(?:curl|wget)[^|;&]*\s-k\b|--insecure", args):
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_TLS_DISABLED",
                    severity=Severity.MEDIUM,
                    title="TLS certificate verification disabled in build step",
                    description=f"'RUN {args[:80]}...' disables certificate checks, "
                                "allowing man-in-the-middle substitution of artifacts.",
                    location=loc,
                    recommendation="Remove the insecure flag and fix the underlying "
                                   "CA trust issue.",
                ))
        elif kind == "EXPOSE":
            if re.search(r"\b22\b", args):
                findings.append(Finding(
                    category="docker", rule_id="DOCKER_EXPOSE_SSH",
                    severity=Severity.LOW,
                    title="Container exposes SSH port 22",
                    description="Running SSH inside application containers widens "
                                "the attack surface.",
                    location=loc,
                    recommendation="Remove the SSH daemon; use 'docker exec' or the "
                                   "orchestrator for debugging access.",
                ))

    # missing USER in the final stage -> runs as root by default
    if not any(k == "USER" and a.strip().split(":")[0] not in ("root", "0")
               for _, k, a in final_stage):
        if not any(k == "USER" for _, k, a in final_stage):
            findings.append(Finding(
                category="docker", rule_id="DOCKER_NO_USER",
                severity=Severity.HIGH,
                title="No USER instruction — container runs as root",
                description=(
                    f"The final stage of {rel} never drops privileges; the "
                    "application runs as root inside the container, so any code "
                    "execution bug becomes root code execution."),
                location=rel,
                recommendation=(
                    "Add an unprivileged user, e.g. 'RUN adduser --system app' "
                    "followed by 'USER app', after installation steps."),
            ))

    if not any(k == "HEALTHCHECK" for _, k, _ in instructions):
        findings.append(Finding(
            category="docker", rule_id="DOCKER_NO_HEALTHCHECK",
            severity=Severity.INFO,
            title="No HEALTHCHECK defined",
            description="Without a HEALTHCHECK the orchestrator cannot detect a "
                        "hung or degraded container.",
            location=rel,
            recommendation="Add a HEALTHCHECK instruction probing the service.",
        ))
    return findings


def analyze_docker(repo_root: str | Path) -> tuple[list[Finding], list[str]]:
    root = Path(repo_root)
    dockerfiles = find_dockerfiles(root)
    findings: list[Finding] = []
    rels: list[str] = []
    for df in dockerfiles:
        rel = str(df.relative_to(root))
        rels.append(rel)
        try:
            findings.extend(analyze_dockerfile(df, rel))
        except Exception as exc:
            log.warning("failed to analyze %s: %s", rel, exc)
    return findings, rels
