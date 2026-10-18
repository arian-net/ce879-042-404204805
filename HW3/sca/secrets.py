"""Secret detection across the full git history.

Strategy (fast even on repos with thousands of commits):
  1. enumerate every unique blob ever committed (git rev-list --objects --all)
  2. filter by path (binary/asset extensions) and size (git cat-file --batch-check)
  3. stream blob contents through git cat-file --batch and scan with a
     compiled pattern set (specific token formats + keyword/entropy generics)
  4. for each hit, locate the introducing commit (git log --find-object)
  5. determine current status: does the secret still exist at HEAD?
"""

from __future__ import annotations

import logging
import math
import re
import subprocess
import threading
from collections import Counter
from pathlib import Path
from typing import Iterable, Optional

from .models import SecretFinding
from .repo import run_git

log = logging.getLogger("sca.secrets")

MAX_BLOB_SIZE = 400_000          # bytes
MAX_FINDINGS = 300               # hard cap to keep reports usable

SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".otf", ".eot",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".whl",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".wav",
    ".pyc", ".pyo", ".so", ".dylib", ".dll", ".exe", ".bin", ".o", ".a",
    ".min.js", ".map", ".lock",   # note: .lock skipped for generic noise
}

# (type, compiled regex, capture group of the secret value, needs entropy check)
PATTERNS: list[tuple[str, re.Pattern[str], int, bool]] = [
    ("AWS Access Key ID",
     re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b"), 1, False),
    ("AWS Secret Access Key",
     re.compile(r"""(?i)aws.{0,25}?['"]([0-9a-z/+]{40})['"]"""), 1, True),
    ("GitHub Token",
     re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"), 1, False),
    ("GitHub Fine-grained PAT",
     re.compile(r"\b(github_pat_[A-Za-z0-9_]{22,255})\b"), 1, False),
    ("GitLab PAT",
     re.compile(r"\b(glpat-[A-Za-z0-9_-]{20,})\b"), 1, False),
    ("Slack Token",
     re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), 1, False),
    ("Slack Webhook",
     re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})"), 1, False),
    ("Stripe Secret Key",
     re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), 1, False),
    ("Stripe Test Key",
     re.compile(r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b"), 1, False),
    ("Google API Key",
     re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), 1, False),
    ("OpenAI API Key",
     re.compile(r"\b(sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{40,})\b"), 1, True),
    ("Anthropic API Key",
     re.compile(r"\b(sk-ant-[A-Za-z0-9_-]{32,})\b"), 1, False),
    ("npm Token",
     re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), 1, False),
    ("PyPI Token",
     re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{20,})\b"), 1, False),
    ("SendGrid API Key",
     re.compile(r"\b(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})\b"), 1, False),
    ("Telegram Bot Token",
     re.compile(r"\b(\d{8,10}:AA[A-Za-z0-9_-]{33})\b"), 1, False),
    ("Twilio Account SID",
     re.compile(r"\b(AC[0-9a-fA-F]{32})\b"), 1, True),
    ("Private Key (PEM)",
     re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?"
                r"PRIVATE KEY(?: BLOCK)?-----)"), 1, False),
    ("JWT",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{14,}\.eyJ[A-Za-z0-9_-]{14,}\.[A-Za-z0-9_-]{10,})\b"),
     1, False),
    ("Credential in URL",
     re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|https?|ftp)"
                r"://[^\s:@/'\"]{1,64}:([^\s@/'\"]{6,})@[\w.-]+"), 1, True),
    ("Generic Secret Assignment",
     re.compile(r"""(?i)\b(?:password|passwd|pwd|secret|secret[_-]?key|api[_-]?key|apikey|
                auth[_-]?token|access[_-]?token|client[_-]?secret)\b['"]?\s*[:=]\s*
                ['"]([^'"\s]{8,128})['"]""", re.VERBOSE), 1, True),
]

_PLACEHOLDER_RE = re.compile(
    r"(?i)example|sample|dummy|fake|placeholder|changeme|change_me|your[_-]?|"
    r"<[^>]*>|\$\{|\{\{|%s|%\(|xxxx|\.\.\.|todo|fixme|not[_-]?real|redacted|"
    r"insert[_-]?|deadbeef|password123|secret123|abcdef|0123456789|testkey|mytoken|"
    r"my[_-]?(?:secret|password|key)|s3cr3t|hunter2|correcthorse")
_PLACEHOLDER_PATH_RE = re.compile(
    r"(?i)(^|/)(\w*tests?|testing|testdata|examples?|samples?|fixtures?|mocks?|docs?|"
    r"docs_src|documentation|demo)s?(/|$)")
# file names that mark test/example material even outside test directories,
# e.g. Go's foo_test.go convention or files like example-key.pem, testcert.go
_PLACEHOLDER_FILE_RE = re.compile(
    r"(?i)(_test\.|^test|\.test\.|example|sample|dummy|fixture|mock|fake)")

MIN_ENTROPY = 3.3


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return value[:2] + "*" * (len(value) - 2)
    return f"{value[:5]}{'*' * min(len(value) - 7, 24)}{value[-2:]}"


def _path_allowed(path: str) -> bool:
    lower = path.lower()
    for ext in SKIP_EXTENSIONS:
        if lower.endswith(ext):
            return False
    return True


def scan_repository(repo_path: str | Path) -> list[SecretFinding]:
    repo_path = str(repo_path)
    blobs = _list_blobs(repo_path)          # {sha: path}
    log.info("secret scan: %d candidate blobs in history", len(blobs))
    sized = _filter_by_size(repo_path, blobs)
    raw_hits = _scan_blobs(repo_path, sized)
    log.info("secret scan: %d raw pattern hits", len(raw_hits))
    return _build_findings(repo_path, raw_hits)


def _list_blobs(repo_path: str) -> dict[str, str]:
    out = run_git(repo_path, "rev-list", "--objects", "--all", timeout=900)
    blobs: dict[str, str] = {}
    for line in out.splitlines():
        if " " not in line:
            continue  # commits/trees have no path suffix
        sha, path = line.split(" ", 1)
        if path and _path_allowed(path) and sha not in blobs:
            blobs[sha] = path
    return blobs


def _filter_by_size(repo_path: str, blobs: dict[str, str]) -> dict[str, str]:
    proc = subprocess.Popen(
        ["git", "-C", repo_path, "cat-file", "--batch-check"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    shas = list(blobs)

    def feed() -> None:
        assert proc.stdin
        for sha in shas:
            proc.stdin.write(sha + "\n")
        proc.stdin.close()

    threading.Thread(target=feed, daemon=True).start()
    keep: dict[str, str] = {}
    assert proc.stdout
    for line in proc.stdout:
        parts = line.split()
        if len(parts) == 3 and parts[1] == "blob" and int(parts[2]) <= MAX_BLOB_SIZE:
            keep[parts[0]] = blobs[parts[0]]
    proc.wait()
    return keep


def _scan_blobs(
    repo_path: str, blobs: dict[str, str]
) -> list[tuple[str, str, str, str, int, bool]]:
    """Returns raw hits: (type, secret_value, blob_sha, path, line, needs_entropy)."""
    proc = subprocess.Popen(
        ["git", "-C", repo_path, "cat-file", "--batch"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    shas = list(blobs)

    def feed() -> None:
        assert proc.stdin
        for sha in shas:
            proc.stdin.write((sha + "\n").encode())
        proc.stdin.close()

    threading.Thread(target=feed, daemon=True).start()

    hits: list[tuple[str, str, str, str, int, bool]] = []
    assert proc.stdout
    out = proc.stdout
    while True:
        header = out.readline()
        if not header:
            break
        parts = header.decode(errors="replace").split()
        if len(parts) != 3 or parts[1] != "blob":
            continue
        sha, size = parts[0], int(parts[2])
        content = out.read(size)
        out.read(1)  # trailing newline
        if b"\0" in content[:4096]:
            continue  # binary
        text = content.decode("utf-8", errors="replace")
        path = blobs.get(sha, "?")
        for stype, pattern, group, needs_entropy in PATTERNS:
            for m in pattern.finditer(text):
                value = m.group(group)
                line = text.count("\n", 0, m.start()) + 1
                hits.append((stype, value, sha, path, line, needs_entropy))
        if len(hits) > MAX_FINDINGS * 20:
            log.warning("secret scan: too many raw hits, truncating scan")
            proc.kill()
            break
    proc.wait()
    return hits


def _build_findings(
    repo_path: str, raw_hits: list[tuple[str, str, str, str, int, bool]]
) -> list[SecretFinding]:
    head_files: dict[str, Optional[str]] = {}

    def head_content(path: str) -> Optional[str]:
        if path not in head_files:
            try:
                head_files[path] = run_git(
                    repo_path, "cat-file", "-p", f"HEAD:{path}", check=True)
            except Exception:
                head_files[path] = None
        return head_files[path]

    # group duplicate hits (same secret, same file across blob versions) so the
    # reported commit is the one that *introduced* the secret, not just any
    # blob revision that happens to contain it
    groups: dict[tuple[str, str, str], list[tuple[str, int, bool]]] = {}
    for stype, value, sha, path, line, needs_entropy in raw_hits:
        groups.setdefault((stype, value, path), []).append(
            (sha, line, needs_entropy))

    findings: list[SecretFinding] = []
    commit_cache: dict[str, tuple[str, Optional[str], Optional[str]]] = {}

    def commit_for(sha: str) -> tuple[str, Optional[str], Optional[str]]:
        if sha not in commit_cache:
            commit_cache[sha] = _introducing_commit(repo_path, sha)
        return commit_cache[sha]

    for (stype, value, path), hits in groups.items():
        needs_entropy = hits[0][2]
        entropy = shannon_entropy(value)
        basename = path.rsplit("/", 1)[-1]
        placeholder = bool(_PLACEHOLDER_RE.search(value)) or \
            bool(_PLACEHOLDER_PATH_RE.search(path)) or \
            bool(_PLACEHOLDER_FILE_RE.search(basename))
        if needs_entropy and entropy < MIN_ENTROPY:
            continue  # low-entropy generic match: almost certainly not a secret
        if stype == "Stripe Test Key":
            placeholder = True

        # earliest introducing commit across all blob versions with this hit
        candidates = [(commit_for(sha), line) for sha, line, _ in hits[:5]]
        (commit, author, date), line = min(
            candidates, key=lambda c: c[0][2] or "9999")

        head = head_content(path)
        in_head = bool(head and value in head)

        findings.append(SecretFinding(
            secret_type=stype, file_path=path, line=line,
            match_preview=_redact(value), commit=commit,
            commit_author=author, commit_date=date, in_head=in_head,
            likely_placeholder=placeholder, entropy=round(entropy, 2),
        ))
        if len(findings) >= MAX_FINDINGS:
            log.warning("secret scan: reached cap of %d findings", MAX_FINDINGS)
            break

    findings.sort(key=lambda f: (f.likely_placeholder, not f.in_head, f.secret_type))
    return findings


def _introducing_commit(
    repo_path: str, blob_sha: str
) -> tuple[str, Optional[str], Optional[str]]:
    try:
        out = run_git(
            repo_path, "log", "--all", "--reverse",
            f"--find-object={blob_sha}",
            "--format=%H%x00%an%x00%aI", timeout=120, check=False)
        first = next((l for l in out.splitlines() if l.strip()), "")
        if first:
            parts = first.split("\0")
            return parts[0], parts[1] if len(parts) > 1 else None, \
                parts[2] if len(parts) > 2 else None
    except Exception as exc:
        log.debug("find-object failed for %s: %s", blob_sha, exc)
    return "unknown", None, None
