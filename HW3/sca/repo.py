"""Repository acquisition: parse the GitHub URL, clone with full history,
and gather basic repository metadata (used by license + risk stages)."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .http import HTTP
from .models import RepoInfo

log = logging.getLogger("sca.repo")

_GITHUB_URL_RE = re.compile(
    r"^(?:https?://|git@)?(?:www\.)?github\.com[:/]"
    r"(?P<owner>[A-Za-z0-9_.-]+)/(?P<name>[A-Za-z0-9_.-]+?)(?:\.git)?/?$"
)


class RepoError(Exception):
    pass


def parse_github_url(url: str) -> tuple[Optional[str], Optional[str]]:
    m = _GITHUB_URL_RE.match(url.strip())
    if m:
        return m.group("owner"), m.group("name")
    return None, None


def run_git(repo_path: str | Path, *args: str, check: bool = True, timeout: int = 600) -> str:
    """Run a git command in the repo and return stdout as text."""
    cmd = ["git", "-C", str(repo_path), *args]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, errors="replace", timeout=timeout
    )
    if check and proc.returncode != 0:
        raise RepoError(f"git {' '.join(args[:2])} failed: {proc.stderr.strip()[:300]}")
    return proc.stdout


def clone_repository(url: str, dest_dir: Optional[str] = None) -> Path:
    """Clone with full history (required for git-history secret scanning)."""
    dest = Path(dest_dir) if dest_dir else Path(tempfile.mkdtemp(prefix="sca-repo-"))
    if dest.exists() and any(dest.iterdir()):
        raise RepoError(f"clone destination {dest} is not empty")
    dest.mkdir(parents=True, exist_ok=True)
    log.info("Cloning %s (full history) ...", url)
    proc = subprocess.run(
        ["git", "clone", "--quiet", url, str(dest)],
        capture_output=True, text=True, timeout=1800,
    )
    if proc.returncode != 0:
        shutil.rmtree(dest, ignore_errors=True)
        raise RepoError(f"git clone failed: {proc.stderr.strip()[:500]}")
    return dest


def acquire_repo(url: str, local_path: Optional[str] = None) -> RepoInfo:
    """Clone the repo (or reuse a local clone) and populate RepoInfo."""
    owner, name = parse_github_url(url)
    info = RepoInfo(url=url, owner=owner, name=name)

    if local_path:
        path = Path(local_path).resolve()
        if not (path / ".git").exists():
            raise RepoError(f"{path} is not a git repository")
        info.local_path = str(path)
        if not info.name:
            info.name = path.name
    else:
        path = clone_repository(url)
        info.local_path = str(path)

    try:
        info.head_commit = run_git(path, "rev-parse", "HEAD").strip()
        info.default_branch = run_git(
            path, "rev-parse", "--abbrev-ref", "HEAD"
        ).strip()
        info.commit_count = int(run_git(path, "rev-list", "--count", "HEAD").strip())
    except (RepoError, ValueError) as exc:
        log.warning("could not read git metadata: %s", exc)

    if owner and name:
        _enrich_from_github(info)
    return info


def _enrich_from_github(info: RepoInfo) -> None:
    data = HTTP.github_json(f"https://api.github.com/repos/{info.owner}/{info.name}")
    if not data:
        log.info("GitHub API metadata unavailable (rate limit or offline); continuing")
        return
    info.description = data.get("description")
    info.stars = data.get("stargazers_count")
    info.forks = data.get("forks_count")
    info.open_issues = data.get("open_issues_count")
    info.archived = data.get("archived")
    info.pushed_at = data.get("pushed_at")
    info.created_at = data.get("created_at")
    if not info.default_branch:
        info.default_branch = data.get("default_branch")
    lic = data.get("license") or {}
    spdx = lic.get("spdx_id")
    if spdx and spdx not in ("NOASSERTION", "OTHER"):
        info.github_license_spdx = spdx
