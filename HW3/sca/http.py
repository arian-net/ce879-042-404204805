"""Shared HTTP client: retries, timeouts, JSON caching, GitHub auth."""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import __version__

log = logging.getLogger("sca.http")

DEFAULT_TIMEOUT = 30


class Http:
    """Thread-safe HTTP helper with an in-memory GET cache."""

    def __init__(self) -> None:
        self.session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1.0,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
            respect_retry_after_header=True,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)
        self.session.headers["User-Agent"] = f"sca-supply-chain-analyzer/{__version__}"
        self._cache: dict[str, Any] = {}
        self._lock = threading.Lock()

        self.github_token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")

    def get_json(
        self,
        url: str,
        *,
        headers: Optional[dict[str, str]] = None,
        cache: bool = True,
        ok_codes: tuple[int, ...] = (200,),
        timeout: int = DEFAULT_TIMEOUT,
    ) -> Optional[Any]:
        """GET a JSON document. Returns None on 404 or unrecoverable errors."""
        if cache:
            with self._lock:
                if url in self._cache:
                    return self._cache[url]
        result: Optional[Any] = None
        try:
            resp = self.session.get(url, headers=headers, timeout=timeout)
            if resp.status_code in ok_codes:
                result = resp.json()
            elif resp.status_code == 404:
                result = None
            else:
                log.debug("GET %s -> %s", url, resp.status_code)
                result = None
        except (requests.RequestException, json.JSONDecodeError) as exc:
            log.debug("GET %s failed: %s", url, exc)
            result = None
        if cache:
            with self._lock:
                self._cache[url] = result
        return result

    def post_json(
        self,
        url: str,
        payload: Any,
        *,
        timeout: int = DEFAULT_TIMEOUT,
        headers: Optional[dict[str, str]] = None,
    ) -> Optional[Any]:
        try:
            resp = self.session.post(url, json=payload, timeout=timeout, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            log.debug("POST %s -> %s: %s", url, resp.status_code, resp.text[:200])
        except (requests.RequestException, json.JSONDecodeError) as exc:
            log.debug("POST %s failed: %s", url, exc)
        return None

    def github_json(self, url: str, *, cache: bool = True) -> Optional[Any]:
        """GET from the GitHub REST API, using GITHUB_TOKEN when available."""
        headers = {"Accept": "application/vnd.github+json"}
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        return self.get_json(url, headers=headers, cache=cache)


# module-level singleton so every stage shares one connection pool + cache
HTTP = Http()


def utcnow_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
