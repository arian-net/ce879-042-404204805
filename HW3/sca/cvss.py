"""Minimal CVSS v3.x base-score calculator (vector string -> score/severity)."""

from __future__ import annotations

import math
import re
from typing import Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_base_score(vector: str) -> Optional[float]:
    if not vector or not vector.startswith("CVSS:3"):
        return None
    metrics = dict(
        part.split(":", 1) for part in vector.split("/")[1:] if ":" in part)
    try:
        scope_changed = metrics["S"] == "C"
        pr_table = _PR_CHANGED if scope_changed else _PR_UNCHANGED
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed \
            else 6.42 * iss
        exploitability = (8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]]
                          * pr_table[metrics["PR"]] * _UI[metrics["UI"]])
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + exploitability), 10) if scope_changed \
            else min(impact + exploitability, 10)
        return math.ceil(raw * 10) / 10  # CVSS "round up" to 1 decimal
    except KeyError:
        return None


def cvss4_score_from_vector(vector: str) -> Optional[float]:
    """CVSS 4.0 scoring is table-based; we don't implement it. Returns None."""
    return None


def severity_from_score(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "LOW"


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def is_cve(identifier: str) -> bool:
    return bool(_CVE_RE.match(identifier))
