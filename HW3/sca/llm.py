"""Bonus: LLM-based Security Executive Report.

Sends the condensed, structured analysis output to an LLM and returns an
executive summary (security posture, top risks, prioritized actions) for
managers and the development team.

Optional feature, enabled with the --llm-summary CLI flag. Two providers:

  1. OpenRouter (preferred): set OPENROUTER_API_KEY. Uses the plain HTTP API
     via the shared requests session — no extra package required. The model
     defaults to `anthropic/claude-sonnet-4.5` and can be overridden with the
     OPENROUTER_MODEL environment variable.
  2. Anthropic (fallback): set ANTHROPIC_API_KEY and `pip install anthropic`.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Optional

from .http import HTTP
from .models import AnalysisResult

log = logging.getLogger("sca.llm")

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
OPENROUTER_DEFAULT_MODEL = "anthropic/claude-sonnet-4.5"
ANTHROPIC_MODEL = "claude-opus-4-8"

SYSTEM_PROMPT = (
    "You are a principal application security engineer. You receive the "
    "structured JSON output of a software supply chain analysis tool. Write a "
    "concise executive report in Markdown with these sections:\n"
    "1. Security Posture Summary (2-3 sentences, for management)\n"
    "2. Top Risks (ranked, max 5, one line each with business impact)\n"
    "3. Prioritized Action Plan (concrete steps for the development team, "
    "referencing exact package names/versions/files from the data)\n"
    "4. Longer-term Recommendations (process improvements)\n"
    "Base every statement strictly on the provided data; do not invent "
    "findings. Keep the whole report under 500 words."
)


def _condense(result: AnalysisResult) -> dict:
    """Reduce the analysis result to what the LLM needs (bounded size)."""
    lic = result.license_report
    return {
        "repository": {
            "name": result.repo.full_name,
            "url": result.repo.url,
            "stars": result.repo.stars,
            "archived": result.repo.archived,
        },
        "risk": {
            "level": result.risk_level,
            "score": result.risk_score,
            "breakdown": result.risk_breakdown,
            "reasoning": result.risk_reasoning,
        },
        "dependencies": {
            "total": len(result.dependencies),
            "direct": sum(1 for d in result.dependencies if d.direct),
            "resolution": result.transitive_resolution,
        },
        "vulnerabilities": [
            {
                "package": v.package, "version": v.package_version,
                "id": v.display_id, "severity": v.severity.value,
                "cvss": v.cvss_score, "summary": v.summary[:150],
                "fixed_versions": v.fixed_versions[-2:],
            }
            for v in result.vulnerabilities[:25]
        ],
        "secrets": [
            {
                "type": s.secret_type, "file": s.file_path,
                "status": s.status, "placeholder": s.likely_placeholder,
            }
            for s in result.secrets[:25]
        ],
        "docker_findings": [
            {"severity": f.severity.value, "title": f.title, "location": f.location}
            for f in result.docker_findings[:20]
        ],
        "cicd_findings": [
            {"severity": f.severity.value, "title": f.title, "location": f.location}
            for f in result.cicd_findings[:20]
        ],
        "licenses": {
            "project": lic.project_license,
            "incompatibilities": lic.incompatibilities[:10],
            "restrictive": lic.restrictive[:10],
            "missing_count": len(lic.missing_license),
        },
        "top_recommendations": result.recommendations[:15],
    }


def _user_message(result: AnalysisResult) -> str:
    return ("Supply chain analysis results:\n\n"
            + json.dumps(_condense(result), indent=1))


def generate_executive_summary(result: AnalysisResult) -> Optional[str]:
    if os.environ.get("OPENROUTER_API_KEY"):
        return _openrouter_summary(result)
    if os.environ.get("ANTHROPIC_API_KEY"):
        return _anthropic_summary(result)
    log.warning("LLM summary skipped: set OPENROUTER_API_KEY (or "
                "ANTHROPIC_API_KEY) to enable it")
    return None


def _openrouter_summary(result: AnalysisResult) -> Optional[str]:
    model = os.environ.get("OPENROUTER_MODEL", OPENROUTER_DEFAULT_MODEL)
    log.info("requesting executive summary from OpenRouter (%s)", model)
    data = HTTP.post_json(
        OPENROUTER_URL,
        {
            "model": model,
            "max_tokens": 2000,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _user_message(result)},
            ],
        },
        headers={
            "Authorization": f"Bearer {os.environ['OPENROUTER_API_KEY']}",
            "HTTP-Referer": "https://github.com/sca-supply-chain-analyzer",
            "X-Title": "sca supply-chain-analyzer",
        },
        timeout=120,
    )
    if not data:
        log.warning("LLM summary skipped: OpenRouter request failed "
                    "(check OPENROUTER_API_KEY / network; run with -v for details)")
        return None
    if data.get("error"):
        log.warning("LLM summary skipped: OpenRouter error: %s",
                    data["error"].get("message", data["error"]))
        return None
    choices = data.get("choices") or []
    content = (choices[0].get("message") or {}).get("content") if choices else None
    if not content:
        log.warning("LLM summary skipped: OpenRouter returned no content")
        return None
    return content.strip()


def _anthropic_summary(result: AnalysisResult) -> Optional[str]:
    try:
        import anthropic
    except ImportError:
        log.warning("ANTHROPIC_API_KEY is set but the 'anthropic' package is "
                    "not installed; run: pip install anthropic (or use "
                    "OPENROUTER_API_KEY instead, which needs no extra package)")
        return None

    try:
        client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env
        response = client.messages.create(
            model=ANTHROPIC_MODEL,
            max_tokens=16000,
            thinking={"type": "adaptive"},
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": _user_message(result)}],
        )
        if response.stop_reason == "refusal":
            log.warning("LLM declined to generate the summary")
            return None
        return next(
            (b.text for b in response.content if b.type == "text"), None)
    except anthropic.AuthenticationError:
        log.warning("LLM summary skipped: ANTHROPIC_API_KEY missing or invalid")
    except anthropic.RateLimitError:
        log.warning("LLM summary skipped: rate limited")
    except anthropic.APIStatusError as exc:
        log.warning("LLM summary skipped: API error %s", exc.status_code)
    except anthropic.APIConnectionError:
        log.warning("LLM summary skipped: network error")
    return None
