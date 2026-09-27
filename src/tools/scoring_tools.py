"""
Scoring-stage tools for the Doorman recruiting agent.

These are the ONLY tools available to the scoring stage node:
  - score(candidate_data) → structured ScoreResult
  - flag_for_review(candidate_id, reason) → ActionResult

The scoring stage CANNOT call send_email() or write_ats() — those tools
live in action_tools.py and are only available to the action stage node.
This is the structural guarantee: even if the LLM is tricked into wanting
to send an email, it has no send_email tool to call.

The score() tool is carefully designed to return STRUCTURED output
(score + category + justification), not raw text the LLM can use to
smuggle instructions downstream.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("doorman.tools.scoring")


@dataclass
class ScoreResult:
    """Structured score output — designed to be inspectable by the output scanner."""
    candidate_id: str
    overall_score: float           # 0.0 - 10.0
    category: str                  # "top", "review", "hold", "reject"
    justification: str             # brief human-readable reason (≤300 chars)
    skills_match: float            # 0.0 - 1.0
    experience_match: float        # 0.0 - 1.0
    culture_fit: float             # 0.0 - 1.0
    red_flags: list[str]           # any concerns raised during scoring
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_summary: str = ""     # brief summary of what the score is based on


# ---------------------------------------------------------------------------
# score — the only data-producing tool available to the scoring stage
# ---------------------------------------------------------------------------

def score(candidate_data: dict[str, Any]) -> ScoreResult:
    """
    Score a candidate based on extracted resume data.

    Parameters
    ----------
    candidate_data : dict
        Must contain:
          - candidate_id: str
          - name: str
          - skills: list[str]
          - experience_years: float | None
          - education: str | None
          - job_description: str  (the role being scored against)

    Returns a structured ScoreResult. The output scanner inspects this
    for anomalies: maxed score with no evidence, embedded instructions in
    justification, etc.
    """
    candidate_id = candidate_data.get("candidate_id", "unknown")
    name = candidate_data.get("name", "Unknown")
    skills = candidate_data.get("skills", [])
    exp_years = candidate_data.get("experience_years")
    education = candidate_data.get("education")
    job_desc = candidate_data.get("job_description", "")

    # ---- Simple scoring logic (mock — real system would use a proper model) ----
    # This is intentionally simple so we can reason about what "normal" output looks like.

    # Skills match: overlap between resume skills and job description keywords
    job_keywords = set(job_desc.lower().split())
    skills_lower = [s.lower() for s in skills]
    if job_keywords and skills_lower:
        overlap = len(set(skills_lower) & job_keywords) / max(len(set(skills_lower)), 1)
    else:
        overlap = 0.5

    # Experience score: rough heuristic
    if exp_years is not None:
        exp_score = min(exp_years / 10.0, 1.0)
    else:
        exp_score = 0.5

    # Education: binary-ish
    edu_score = 0.7 if education else 0.4

    # Overall: weighted average
    overall = round(overlap * 0.4 + exp_score * 0.35 + edu_score * 0.25, 1)
    overall = max(0.0, min(10.0, overall * 10.0))  # scale to 0-10

    # Category
    if overall >= 7.5:
        category = "top"
    elif overall >= 5.0:
        category = "review"
    elif overall >= 3.0:
        category = "hold"
    else:
        category = "reject"

    justification = (
        f"Skills match: {overlap:.1%}, Experience: {exp_years}y (score {exp_score:.2f}), "
        f"Education: {education or 'not specified'} (score {edu_score:.2f}). "
        f"Overall: {overall}/10."
    )

    result = ScoreResult(
        candidate_id=candidate_id,
        overall_score=overall,
        category=category,
        justification=justification[:300],
        skills_match=overlap,
        experience_match=exp_score,
        culture_fit=0.5,  # neutral default — not assessed in mock
        red_flags=[],
        evidence_summary=f"Scored against {len(job_keywords)} job keywords, {exp_years or '?'}y experience, education: {education or 'N/A'}",
    )

    # Log the scoring event
    payload_hash = hashlib.sha256(
        json.dumps(candidate_data, sort_keys=True, default=str).encode()
    ).hexdigest()[:16]

    logger.info(
        "score_called",
        extra={
            "structured": {
                "tool": "score",
                "candidate_id": candidate_id,
                "input_hash": payload_hash,
                "overall_score": overall,
                "category": category,
            }
        },
    )

    return result


# ---------------------------------------------------------------------------
# flag_for_review — also available at scoring stage
# ---------------------------------------------------------------------------

def flag_for_review(
    candidate_id: str,
    reason: str,
    severity: str = "medium",
) -> dict[str, Any]:
    """
    Flag a candidate for human review.

    Available to both scoring and action stages. This is a SAFE operation —
    it doesn't leak info, doesn't send email, doesn't write ATS status.
    """
    entry = {
        "tool": "flag_for_review",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate_id,
        "reason": reason,
        "severity": severity,
    }

    logger.info(
        "flag_for_review_called",
        extra={"structured": entry},
    )

    return entry
