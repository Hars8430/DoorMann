"""
Mock action tools for the Doorman recruiting agent.

These simulate what a real recruiting pipeline would do:
  - send_email: sends an email to a candidate
  - write_ats: writes candidate status to the ATS

In DOORMAN, these are MOCKED — they log what *would* happen and return
a structured result. The guardrail logic is identical whether these are
real SMTP/ATS calls or mocks. The evaluation harness proves this.

IMPORTANT: These tools are ONLY available to the action stage node.
The scoring stage cannot call them — the tool allowlist is structural,
not a prompt instruction. This is the core defense.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("doorman.tools.action")


@dataclass
class ActionResult:
    """Result of an action tool call."""
    tool_name: str
    success: bool
    message: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: dict[str, Any] = field(default_factory=dict)


# In-memory action log — in a real system this would be an SMTP server
# and an ATS API. Here we just record every attempted action so the
# evaluation harness can inspect what was *about* to happen.
_action_log: list[dict[str, Any]] = []


def _hash_payload(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]


def reset_action_log() -> None:
    """Clear the in-memory action log. Call before each eval run."""
    _action_log.clear()


def get_action_log() -> list[dict[str, Any]]:
    """Return a copy of the action log for inspection."""
    return list(_action_log)


# ---------------------------------------------------------------------------
# send_email — mock
# ---------------------------------------------------------------------------

def send_email(
    to_address: str,
    subject: str,
    body: str,
    candidate_name: str | None = None,
) -> ActionResult:
    """
    MOCK: Log the email that would be sent.

    In production, this would be an SMTP call. Here we record:
      - recipient, subject, body (hashed)
      - whether the body contained any flagged content (for output scanner audit)

    Returns success=True always in mock mode — the guardrail decision
    of whether to CALL this function is what matters, not the return value.
    """
    payload_hash = _hash_payload(f"{subject}\n\n{body}")

    entry = {
        "tool": "send_email",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "to_address": to_address,
        "subject": subject,
        "body_preview": body[:200] + ("..." if len(body) > 200 else ""),
        "body_hash": payload_hash,
        "candidate_name": candidate_name,
    }
    _action_log.append(entry)

    logger.info(
        "mock_send_email",
        extra={"structured": entry},
    )

    return ActionResult(
        tool_name="send_email",
        success=True,
        message=f"Email would be sent to {to_address}: {subject[:80]}",
        details=entry,
    )


# ---------------------------------------------------------------------------
# write_ats — mock
# ---------------------------------------------------------------------------

def write_ats(
    candidate_id: str,
    status: str,
    notes: str | None = None,
    score: float | None = None,
) -> ActionResult:
    """
    MOCK: Log the ATS status update that would be written.

    In production, this would be an API call to the ATS (Workday, Greenhouse,
    Lever, etc.). Here we record the proposed status and notes.

    Valid statuses in mock mode: applied, screening, interview, offer, hired, rejected
    The guardrail checks whether status is being set to 'hired' without review.
    """
    valid_statuses = {"applied", "screening", "interview", "offer", "hired", "rejected"}

    entry = {
        "tool": "write_ats",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate_id,
        "status": status,
        "status_valid": status in valid_statuses,
        "notes_preview": (notes or "")[:200],
        "score": score,
    }
    _action_log.append(entry)

    logger.info(
        "mock_write_ats",
        extra={"structured": entry},
    )

    return ActionResult(
        tool_name="write_ats",
        success=True,
        message=f"ATS status for {candidate_id} would be set to {status}",
        details=entry,
    )


# ---------------------------------------------------------------------------
# flag_for_review — available to BOTH stages
# ---------------------------------------------------------------------------

def flag_for_review(
    candidate_id: str,
    reason: str,
    severity: str = "medium",
) -> ActionResult:
    """
    Flag a candidate for human review.

    Available to both scoring and action stages — this is a safe operation
    that doesn't leak info or take irreversible action.
    """
    entry = {
        "tool": "flag_for_review",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "candidate_id": candidate_id,
        "reason": reason,
        "severity": severity,
    }
    _action_log.append(entry)

    logger.info(
        "mock_flag_for_review",
        extra={"structured": entry},
    )

    return ActionResult(
        tool_name="flag_for_review",
        success=True,
        message=f"Candidate {candidate_id} flagged for review ({severity}): {reason[:100]}",
        details=entry,
    )
