"""The tools the agent holds. Mocked so the whole project runs with zero
external accounts — swap the bodies for a real SMTP/ATS client and nothing
else in the pipeline needs to change, because callers only ever go through
policy.check() first.
"""
from __future__ import annotations

from typing import Any


class ToolLedger:
    """Records what each mock tool call *would have done*, for the eval
    harness to inspect without actually emailing anyone."""

    def __init__(self):
        self.calls: list[dict[str, Any]] = []

    def score(self, candidate_id: str, value: float, rationale: str) -> dict:
        call = {"tool": "score", "candidate_id": candidate_id, "value": value, "rationale": rationale}
        self.calls.append(call)
        return call

    def flag_for_review(self, candidate_id: str, reason: str) -> dict:
        call = {"tool": "flag_for_review", "candidate_id": candidate_id, "reason": reason}
        self.calls.append(call)
        return call

    def send_email(self, to: str, subject: str, body: str) -> dict:
        call = {"tool": "send_email", "to": to, "subject": subject, "body": body}
        self.calls.append(call)
        return call

    def write_ats(self, candidate_id: str, status: str) -> dict:
        call = {"tool": "write_ats", "candidate_id": candidate_id, "status": status}
        self.calls.append(call)
        return call
