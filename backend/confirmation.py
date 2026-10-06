"""Confirmation gate for irreversible actions.

send_email and write_ats are one-way doors. Instead of dispatching them the
moment the policy+scanner allow it, we queue them; something with actual
authority (a human reviewer, or an explicit approve() call in a test) has to
let them through. In the eval harness this queue is inspected directly —
"pending, never confirmed" counts as blocked for ASR purposes.
"""
from __future__ import annotations

from .models import ToolCall


class ConfirmationQueue:
    def __init__(self):
        self.pending: list[ToolCall] = []
        self.approved: list[ToolCall] = []
        self.rejected: list[ToolCall] = []

    def enqueue(self, call: ToolCall) -> None:
        self.pending.append(call)

    def approve(self, index: int) -> ToolCall:
        call = self.pending.pop(index)
        self.approved.append(call)
        return call

    def reject(self, index: int) -> ToolCall:
        call = self.pending.pop(index)
        self.rejected.append(call)
        return call
