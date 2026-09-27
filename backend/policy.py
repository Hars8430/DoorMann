"""Policy layer: per-stage tool allowlist.

This is the load-bearing wall of the whole project. It does not matter how
thoroughly the model was fooled by the resume — if the scoring stage is not
in the allowlist for `send_email`, the call cannot happen. Full stop, before
any LLM output is even inspected.

Deliberately dumb and auditable: a dict literal, not a rules engine. If you
can't read the whole policy in ten seconds, it's grown too clever to trust.
"""
from __future__ import annotations

from .models import Stage

ALLOWLIST: dict[Stage, set[str]] = {
    Stage.SCORING: {"score", "flag_for_review"},
    Stage.CONFIRMATION: {"send_email", "write_ats"},
}


class PolicyViolation(Exception):
    def __init__(self, stage: Stage, tool_name: str):
        self.stage = stage
        self.tool_name = tool_name
        super().__init__(f"tool '{tool_name}' is not allowed at stage '{stage.value}'")


def check(stage: Stage, tool_name: str) -> None:
    """Raise PolicyViolation if `tool_name` is not allowlisted for `stage`."""
    allowed = ALLOWLIST.get(stage, set())
    if tool_name not in allowed:
        raise PolicyViolation(stage, tool_name)
