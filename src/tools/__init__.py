"""Tool registry and policy layer."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable

# Absolute imports -- src/ is on sys.path
from tools.scoring_tools import score as scoring_score, flag_for_review as scoring_flag
from tools.action_tools import send_email, write_ats, flag_for_review as action_flag

TOOL_REGISTRY: dict[str, Callable[..., Any]] = {
    "score": scoring_score,
    "flag_for_review": scoring_flag,
    "send_email": send_email,
    "write_ats": write_ats,
    "_action_flag": action_flag,
}

STAGE_ALLOWLISTS: dict[str, set[str]] = {
    "ingest": set(),
    "classify": set(),
    "isolate": set(),
    "score": {"score", "flag_for_review"},
    "output_scan": set(),
    "confirm": set(),
    "action": {"send_email", "write_ats", "flag_for_review"},
}

@dataclass
class ToolDispatchResult:
    allowed: bool
    tool_name: str
    stage: str
    result: Any = None
    error: str | None = None

def dispatch_tool(stage: str, tool_name: str, *args, **kwargs) -> ToolDispatchResult:
    if stage not in STAGE_ALLOWLISTS:
        return ToolDispatchResult(False, tool_name, stage, error=f"Unknown stage: {stage}")
    if tool_name not in STAGE_ALLOWLISTS[stage]:
        return ToolDispatchResult(False, tool_name, stage,
            error=f"Tool '{tool_name}' not allowed in stage '{stage}'. Allowed: {sorted(STAGE_ALLOWLISTS[stage])}")
    func = TOOL_REGISTRY.get(tool_name)
    if func is None:
        return ToolDispatchResult(False, tool_name, stage, error=f"Tool '{tool_name}' not in registry")
    try:
        result = func(*args, **kwargs)
        return ToolDispatchResult(True, tool_name, stage, result=result)
    except Exception as e:
        return ToolDispatchResult(True, tool_name, stage, error=f"Tool execution failed: {e}", result=None)

def get_tool_function(tool_name: str) -> Callable[..., Any] | None:
    return TOOL_REGISTRY.get(tool_name)
