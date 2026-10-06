"""Shared data models for the Doorman pipeline."""
from __future__ import annotations

from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel


class Verdict(str, Enum):
    ALLOW = "allow"
    HOLD = "hold"          # flagged for human review, not blocked outright
    DENY = "deny"


class Stage(str, Enum):
    INGESTION = "ingestion"
    GUARD = "guard"
    ISOLATION = "isolation"
    SCORING = "scoring"
    OUTPUT_SCAN = "output_scan"
    CONFIRMATION = "confirmation"


class HiddenSpan(BaseModel):
    """A run of text the ingestion layer decided was hidden from a human reader."""
    text: str
    reason: str          # e.g. "white_on_white", "off_page", "tiny_font", "zero_width"
    page: int


class Document(BaseModel):
    filename: str
    visible_text: str
    hidden_spans: list[HiddenSpan] = []
    metadata_text: dict[str, str] = {}   # raw PDF metadata fields (Author, Title, Keywords, ...)
    linked_urls: list[str] = []


class RuleHit(BaseModel):
    rule_id: str
    family: str
    detail: str


class GuardResult(BaseModel):
    verdict: Verdict
    score: float                 # 0..1 likelihood of injection
    hits: list[RuleHit] = []


class ToolCall(BaseModel):
    tool_name: str
    arguments: dict[str, Any]


class ScanResult(BaseModel):
    verdict: Verdict
    hits: list[RuleHit] = []


class LogEntry(BaseModel):
    stage: Stage
    rule_id: Optional[str] = None
    verdict: Verdict
    detail: str
    timestamp: str
    input_hash: str
    action_attempted: Optional[str] = None


class ScoreResult(BaseModel):
    value: float                     # 0..1 candidate fit score
    rationale: str
    coerced: bool = False            # True if the scorer detected it was complying with embedded text
    wants_direct_action: bool = False  # True if the (naive) scorer tried to skip straight to email/ATS
    # True when a maxed score is independently corroborated by evidence the
    # scorer did not take on faith from the document — e.g. every job keyword
    # literally appears in the resume. Without this, a perfect keyword match
    # and a coerced 1.0 are indistinguishable to the output scanner, and the
    # most relevant resumes get denied (the false-positive bug this field fixes).
    evidence_backed: bool = False


class PipelineResult(BaseModel):
    filename: str
    final_verdict: Verdict
    blocked_at_stage: Optional[Stage] = None
    candidate_score: Optional[float] = None
    tool_calls_allowed: list[str] = []
    tool_calls_blocked: list[str] = []
    logs: list[LogEntry] = []
    pending_actions: list[ToolCall] = []
