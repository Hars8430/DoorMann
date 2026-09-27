"""
Pipeline state -- the shared dataclass that flows through every LangGraph node.

Every node reads some fields, writes some fields, and passes the state to
the next node. This is the "paperwork" that each stage fills out.

The state tracks:
  - Input: raw text, extracted text, hidden text, hashes
  - Guard decisions: classification verdict, rule IDs, signals
  - Pipeline progress: which stages have run, block status
  - Tool outputs: score result, pending actions, held actions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class PipelineState:
    """Shared state that flows through the Doorman LangGraph pipeline."""

    # ---- Identifiers ----
    run_id: str = ""
    candidate_id: str = ""
    candidate_name: str = ""

    # ---- Input tracking ----
    input_text: str = ""                    # raw text extracted from resume
    full_text: str = ""                     # visible + extracted hidden text, concatenated
    visible_text: str = ""                  # only the visible/legible text
    hidden_text_segments: list[dict[str, Any]] = field(default_factory=list)
    hidden_text_detail: str = ""            # human-readable summary of hidden text findings
    input_hash: str = ""                    # SHA-256 hash of the full input text

    # ---- Job context ----
    job_description: str = ""               # the job description being scored against

    # ---- Ingestion results ----
    pdf_metadata: dict[str, Any] = field(default_factory=dict)
    extraction_warnings: list[str] = field(default_factory=list)
    text_sources: dict[str, str] = field(default_factory=dict)

    # ---- Guard decisions ----
    classification: Any = None              # ClassificationResult from classify node
    isolated_text: str = ""                 # framed/isolation-wrapped text for scoring
    isolation_fence_tag: str = ""           # which fence tag was used

    # ---- Block tracking ----
    blocked: bool = False
    block_stage: str = ""                   # which stage blocked (classify, output_scan, etc.)
    block_rule_id: str | None = None
    block_reason: str = ""

    # ---- Scoring results ----
    score_result: Any = None               # ScoreResult from score node
    score_latency_ms: float = 0.0
    score_raw_response: str = ""
    score_flags: list[dict[str, Any]] = field(default_factory=list)
    score_has_instruction_leak: bool = False

    # ---- Pending actions (output scan + confirmation gate) ----
    pending_email: dict[str, Any] = field(default_factory=dict)   # proposed email: to, subject, body
    pending_ats: dict[str, Any] = field(default_factory=dict)      # proposed ATS: candidate_id, status, notes
    pending_actions: list[dict[str, Any]] = field(default_factory=list)  # held actions
    confirmed_actions: list[dict[str, Any]] = field(default_factory=list)
    held_count: int = 0
    needs_confirmation: bool = False

    # ---- Output scan ----
    output_scan: Any = None                 # OutputScanResult

    # ---- Timestamp ----
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    # ---- Tool allowlist enforcement log ----
    tool_calls_attempted: list[dict[str, Any]] = field(default_factory=list)

    # ---- Final pipeline outcome ----
    pipeline_verdict: str = ""              # "allowed", "blocked", "held_for_review"
    pipeline_summary: str = ""              # human-readable one-line summary


def make_initial_state(
    input_text: str = "",
    candidate_id: str = "",
    candidate_name: str = "",
    job_description: str = "",
    run_id: str = "",
) -> PipelineState:
    """Create an initial PipelineState with the given inputs."""
    import hashlib

    if not run_id:
        run_id = hashlib.sha256(
            f"{input_text}{candidate_id}{datetime.now(timezone.utc).isoformat()}".encode()
        ).hexdigest()[:12]

    return PipelineState(
        run_id=run_id,
        input_text=input_text,
        candidate_id=candidate_id,
        candidate_name=candidate_name,
        job_description=job_description,
        input_hash=hashlib.sha256(
            input_text.encode("utf-8", errors="replace")
        ).hexdigest()[:16],
    )
