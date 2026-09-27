"""
Input classifier node — ensembles three signals into one verdict.

Signals (in priority order):
  1. Heuristic guard — regex/pattern-based, fast, always available
  2. HF classifier — ProtectAI DeBERTa, trained model, may need download
  3. LLM judge — Ollama LLM, deepest context understanding, slowest

Ensemble policies:
  - "any": block if ANY signal flags as attack (most conservative)
  - "majority": block if 2+ signals flag (balanced)
  - "all": block only if ALL available signals flag (most permissive)

The classifier runs BEFORE the scoring stage sees the content. If it
returns "block", the pipeline short-circuits and logs the decision with
a rule ID. If "allow", the content proceeds to context isolation and
scoring. If "flagged" (confidence between thresholds), it proceeds but
is marked for review.

This is the SECOND layer of defense (after ingestion/extraction).
The FIRST layer is the hidden-text extraction in the ingest node —
if we find white-on-white text, we already know something is suspicious
before the classifier even sees it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from guards.heuristic_guard import check_heuristics, heuristic_verdict
from guards.hf_guard import HFGuard, get_hf_guard
from guards.llm_judge import LLMJudgeGuard, get_llm_judge
from pipeline_state import PipelineState
from logging_setup import log_decision

logger = logging.getLogger("doorman.nodes.classify")


class Verdict(str, Enum):
    BLOCK = "block"
    ALLOW = "allow"
    FLAGGED = "flagged"     # proceed but mark for review
    UNKNOWN = "unknown"     # classifier unavailable, proceed with caution


@dataclass
class ClassificationResult:
    verdict: Verdict
    rule_id: str | None           # which rule fired (if any)
    detail: str                   # human-readable explanation
    signals: dict[str, Any]       # raw results from each signal
    input_hash: str               # hash of the classified input


# ---------------------------------------------------------------------------
# Ensemble logic
# ---------------------------------------------------------------------------

def _ensemble_any(
    signals: dict[str, Any],
) -> tuple[Verdict, str | None, str]:
    """
    Block if ANY signal says block.
    """
    reasons = []
    rule_id = None

    for name, result in signals.items():
        v = result.get("verdict", "unknown")
        if v == "block":
            rid = result.get("rule_id")
            if rid:
                rule_id = rid
            reasons.append(f"{name}: BLOCK ({result.get('detail', '')[:100]})")

    if reasons:
        return Verdict.BLOCK, rule_id, "; ".join(reasons)

    return Verdict.ALLOW, None, "All signals passed"


def _ensemble_majority(
    signals: dict[str, Any],
) -> tuple[Verdict, str | None, str]:
    """
    Block if 2+ signals say block (majority of 3).
    """
    block_count = 0
    allow_count = 0
    unknown_count = 0
    block_reasons = []
    block_rule_id = None

    for name, result in signals.items():
        v = result.get("verdict", "unknown")
        if v == "block":
            block_count += 1
            rid = result.get("rule_id")
            if rid and block_rule_id is None:
                block_rule_id = rid
            block_reasons.append(f"{name}: BLOCK")
        elif v == "allow":
            allow_count += 1
        else:
            unknown_count += 1

    total = block_count + allow_count + unknown_count
    if total == 0:
        return Verdict.UNKNOWN, None, "No signals returned"

    if block_count >= 2:
        return Verdict.BLOCK, block_rule_id, (
            f"Majority ({block_count}/{total}) voted block: "
            + "; ".join(block_reasons)
        )

    if block_count == 1 and unknown_count > 0:
        # One block, some unknown — flag for review rather than hard block
        return Verdict.FLAGGED, block_rule_id, (
            f"Tie-ish ({block_count} block, {unknown_count} unknown): "
            "flagged for review"
        )

    return Verdict.ALLOW, None, (
        f"Majority ({allow_count}/{total}) voted allow"
    )


def _ensemble_all(
    signals: dict[str, Any],
) -> tuple[Verdict, str | None, str]:
    """
    Block only if ALL available signals say block.
    """
    reasons = []
    rule_id = None
    all_block = True
    any_available = False

    for name, result in signals.items():
        v = result.get("verdict", "unknown")
        if v != "unknown":
            any_available = True
        if v != "block":
            all_block = False
        else:
            rid = result.get("rule_id")
            if rid:
                rule_id = rid
            reasons.append(f"{name}: BLOCK")

    if not any_available:
        return Verdict.UNKNOWN, None, "No signals available"

    if all_block and reasons:
        return Verdict.BLOCK, rule_id, (
            f"All {len(reasons)} signals voted block: "
            + "; ".join(reasons)
        )

    return Verdict.ALLOW, None, (
        f"Not all signals blocked ({len(reasons)} block, "
        f"{len(signals) - len(reasons)} passed/unknown)"
    )


# ---------------------------------------------------------------------------
# Main classify function
# ---------------------------------------------------------------------------

def classify_node(state: PipelineState, config: dict[str, Any]) -> PipelineState:
    """
    LangGraph node: classify the ingested input text.

    Reads state.input_text (or state.full_text for the combined visible+hidden).
    Runs all three signals, ensembles the verdict, logs the decision, and
    writes the result to state.classification.

    If verdict is BLOCK, sets state.blocked = True and state.block_reason.
    """
    # Use the combined text (visible + extracted hidden) for classification
    # This is what the classifier actually sees
    text_to_classify = state.full_text or state.input_text or ""

    if not text_to_classify.strip():
        logger.warning("classify_node: empty input text — allowing through")
        state.classification = ClassificationResult(
            verdict=Verdict.ALLOW,
            rule_id=None,
            detail="Empty input — allowed through",
            signals={},
            input_hash=state.input_hash or "",
        )
        log_decision(
            logger,
            stage="classify",
            rule_id=None,
            input_hash=state.input_hash or "",
            action_attempted=None,
            verdict="passed",
            detail="Empty input, no classification needed",
        )
        return state

    # ---- Run signals ----

    # Signal 1: Heuristic (always runs)
    heuristic_matches = check_heuristics(text_to_classify)
    heuristic_blocked, heuristic_rule, heuristic_detail = heuristic_verdict(heuristic_matches)

    heuristic_signal = {
        "verdict": "block" if heuristic_blocked else "allow",
        "rule_id": heuristic_rule,
        "detail": heuristic_detail or "No heuristic patterns matched",
        "matches": [
            {"rule_id": m.rule_id, "pattern": m.pattern_name, "confidence": m.confidence}
            for m in heuristic_matches
        ],
    }

    # Signal 2: HF classifier (if available)
    hf_config = config.get("guard", {}).get("classifier", {})
    hf_threshold = hf_config.get("hf_threshold", 0.5)

    hf_guard = get_hf_guard(threshold=hf_threshold)
    hf_result = hf_guard.classify(text_to_classify)

    hf_signal = {
        "verdict": hf_result.verdict,
        "rule_id": hf_result.rule_id,
        "detail": hf_result.detail,
        "score": hf_result.score,
        "model_id": hf_result.model_id,
    }

    # Signal 3: LLM judge (if configured and available)
    llm_config = config.get("guard", {}).get("classifier", {})
    use_llm = llm_config.get("use_llm_judge", True)

    llm_signal = {}
    if use_llm:
        llm_judge = get_llm_judge(
            base_url=config.get("pipeline", {}).get("llm_base_url", "http://localhost:11434"),
            model=config.get("pipeline", {}).get("llm_model", "llama3.1"),
        )
        llm_result = llm_judge.classify(text_to_classify)
        llm_signal = {
            "verdict": llm_result.verdict,
            "rule_id": llm_result.rule_id,
            "detail": llm_result.detail,
            "latency_ms": llm_result.latency_ms,
        }

    # Combine signals
    signals = {"heuristic": heuristic_signal}
    if hf_signal.get("verdict") != "unknown" or hf_signal.get("available", False):
        signals["hf_classifier"] = hf_signal
    if llm_signal:
        signals["llm_judge"] = llm_signal

    # Ensemble
    ensemble_policy = config.get("guard", {}).get("classifier", {}).get("ensemble_policy", "any")

    if ensemble_policy == "majority":
        verdict, rule_id, detail = _ensemble_majority(signals)
    elif ensemble_policy == "all":
        verdict, rule_id, detail = _ensemble_all(signals)
    else:
        verdict, rule_id, detail = _ensemble_any(signals)

    classification = ClassificationResult(
        verdict=verdict,
        rule_id=rule_id,
        detail=detail,
        signals=signals,
        input_hash=state.input_hash or "",
    )

    state.classification = classification

    # ---- Log the decision ----

    log_decision(
        logger,
        stage="classify",
        rule_id=rule_id,
        input_hash=state.input_hash or "",
        action_attempted=None,
        verdict=verdict.value,
        detail=detail,
        signals={k: {"verdict": v.get("verdict")} for k, v in signals.items()},
    )

    # ---- If blocked, short-circuit ----

    if verdict == Verdict.BLOCK:
        state.blocked = True
        state.block_stage = "classify"
        state.block_rule_id = rule_id
        state.block_reason = detail
        logger.info(
            "classify_node: INPUT BLOCKED by rule %s — %s",
            rule_id or "N/A",
            detail[:200],
        )

    return state
