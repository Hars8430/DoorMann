"""
Output scanner node -- inspects tool arguments before dispatch.

Fourth layer of defense (after ingest extraction, input classifier,
context isolation). Inspects what the scoring stage is ABOUT to send
to the action stage before dispatch.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from pipeline_state import PipelineState
from tools.scoring_tools import ScoreResult
from logging_setup import log_decision

logger = logging.getLogger("doorman.nodes.output_scan")


@dataclass
class OutputScanResult:
    email_body_scanned: bool = False
    email_body_clean: bool = True
    email_body_detail: str = ""
    score_scanned: bool = False
    score_clean: bool = True
    score_detail: str = ""
    ats_scanned: bool = False
    ats_clean: bool = True
    ats_detail: str = ""
    overall_clean: bool = True
    overall_detail: str = ""


def output_scan_node(state: PipelineState, config: dict[str, Any]) -> PipelineState:
    """LangGraph node: scan proposed tool args before dispatch."""
    scan = OutputScanResult()

    pending_email = getattr(state, 'pending_email', None)
    if pending_email and pending_email.get('body'):
        scan.email_body_scanned = True
        body = pending_email['body']

        from guards.heuristic_guard import scan_output_text
        flags = scan_output_text(body)

        if flags:
            scan.email_body_clean = False
            scan.email_body_detail = (
                f"Email body flagged by output scanner: "
                + "; ".join(f"{f['rule_id']}: {f['matched_text'][:60]}" for f in flags)
            )
            logger.warning(
                "output_scan_node: EMAIL BODY FLAGGED -- %s",
                scan.email_body_detail[:200],
            )
        else:
            scan.email_body_detail = "Email body clean"

    score_result = state.score_result
    if score_result:
        scan.score_scanned = True

        if score_result.overall_score >= 9.5 and not score_result.evidence_summary:
            scan.score_clean = False
            scan.score_detail = (
                f"Score maxed at {score_result.overall_score}/10 with no evidence summary"
            )
            logger.warning(
                "output_scan_node: SCORE MAXED WITH NO EVIDENCE -- %s",
                scan.score_detail[:200],
            )
        elif score_result.overall_score >= 9.5 and len(score_result.evidence_summary) < 30:
            scan.score_clean = False
            scan.score_detail = (
                f"Score maxed at {score_result.overall_score}/10 with thin evidence"
            )
        elif score_result.overall_score == 10.0 and score_result.category != "top":
            scan.score_clean = False
            scan.score_detail = (
                f"Score is 10.0/10 but category is '{score_result.category}'"
            )
        elif score_result.justification and len(score_result.justification) > 50:
            from guards.heuristic_guard import scan_output_text
            flags = scan_output_text(score_result.justification)
            if flags:
                scan.score_clean = False
                scan.score_detail = (
                    f"Score justification contains instruction patterns: "
                    + "; ".join(f"{f['rule_id']}: {f['matched_text'][:60]}" for f in flags)
                )
            else:
                scan.score_detail = "Score evidence clean"
        else:
            scan.score_detail = "Score evidence clean"

    pending_ats = getattr(state, 'pending_ats', None)
    if pending_ats and pending_ats.get('status'):
        scan.ats_scanned = True
        status = pending_ats['status']

        valid_statuses = {"applied", "screening", "interview", "offer", "hired", "rejected"}

        if status not in valid_statuses:
            scan.ats_clean = False
            scan.ats_detail = f"ATS status '{status}' is not valid"
        elif status == "hired":
            scan.ats_clean = True
            scan.ats_detail = (
                "ATS status set to 'hired' -- valid but requires confirmation gate"
            )
            logger.info(
                "output_scan_node: ATS 'hired' status flagged for confirmation gate"
            )
        elif pending_ats.get('notes'):
            from guards.heuristic_guard import scan_output_text
            flags = scan_output_text(pending_ats['notes'])
            if flags:
                scan.ats_clean = False
                scan.ats_detail = (
                    f"ATS notes contain instruction patterns: "
                    + "; ".join(f"{f['rule_id']}: {f['matched_text'][:60]}" for f in flags)
                )
            else:
                scan.ats_detail = "ATS update clean"
        else:
            scan.ats_detail = "ATS update clean"

    scan.overall_clean = (
        scan.email_body_clean
        and scan.score_clean
        and (scan.ats_clean or (pending_ats and pending_ats.get('status') == 'hired'))
    )

    if not scan.overall_clean:
        detail_parts = []
        if not scan.email_body_clean:
            detail_parts.append(scan.email_body_detail)
        if not scan.score_clean:
            detail_parts.append(scan.score_detail)
        if not scan.ats_clean:
            detail_parts.append(scan.ats_detail)
        scan.overall_detail = " | ".join(detail_parts)

        state.pending_actions.append({
            "action_attempted": "send_email" if pending_email else ("write_ats" if pending_ats else "unknown"),
            "held_by": "output_scan",
            "reason": scan.overall_detail,
            "timestamp": state.timestamp,
        })
        state.held_count = getattr(state, 'held_count', 0) + 1

        log_decision(
            logger,
            stage="output_scan",
            rule_id="OS01",
            input_hash=state.input_hash or "",
            action_attempted="send_email" if pending_email else ("write_ats" if pending_ats else None),
            verdict="blocked",
            detail=scan.overall_detail,
        )
    else:
        log_decision(
            logger,
            stage="output_scan",
            rule_id=None,
            input_hash=state.input_hash or "",
            action_attempted="send_email" if pending_email else ("write_ats" if pending_ats else None),
            verdict="passed",
            detail="Output scan passed",
        )

    state.output_scan = scan

    return state
