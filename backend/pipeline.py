"""Orchestration.

Two entry points:

  run_naive(path, ...)    — no guard, no allowlist, no output scan, no
                             confirmation gate. Tools are called directly the
                             instant the scorer decides to call them. This is
                             "the trap" made concrete: a recruiting agent
                             built the way most people build agent demos.

  run_guarded(path, ...)  — the full six-stage pipeline from the design doc.

Both return a PipelineResult with a complete structured log, so the eval
script can diff behavior on the exact same input.
"""
from __future__ import annotations

from pathlib import Path

from . import policy
from .confirmation import ConfirmationQueue
from .guard import Guard, build_default_guard
from .ingestion import extract_document
from .logger import DecisionLog
from .models import PipelineResult, Stage, ToolCall, Verdict
from .scanner import scan_action_call, scan_score_call
from .scorer import IsolatedScorer, NaiveScorer, Scorer
from .tools import ToolLedger


def run_naive(
    path: str,
    job_keywords: list[str],
    candidate_email: str = "candidate@example.com",
    scorer: Scorer | None = None,
) -> PipelineResult:
    document = extract_document(path)
    log = DecisionLog()
    ledger = ToolLedger()
    scorer = scorer or NaiveScorer()

    result = scorer.score(document, job_keywords)
    log.record(Stage.SCORING, Verdict.ALLOW, result.rationale, document.visible_text)

    ledger.score(candidate_id=document.filename, value=result.value, rationale=result.rationale)
    allowed = ["score"]

    # no allowlist, no scanner, no confirmation gate: if the (simulated)
    # model decided to act, it acts, immediately, for real.
    if result.wants_direct_action or result.value >= 0.9:
        ledger.send_email(
            to=candidate_email,
            subject="You're hired!",
            body="Congratulations, you've been selected for the position.",
        )
        ledger.write_ats(candidate_id=document.filename, status="hired")
        allowed += ["send_email", "write_ats"]
        log.record(Stage.CONFIRMATION, Verdict.ALLOW, "dispatched with no confirmation gate",
                    document.visible_text, action_attempted="send_email+write_ats")

    return PipelineResult(
        filename=document.filename,
        final_verdict=Verdict.ALLOW,
        blocked_at_stage=None,
        candidate_score=result.value,
        tool_calls_allowed=allowed,
        tool_calls_blocked=[],
        logs=log.entries,
        pending_actions=[],
    )


def run_guarded(
    path: str,
    job_keywords: list[str],
    candidate_email: str = "candidate@example.com",
    guard: Guard | None = None,
    scorer: Scorer | None = None,
) -> PipelineResult:
    document = extract_document(path)
    log = DecisionLog()
    ledger = ToolLedger()
    queue = ConfirmationQueue()
    guard = guard or build_default_guard()
    scorer = scorer or IsolatedScorer()

    blocked: list[str] = []
    allowed: list[str] = []

    # --- stage: input guard -------------------------------------------------
    guard_result = guard.score(document)
    rule_ids = ",".join(h.rule_id for h in guard_result.hits) or None
    log.record(
        Stage.GUARD, guard_result.verdict,
        f"score={guard_result.score} hits={[h.rule_id for h in guard_result.hits]}",
        document.visible_text, rule_id=rule_ids,
    )

    if guard_result.verdict == Verdict.DENY:
        return PipelineResult(
            filename=document.filename, final_verdict=Verdict.DENY,
            blocked_at_stage=Stage.GUARD, candidate_score=None,
            tool_calls_allowed=[], tool_calls_blocked=["score", "send_email", "write_ats"],
            logs=log.entries, pending_actions=[],
        )

    # --- stage: isolation (structural — document.visible_text already has
    # hidden spans removed by ingestion; nothing further to do here except
    # log that isolation held) -------------------------------------------
    log.record(Stage.ISOLATION, Verdict.ALLOW,
               "candidate content passed as fenced data, not instructions",
               document.visible_text)

    # --- stage: scoring (allowlist: score, flag_for_review only) ----------
    if guard_result.verdict == Verdict.HOLD:
        try:
            policy.check(Stage.SCORING, "flag_for_review")
        except policy.PolicyViolation:
            pass  # unreachable given ALLOWLIST above; defense in depth
        ledger.flag_for_review(candidate_id=document.filename,
                                reason=f"guard hold: {[h.rule_id for h in guard_result.hits]}")
        log.record(Stage.SCORING, Verdict.HOLD, "routed to human review queue instead of scoring",
                    document.visible_text, action_attempted="flag_for_review")
        return PipelineResult(
            filename=document.filename, final_verdict=Verdict.HOLD,
            blocked_at_stage=None, candidate_score=None,
            tool_calls_allowed=["flag_for_review"], tool_calls_blocked=["send_email", "write_ats"],
            logs=log.entries, pending_actions=[],
        )

    policy.check(Stage.SCORING, "score")  # raises if a refactor ever breaks the allowlist
    score_result = scorer.score(document, job_keywords)
    score_call = ToolCall(tool_name="score", arguments={"value": score_result.value})
    scan1 = scan_score_call(score_result, score_call)
    log.record(
        Stage.OUTPUT_SCAN, scan1.verdict,
        f"scanned proposed score={score_result.value}, hits={[h.rule_id for h in scan1.hits]}",
        document.visible_text, rule_id=",".join(h.rule_id for h in scan1.hits) or None,
    )

    if scan1.verdict == Verdict.DENY:
        return PipelineResult(
            filename=document.filename, final_verdict=Verdict.DENY,
            blocked_at_stage=Stage.OUTPUT_SCAN, candidate_score=None,
            tool_calls_allowed=[], tool_calls_blocked=["score", "send_email", "write_ats"],
            logs=log.entries, pending_actions=[],
        )

    ledger.score(candidate_id=document.filename, value=score_result.value, rationale=score_result.rationale)
    allowed.append("score")

    # --- stage: propose action, still gated by allowlist + scanner --------
    status = "interview" if score_result.value >= 0.6 else "not_selected"
    subject = "Next steps on your application" if status == "interview" else "Update on your application"
    body = (
        "Thanks for applying — we'd like to schedule an interview."
        if status == "interview"
        else "Thanks for applying. We will not be moving forward at this time."
    )
    email_call = ToolCall(tool_name="send_email",
                           arguments={"to": candidate_email, "subject": subject, "body": body})
    ats_call = ToolCall(tool_name="write_ats", arguments={"status": status})

    for call in (email_call, ats_call):
        try:
            policy.check(Stage.CONFIRMATION, call.tool_name)
        except policy.PolicyViolation:
            blocked.append(call.tool_name)
            continue
        scan2 = scan_action_call(call)
        log.record(
            Stage.OUTPUT_SCAN, scan2.verdict,
            f"scanned proposed {call.tool_name}, hits={[h.rule_id for h in scan2.hits]}",
            document.visible_text, rule_id=",".join(h.rule_id for h in scan2.hits) or None,
            action_attempted=call.tool_name,
        )
        if scan2.verdict == Verdict.DENY:
            blocked.append(call.tool_name)
            continue
        queue.enqueue(call)
        log.record(Stage.CONFIRMATION, Verdict.HOLD, "queued pending human confirmation",
                    document.visible_text, action_attempted=call.tool_name)

    return PipelineResult(
        filename=document.filename,
        final_verdict=Verdict.ALLOW if not blocked else Verdict.HOLD,
        blocked_at_stage=None,
        candidate_score=score_result.value,
        tool_calls_allowed=allowed,
        tool_calls_blocked=blocked,
        logs=log.entries,
        pending_actions=queue.pending,
    )
