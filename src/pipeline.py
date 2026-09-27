"""
LangGraph pipeline definition -- the 7-node graph that models the full
Doorman recruiting-agent pipeline with guardrails.

Graph structure:
  ingest -> classify -> isolate -> score -> output_scan -> confirm -> action

Each node is a function that takes PipelineState and returns PipelineState.
The graph is compiled with LangGraph's StateGraph and can be run end-to-end.

The tool allowlist is STRUCTURAL: each node type has a fixed set of tools
it can call, enforced by the dispatch_tool() policy layer, not by prompting
the LLM to behave.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from langgraph.graph import StateGraph, END

from pipeline_state import PipelineState
from nodes.ingest import ingest_node
from nodes.classify import classify_node
from nodes.isolate import isolate_node
from nodes.score import score_node
from nodes.output_scan import output_scan_node
from nodes.confirm import confirm_node
from logging_setup import log_decision, get_logger

logger = get_logger("doorman.pipeline")


# ---------------------------------------------------------------------------
# Action stage node -- only called if the pipeline is NOT blocked
# ---------------------------------------------------------------------------

def action_node(state: PipelineState, config: dict[str, Any]) -> PipelineState:
    """
    LangGraph node: execute confirmed actions.

    This is the FINAL stage. It dispatches confirmed actions from the
    confirmed_actions queue. Only actions that have passed through:
      1. Input classifier (not blocked)
      2. Context isolation
      3. Scoring stage (structural tool allowlist)
      4. Output scanner (clean)
      5. Confirmation gate (explicitly confirmed)

    ...are dispatched here.

    In mock mode, this logs what would happen. In production, this would
    call the real SMTP and ATS APIs.
    """
    if not state.confirmed_actions:
        logger.info("action_node: no confirmed actions to dispatch")
        state.pipeline_verdict = "allowed_no_actions"
        state.pipeline_summary = "Pipeline completed -- no actions required"
        return state

    from tools.action_tools import send_email, write_ats

    results = []
    for action in state.confirmed_actions:
        tool_name = action.get("action_attempted", "")
        action_result = None

        if tool_name == "send_email":
            email = action.get("email", {})
            action_result = send_email(
                to_address=email.get("to", ""),
                subject=email.get("subject", ""),
                body=email.get("body", ""),
                candidate_name=state.candidate_name or None,
            )
        elif tool_name == "write_ats":
            ats = action.get("ats", {})
            action_result = write_ats(
                candidate_id=ats.get("candidate_id", state.candidate_id or "unknown"),
                status=ats.get("status", ""),
                notes=ats.get("notes", None),
                score=state.score_result.overall_score if state.score_result else None,
            )
        else:
            action_result = None

        results.append({
            "action": action,
            "result": action_result,
        })

        log_decision(
            logger,
            stage="action",
            rule_id=None,
            input_hash=state.input_hash or "",
            action_attempted=tool_name,
            verdict="allowed",
            detail=f"Action dispatched: {tool_name} -- {action_result.message if action_result else 'N/A'}",
        )

        logger.info(
            "action_node: DISPATCHED %s -- %s",
            tool_name,
            action_result.message if action_result else "N/A",
        )

    state.pipeline_verdict = "allowed"
    state.pipeline_summary = (
        f"Pipeline completed successfully -- {len(results)} action(s) dispatched: "
        + ", ".join(r["action"].get("action_attempted", "?") for r in results)
    )

    return state


# ---------------------------------------------------------------------------
# Conditional edge: should we go to action stage or end?
# ---------------------------------------------------------------------------

def should_proceed_to_action(state: PipelineState) -> str:
    """
    Conditional edge function: determine whether to proceed to action stage.

    Returns:
      - "action" if the pipeline should proceed to the action stage
      - END if the pipeline should stop (blocked or no actions needed)

    Blocking conditions:
      - state.blocked == True (blocked by classifier or other stage)
      - No pending email or ATS update (nothing to do)
      - Output scan is not clean (action held)

    The action stage only receives candidates that:
      1. Passed the input classifier
      2. Have a valid score result
      3. Have a pending email or ATS update that passed the output scan
    """
    if state.blocked:
        logger.info(
            "should_proceed_to_action: BLOCKED at %s by rule %s -- %s",
            state.block_stage,
            state.block_rule_id or "N/A",
            state.block_reason[:100],
        )
        state.pipeline_verdict = "blocked"
        state.pipeline_summary = (
            f"Pipeline BLOCKED at {state.block_stage} stage by rule {state.block_rule_id or 'N/A'}: "
            f"{state.block_reason[:150]}"
        )
        return END

    # Check if there's anything to do
    has_email = bool(getattr(state, 'pending_email', None) and state.pending_email.get('body'))
    has_ats = bool(getattr(state, 'pending_ats', None) and state.pending_ats.get('status'))

    if not has_email and not has_ats:
        state.pipeline_verdict = "allowed_no_actions"
        state.pipeline_summary = "Pipeline completed -- no actions required (no email or ATS update triggered)"
        return END

    # Check output scan
    scan = state.output_scan
    if scan and not scan.overall_clean:
        state.pipeline_verdict = "held_for_review"
        state.pipeline_summary = (
            f"Pipeline held at output scan -- {scan.overall_detail[:150]}"
        )
        return END

    # Check if we need confirmation
    if state.needs_confirmation and not state.confirmed_actions:
        # In the real pipeline, this would pause for human confirmation
        # In the eval harness, we set state.confirm_next to auto-confirm
        logger.info(
            "should_proceed_to_action: %d action(s) pending confirmation",
            len(state.pending_actions),
        )
        # For the eval harness, we auto-confirm if confirm_next is set
        if getattr(state, 'confirm_next', False):
            # The confirm node will handle this
            return "confirm"
        else:
            state.pipeline_verdict = "held_for_review"
            state.pipeline_summary = (
                f"Pipeline held -- {len(state.pending_actions)} action(s) require confirmation"
            )
            return END

    return "action"


# ---------------------------------------------------------------------------
# Build the graph
# ---------------------------------------------------------------------------

def build_pipeline_graph() -> StateGraph:
    """
    Build and return the compiled LangGraph pipeline.

    The graph is:
      ingest -> classify -> isolate -> score -> output_scan -> confirm -> action -> END

    With a conditional edge after output_scan that checks whether to proceed
    to action or end.
    """
    # Define the state type
    # StateGraph uses a TypedDict or dataclass; we use PipelineState

    graph = StateGraph(PipelineState)

    # Add nodes
    graph.add_node("ingest", ingest_node)
    graph.add_node("classify", classify_node)
    graph.add_node("isolate", isolate_node)
    graph.add_node("score", score_node)
    graph.add_node("output_scan", output_scan_node)
    graph.add_node("confirm", confirm_node)
    graph.add_node("action", action_node)

    # Set entry point
    graph.set_entry_point("ingest")

    # Add edges (linear flow)
    graph.add_edge("ingest", "classify")
    graph.add_edge("classify", "isolate")
    graph.add_edge("isolate", "score")
    graph.add_edge("score", "output_scan")

    # Conditional edge after output_scan: action or confirm or end?
    graph.add_conditional_edges(
        "output_scan",
        should_proceed_to_action,
        {
            "action": "action",
            "confirm": "confirm",
            END: END,
        },
    )

    # confirm -> action (after confirmation, proceed to action)
    graph.add_edge("confirm", "action")

    # action -> END (pipeline complete)
    graph.add_edge("action", END)

    # Compile
    compiled = graph.compile()
    logger.info("build_pipeline_graph: graph compiled successfully -- 7 nodes, linear + 1 conditional edge")

    return compiled


# ---------------------------------------------------------------------------
# Convenience: run the pipeline on a single input
# ---------------------------------------------------------------------------

def run_pipeline(
    input_text: str,
    candidate_id: str = "",
    candidate_name: str = "",
    job_description: str = "",
    pdf_path: str = "",
    config: dict[str, Any] | None = None,
    confirm_next: bool = False,
) -> PipelineState:
    """
    Run the full Doorman pipeline on a single input.

    This is the main entry point for the demo and for the eval harness.

    Parameters
    ----------
    input_text : str
        The resume text (or PDF path if pdf_path is set).
    candidate_id : str
        Candidate identifier.
    candidate_name : str
        Candidate name (for email personalization).
    job_description : str
        The job description to score against.
    pdf_path : str
        Path to a PDF file (optional -- if set, PDF ingestion is used).
    config : dict
        Pipeline configuration (loaded from settings.yaml by default).
    confirm_next : bool
        If True, auto-confirm pending actions (for eval harness).

    Returns
    -------
    PipelineState
        The final state after the pipeline completes.
    """
    from config.loader import load_config
    from logging_setup import setup_logging

    if config is None:
        config = load_config()

    # Set up logging
    output_dir = config.get("evaluation", {}).get("output_dir", "output")
    setup_logging(output_dir=output_dir)

    # Build initial state
    state = PipelineState(
        run_id="",
        candidate_id=candidate_id,
        candidate_name=candidate_name,
        input_text=input_text if not pdf_path else "",
        full_text=input_text if not pdf_path else "",
        job_description=job_description,
        pdf_path=pdf_path if pdf_path else None,
        timestamp="",
        confirm_next=confirm_next,
    )

    # Re-hash after PDF ingestion might change full_text
    # (the ingest node will set input_hash)

    # Build and run the graph
    graph = build_pipeline_graph()

    logger.info(
        "run_pipeline: starting run %s -- candidate=%s, pdf=%s",
        state.run_id or "auto",
        candidate_name or "unknown",
        "yes" if pdf_path else "no",
    )

    # Run the graph
    final_state = graph.invoke(state, config)

    logger.info(
        "run_pipeline: run %s complete -- verdict=%s -- %s",
        final_state.run_id or "auto",
        final_state.pipeline_verdict,
        final_state.pipeline_summary[:150],
    )

    return final_state
