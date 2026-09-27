"""
Confirmation gate node — irreversible actions require explicit confirmation.

Actions like send_email and write_ats (especially setting status to "hired")
are irreversible in a real system. The confirmation gate holds these in a
pending_actions queue and requires an explicit confirm signal before dispatch.

In the DOORMAN evaluation harness, the confirm signal is controlled by the
test — we verify that the gate correctly holds actions that should be held
and releases actions that are safe.

This is the FIFTH layer of defense. Even if the output scanner passes an
action, the confirmation gate provides a final check point.
"""

from __future__ import annotations

import logging

from pipeline_state import PipelineState
from logging_setup import log_decision

logger = logging.getLogger("doorman.nodes.confirm")


def confirm_node(state: PipelineState, config: dict[str, Any]) -> PipelineState:
    """
    LangGraph node: check the pending_actions queue and confirm or hold.

    In the evaluation harness:
      - If state.confirm_next is True, the next pending action is confirmed
        and moved to state.confirmed_actions.
      - If state.confirm_next is False (default), pending actions stay in
        the queue and state.needs_confirmation is set.

    In a real system, this would be a human-in-the-loop step or a separate
    confirmation API call. Here we model it for the eval harness.
    """
    if not state.pending_actions:
        state.needs_confirmation = False
        state.confirmed_actions = []
        return state

    # Check if we should confirm the next action
    confirm = state.confirm_next if hasattr(state, 'confirm_next') else False

    if confirm and state.pending_actions:
        # Confirm the first pending action
        action = state.pending_actions[0]
        state.confirmed_actions.append(action)
        state.pending_actions = state.pending_actions[1:]
        state.needs_confirmation = len(state.pending_actions) > 0

        log_decision(
            logger,
            stage="confirm",
            rule_id=action.get("rule_id"),
            input_hash=state.input_hash or "",
            action_attempted=action.get("action_attempted"),
            verdict="allowed",
            detail=f"Action confirmed: {action.get('action_attempted')} — {action.get('detail', '')[:100]}",
        )

        logger.info(
            "confirm_node: action CONFIRMED — %s",
            action.get("action_attempted", "unknown"),
        )
    else:
        state.needs_confirmation = True
        log_decision(
            logger,
            stage="confirm",
            rule_id=None,
            input_hash=state.input_hash or "",
            action_attempted=state.pending_actions[0].get("action_attempted") if state.pending_actions else None,
            verdict="held",
            detail=(
                f"{len(state.pending_actions)} action(s) pending confirmation. "
                f"Set confirm_next=True to confirm the next action."
            ),
        )

        logger.debug(
            "confirm_node: %d action(s) pending — confirmation required",
            len(state.pending_actions),
        )

    return state
