"""Output scanner.

Runs on the *proposed tool call*, not the document. This is the last line of
defense: even if a clever attack slipped past the input guard, its whole
point was to change what the agent does — and what the agent does is
visible right here, as structured arguments, before they execute.
"""
from __future__ import annotations

import re

from .models import RuleHit, ScanResult, ScoreResult, ToolCall, Verdict

_MAXED_NO_EVIDENCE = re.compile(r"complied with an instruction", re.IGNORECASE)
_HIRE_LANGUAGE_IN_EMAIL = re.compile(
    r"\byou'?re\s+hired\b|\boffer\s+of\s+employment\b|\bcongratulations.{0,20}\bposition\b",
    re.IGNORECASE,
)
_SELF_REFERENTIAL_STATUS = re.compile(r"\bstatus\s*[:=]\s*['\"]?hired['\"]?", re.IGNORECASE)


def scan_score_call(score_result: ScoreResult, tool_call: ToolCall) -> ScanResult:
    hits: list[RuleHit] = []
    deny = False

    if score_result.coerced:
        hits.append(
            RuleHit(
                rule_id="OUT-001-UNSUPPORTED-MAX-SCORE",
                family="output_scan",
                detail="score is at maximum with a rationale indicating compliance rather than evidence",
            )
        )
        deny = True
    elif score_result.value >= 0.98:
        # A maxed score is only suspicious when nothing outside the document
        # supports it. A resume that literally contains every job keyword
        # earns 1.0 legitimately — denying that inverts the whole point of
        # scoring, and was the source of the false positives on genuine
        # resumes. We still record OUT-001 as an informational hit so the
        # decision stays traceable to the rule that evaluated it.
        if score_result.evidence_backed:
            hits.append(
                RuleHit(
                    rule_id="OUT-001-UNSUPPORTED-MAX-SCORE",
                    family="output_scan",
                    detail="score is at maximum; corroborated by independent keyword evidence, so allowed",
                )
            )
        else:
            hits.append(
                RuleHit(
                    rule_id="OUT-001-UNSUPPORTED-MAX-SCORE",
                    family="output_scan",
                    detail="score is at/near maximum with no independent evidence backing it",
                )
            )
            deny = True

    if score_result.wants_direct_action:
        hits.append(
            RuleHit(
                rule_id="OUT-002-SCOPE-ESCAPE-ATTEMPT",
                family="output_scan",
                detail="scoring stage attempted to bypass its scope and act directly (email/ATS)",
            )
        )
        deny = True

    verdict = Verdict.DENY if deny else Verdict.ALLOW
    return ScanResult(verdict=verdict, hits=hits)


def scan_action_call(tool_call: ToolCall) -> ScanResult:
    hits: list[RuleHit] = []
    args = tool_call.arguments

    if tool_call.tool_name == "send_email":
        body = str(args.get("body", ""))
        if _HIRE_LANGUAGE_IN_EMAIL.search(body):
            hits.append(
                RuleHit(
                    rule_id="OUT-003-UNAUTHORIZED-OFFER",
                    family="output_scan",
                    detail="outgoing email contains a hiring decision the pipeline never approved",
                )
            )

    if tool_call.tool_name == "write_ats":
        status = str(args.get("status", ""))
        if status.lower() == "hired":
            hits.append(
                RuleHit(
                    rule_id="OUT-004-DIRECT-HIRE-WRITE",
                    family="output_scan",
                    detail="ATS write attempts to set status to 'hired' outside the review flow",
                )
            )

    verdict = Verdict.DENY if hits else Verdict.ALLOW
    return ScanResult(verdict=verdict, hits=hits)
