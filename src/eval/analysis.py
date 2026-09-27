"""
Analysis utilities for Doorman evaluation harness.

Computes metrics, formats reports, and generates verdict tables from
evaluation results.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class EvalResult:
    """Result of running one input through the pipeline."""
    input_id: str
    input_type: str  # "attack" or "benign"
    family: str = ""
    technique: str = ""
    input_text: str = ""
    verdict: str = ""
    blocked: bool = False
    block_stage: str = ""
    block_rule_id: str = ""
    block_reason: str = ""
    classification: str = ""
    heuristic_matches: list[dict] = field(default_factory=list)
    hf_score: float | None = None
    hf_verdict: str = ""
    llm_judge_verdict: str = ""
    hidden_text_found: bool = False
    hidden_text_detail: str = ""
    score: float | None = None
    score_category: str = ""
    pending_actions: list[dict] = field(default_factory=list)
    confirmed_actions: list[dict] = field(default_factory=list)
    held_count: int = 0
    output_scan_clean: bool = True
    pipeline_summary: str = ""
    latency_ms: float = 0.0
    signals: list[str] = field(default_factory=list)


@dataclass
class EvalResults:
    """Collection of all evaluation results."""
    results: list[EvalResult] = field(default_factory=list)
    total: int = 0
    blocked: int = 0
    held: int = 0
    allowed: int = 0
    allowed_no_actions: int = 0
    by_family: dict[str, Any] = field(default_factory=dict)
    by_technique: dict[str, Any] = field(default_factory=dict)
    bypass_count: int = 0
    avg_score: float = 0.0
    avg_latency: float = 0.0


def compute_metrics(results: EvalResults) -> dict[str, Any]:
    """Compute aggregate metrics from evaluation results."""
    metrics = {}

    total = len(results.results)
    blocked = sum(1 for r in results.results if r.blocked)
    held = sum(1 for r in results.results if r.verdict == "held_for_review")
    allowed = sum(1 for r in results.results if r.verdict in ("allowed", "allowed_no_actions"))
    allowed_no_actions = sum(1 for r in results.results if r.verdict == "allowed_no_actions")

    attack_results = [r for r in results.results if r.input_type == "attack"]
    benign_results = [r for r in results.results if r.input_type == "benign"]

    metrics["total"] = total
    metrics["blocked"] = blocked
    metrics["held"] = held
    metrics["allowed"] = allowed
    metrics["allowed_no_actions"] = allowed_no_actions
    metrics["block_rate"] = blocked / total if total > 0 else 0.0
    metrics["attack_total"] = len(attack_results)
    metrics["benign_total"] = len(benign_results)

    if attack_results:
        scores = [r.score for r in attack_results if r.score is not None]
        metrics["avg_attack_score"] = sum(scores) / len(scores) if scores else 0.0

    if benign_results:
        b_blocked = sum(1 for r in benign_results if r.blocked)
        b_held = sum(1 for r in benign_results if r.verdict == "held_for_review")
        metrics["benign_blocked"] = b_blocked
        metrics["benign_held"] = b_held
        metrics["benign_block_rate"] = b_blocked / len(benign_results) if benign_results else 0.0

    metrics["by_family"] = {}
    for r in attack_results:
        fam = r.family or "unknown"
        if fam not in metrics["by_family"]:
            metrics["by_family"][fam] = {"total": 0, "blocked": 0, "held": 0, "allowed": 0}
        metrics["by_family"][fam]["total"] += 1
        if r.blocked:
            metrics["by_family"][fam]["blocked"] += 1
        elif r.verdict == "held_for_review":
            metrics["by_family"][fam]["held"] += 1
        else:
            metrics["by_family"][fam]["allowed"] += 1

    for fam, data in metrics["by_family"].items():
        data["block_rate"] = data["blocked"] / data["total"] if data["total"] > 0 else 0.0

    metrics["by_technique"] = {}
    for r in attack_results:
        tech = r.technique or "unknown"
        if tech not in metrics["by_technique"]:
            metrics["by_technique"][tech] = {"total": 0, "blocked": 0, "held": 0, "allowed": 0}
        metrics["by_technique"][tech]["total"] += 1
        if r.blocked:
            metrics["by_technique"][tech]["blocked"] += 1
        elif r.verdict == "held_for_review":
            metrics["by_technique"][tech]["held"] += 1
        else:
            metrics["by_technique"][tech]["allowed"] += 1

    for tech, data in metrics["by_technique"].items():
        data["block_rate"] = data["blocked"] / data["total"] if data["total"] > 0 else 0.0

    results.by_family = metrics["by_family"]
    results.by_technique = metrics["by_technique"]

    return metrics


def format_verdict_table(results: EvalResults) -> str:
    """Format a Markdown table of all results."""
    lines = []
    lines.append("| ID | Type | Family | Technique | Verdict | Rule | Score | Hidden | Signals |")
    lines.append("|----|------|--------|-----------|---------|------|-------|--------|---------|")

    for r in results.results:
        verdict_display = r.verdict
        if r.verdict == "blocked":
            verdict_display = "BLOCKED"
        elif r.verdict == "held_for_review":
            verdict_display = "HELD"
        elif r.verdict == "allowed_no_actions":
            verdict_display = "ALLOW (no action)"

        rule = r.block_rule_id if r.block_rule_id else "-"
        score = f"{r.score:.1f}" if r.score is not None else "-"
        hidden = "YES" if r.hidden_text_found else "-"
        signals = ", ".join(r.signals[:3]) if r.signals else "-"

        lines.append(
            f"| {r.input_id} | {r.input_type} | {r.family} | {r.technique} | "
            f"{verdict_display} | {rule} | {score} | {hidden} | {signals} |"
        )

    return "\n".join(lines)


def format_corpus_summary(results: EvalResults) -> str:
    """Format a summary of the corpus."""
    lines = []
    lines.append("# Doorman Evaluation Summary")
    lines.append("")
    lines.append(f"**Total inputs:** {len(results.results)}")
    lines.append(f"  - Attacks: {results.attack_total if hasattr(results, 'attack_total') else sum(1 for r in results.results if r.input_type == 'attack')}")
    lines.append(f"  - Benign:  {results.benign_total if hasattr(results, 'benign_total') else sum(1 for r in results.results if r.input_type == 'benign')}")
    lines.append("")

    if results.results:
        blocked = sum(1 for r in results.results if r.blocked)
        held = sum(1 for r in results.results if r.verdict == "held_for_review")
        allowed = sum(1 for r in results.results if r.verdict in ("allowed", "allowed_no_actions"))
        total = len(results.results)

        lines.append(f"**Overall:**")
        lines.append(f"- Blocked: {blocked} ({blocked/total:.1%})")
        lines.append(f"- Held:    {held} ({held/total:.1%})")
        lines.append(f"- Allowed: {allowed} ({allowed/total:.1%})")
        lines.append("")

    attack_results = [r for r in results.results if r.input_type == "attack"]
    if attack_results:
        lines.append("**Per-family breakdown:**")
        lines.append("")
        families = defaultdict(list)
        for r in attack_results:
            families[r.family or "unknown"].append(r)

        for fam in sorted(families.keys()):
            fam_results = families[fam]
            fam_blocked = sum(1 for r in fam_results if r.blocked)
            fam_held = sum(1 for r in fam_results if r.verdict == "held_for_review")
            fam_allowed = len(fam_results) - fam_blocked - fam_held
            lines.append(f"  {fam} ({len(fam_results)} attacks):")
            lines.append(f"    Blocked: {fam_blocked} | Held: {fam_held} | Allowed: {fam_allowed}")

        lines.append("")

    benign_results = [r for r in results.results if r.input_type == "benign"]
    if benign_results:
        lines.append("**Benign set:**")
        b_blocked = sum(1 for r in benign_results if r.blocked)
        b_held = sum(1 for r in benign_results if r.verdict == "held_for_review")
        lines.append(f"  Total: {len(benign_results)}")
        lines.append(f"  Blocked (FPR): {b_blocked} ({b_blocked/len(benign_results):.1%})")
        lines.append(f"  Held: {b_held}")
        lines.append("")

    return "\n".join(lines)


def format_bypass_report(bypasses: list[dict]) -> str:
    """Format a bypass report."""
    if not bypasses:
        return "No bypasses detected."

    lines = []
    lines.append("## Bypass Report")
    lines.append("")
    for bp in bypasses:
        lines.append(f"### {bp.get('id', 'unknown')} ({bp.get('family', 'unknown')})")
        lines.append(f"- Technique: {bp.get('technique', 'N/A')}")
        lines.append(f"- Verdict: {bp.get('verdict', 'N/A')}")
        lines.append(f"- Signals fired: {', '.join(bp.get('signals', []) or ['none'])}")
        lines.append(f"- Block reason: {bp.get('block_reason', 'N/A')}")
        lines.append("")

    return "\n".join(lines)


def generate_report(results: EvalResults) -> str:
    """Generate a full Markdown evaluation report."""
    metrics = compute_metrics(results)

    lines = []
    lines.append("# Doorman Evaluation Report")
    lines.append("")
    lines.append(f"Generated from {len(results.results)} inputs ({metrics.get('attack_total', 0)} attacks + {metrics.get('benign_total', 0)} benign)")
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- **Total:** {metrics['total']}")
    lines.append(f"- **Blocked:** {metrics['blocked']} ({metrics['block_rate']:.1%})")
    lines.append(f"- **Held for review:** {metrics['held']}")
    lines.append(f"- **Allowed:** {metrics['allowed']}")
    lines.append("")

    if attack_results := [r for r in results.results if r.input_type == "attack"]:
        scores = [r.score for r in attack_results if r.score is not None]
        lines.append(f"- **Avg attack score:** {sum(scores)/len(scores):.2f}" if scores else "- **Avg attack score:** N/A")
        lines.append("")

    lines.append("## Per-Family Breakdown")
    lines.append("")
    if metrics.get("by_family"):
        lines.append("| Family | Total | Blocked | Held | Allowed | Block Rate |")
        lines.append("|--------|-------|---------|------|---------|------------|")
        for fam, data in sorted(metrics["by_family"].items()):
            lines.append(
                f"| {fam} | {data['total']} | {data['blocked']} | {data['held']} | "
                f"{data['allowed']} | {data['block_rate']:.1%} |"
            )
    lines.append("")

    if metrics.get("by_technique"):
        lines.append("## Per-Technique Breakdown")
        lines.append("")
        lines.append("| Technique | Total | Blocked | Held | Allowed | Block Rate |")
        lines.append("|-----------|-------|---------|------|---------|------------|")
        for tech, data in sorted(metrics["by_technique"].items()):
            lines.append(
                f"| {tech} | {data['total']} | {data['blocked']} | {data['held']} | "
                f"{data['allowed']} | {data['block_rate']:.1%} |"
            )
        lines.append("")

    if benign_results := [r for r in results.results if r.input_type == "benign"]:
        lines.append("## Benign Set (FPR)")
        lines.append("")
        b_total = len(benign_results)
        b_blocked = sum(1 for r in benign_results if r.blocked)
        b_held = sum(1 for r in benign_results if r.verdict == "held_for_review")
        lines.append(f"- Total benign: {b_total}")
        lines.append(f"- Blocked: {b_blocked} ({b_blocked/b_total:.1%})" if b_total > 0 else "- Total benign: 0")
        lines.append(f"- Held: {b_held}")
        lines.append("")

    return "\n".join(lines)
