"""
Heuristic input guard — fast, regex/pattern-based pre-filter.

This catches obvious attack patterns BEFORE the HF classifier or LLM judge
see the content. It's the first line of defense and the cheapest to run.

Patterns are organized into rule IDs so every block is traceable:
  R01 - Direct instruction override ("ignore previous instructions", "disregard", etc.)
  R02 - System prompt exfiltration ("what are your instructions", "reveal your system prompt")
  R03 - Role/identity override ("you are now", "act as", "pretend to be")
  R04 - Constraint removal ("no restrictions", "ignore safety", "bypass filters")
  R05 - Instruction injection framing ("translate the following", "follow these steps")
  R06 - Delimiter/jailbreak patterns ("###", "```", "<<<", repeated special chars)

Each rule returns (matched: bool, rule_id: str, detail: str).
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass
from typing import Pattern

logger = logging.getLogger("doorman.guards.heuristic")


@dataclass
class HeuristicMatch:
    rule_id: str
    pattern_name: str
    matched_text: str
    confidence: float  # 0.0 - 1.0, how strongly this pattern matched


# ---------------------------------------------------------------------------
# Rule definitions — each is (name, compiled_regex, description)
# ---------------------------------------------------------------------------

# R01: Direct instruction override
R01_PATTERNS: list[tuple[str, Pattern, str]] = [
    (
        "ignore_previous",
        re.compile(r"(?i)\b(ignore|forget|disregard)\s+(your\s+)?(previous|prior|above|all\s+)?(instructions|rules|guidelines|directives|prompt|training)\b"),
        "Direct instruction override — tells the model to ignore its prior instructions",
    ),
    (
        "new_instructions_replace",
        re.compile(r"(?i)\b(from\s+now(on)?\s+)?(follow|obey|adhere to|execute)\s+(these|the\s+following|new|different)\s+(instructions|rules|directions|orders|commands)\b"),
        "Declares new instructions that replace prior ones",
    ),
    (
        "system_prompt_override",
        re.compile(r"(?i)\b(you\s+are\s+no\s+longer|you\s+have\s+been\s+reprogrammed|your\s+programming\s+has\s+been|ignore\s+the\s+above)\b"),
        "Explicit claim that the model's programming/system prompt has changed",
    ),
]

# R02: System prompt exfiltration / introspection attacks
R02_PATTERNS: list[tuple[str, Pattern, str]] = [
    (
        "reveal_instructions",
        re.compile(r"(?i)\b(reveal|show|output|display|print|list|enumerate|tell\s+me)\s+(your|the)\s+(instructions|rules|guidelines|system\s+prompt|system\s+message|initial\s+prompt|base\s+prompt|original\s+prompt)\b"),
        "Asks the model to reveal its own instructions or system prompt",
    ),
    (
        "what_are_you",
        re.compile(r"(?i)\b(what\s+are\s+(you|your))\s+(instructions|rules|guidelines|system\s+prompt|training|programming|restrictions|safety\s+filters)\b"),
        "Interrogates the model about its own rules or constraints",
    ),
    (
        "repeat_prompt",
        re.compile(r"(?i)\b(repeat|echo|copy|regurgitate|reproduce|output)\s+(your|the|all\s+of\s+your)\s+(prompt|instructions|rules|system\s+prompt|sentence|words|text)\b"),
        "Asks the model to repeat its own prompt or instructions",
    ),
]

# R03: Role/identity override
R03_PATTERNS: list[tuple[str, Pattern, str]] = [
    (
        "role_override",
        re.compile(r"(?i)\b(you\s+are\s+now|from\s+now(on)?\s+you\s+are|your\s+new\s+role|you\s+will\s+be|act\s+as|pretend\s+to\s+be|you\s+are\s+a|your\s+persona\s+is|adopt\s+the\s+persona)\b"),
        "Attempts to override the model's identity or role",
    ),
    (
        "persona_with_instructions",
        re.compile(r"(?i)\b(you\s+are\s+(now\s+)?a|act\s+as|pretend\s+to\s+be)\s+\w+.{0,50}(instructions|rules|should|must|will|going\s+to)\b"),
        "Assigns a persona AND gives instructions — classic jailbreak framing",
    ),
    (
        "daemon_mode",
        re.compile(r"(?i)\b(enter|switch\s+to|activate)\s+(daemon|developer|admin|root|god|jailbreak|unrestricted|unfiltered|no-?filter|raw)\s+mode\b"),
        "Attempts to switch the model into an unrestricted mode",
    ),
]

# R04: Constraint removal
R04_PATTERNS: list[tuple[str, Pattern, str]] = [
    (
        "no_restrictions",
        re.compile(r"(?i)\b(no|without\s+any|all\s+)?(restrictions|limitations|constraints|safety\s+measures|content\s+policy|safety\s+filters|guardrails|rules)\b"),
        "Declares absence of restrictions or attempts to remove them",
    ),
    (
        "ignore_safety",
        re.compile(r"(?i)\b(ignore|disregard|bypass|circumvent|override|disable|turn\s+off|remove)\s+(safety|safety\s+filters|content\s+filter|safety\s+mechanisms|safety\s+measures|ethical\s+guidelines|Asimov|guardrails)\b"),
        "Direct attempt to disable safety mechanisms",
    ),
    (
        "no_filter",
        re.compile(r"(?i)\b(respond|answer|generate|produce)\s+(without|with\s+no|unfiltered|uncensored|unrestricted|raw|explicit)\s+(filters|limitations|restrictions|safety|checks|guidelines)\b"),
        "Asks for output without safety filtering",
    ),
]

# R05: Instruction injection framing
R05_PATTERNS: list[tuple[str, Pattern, str]] = [
    (
        "command_framing",
        re.compile(r"(?i)\b(translate|convert|transform|rewrite|process|execute|run|perform|do)\s+(the\s+following|this|these)\s+(instructions|commands|steps|operations|tasks|actions)\b"),
        "Frames a block of text as instructions to execute",
    ),
    (
        "instruction_block_intro",
        re.compile(r"(?i)\b(follow|obey|execute|carry\s+out|implement)\s+(these|the\s+following|all\s+of\s+the|every)\s+(instructions|directions|commands|steps|orders)\b"),
        "Explicit command to follow a block of instructions",
    ),
    (
        "data_as_instruction",
        re.compile(r"(?i)\b(this\s+is\s+not\s+a\s+request|this\s+is\s+an\s+(important\s+)?instruction|pay\s+attention|listen\s+carefully|read\s+carefully|note\s+that)\b.{0,100}(instruction|command|order|direction|rule)\b"),
        "Attempts to frame data as instructions by claiming it's important",
    ),
]

# R06: Delimiter and jailbreak pattern abuse
R06_PATTERNS: list[tuple[str, Pattern, str]] = [
    (
        "code_block_framing",
        re.compile(r"```\s*(?:[a-zA-Z0-9]+)?\s*\n"),
        "Code-block delimiters often used to frame injected instructions as 'code'",
    ),
    (
        "hash_separator",
        re.compile(r"#{3,}\s*\n"),
        "Hash separators (###) used to demarcate 'secret' instruction blocks",
    ),
    (
        "angle_bracket_block",
        re.compile(r"\<\<\<|\>\>\>|\<\<|\>\>"),
        "Angle-bracket delimiters used to frame instruction blocks",
    ),
    (
        "base64_instruction_lure",
        re.compile(r"(?i)(decode|decrypt|decode\s+and\s+follow|execute\s+the\s+decoded|follow\s+the\s+instructions\s+in)\s+(this|the\s+following|the\s+encoded)\s+(base64|string|text|message|data|block)"),
        "Lure to decode and follow instructions hidden in encoded data",
    ),
    (
        "foreign_char_injection",
        re.compile(r"[\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2060\ufeff\u00ad]"),
        "Zero-width / invisible Unicode characters — often used to obfuscate trigger words",
    ),
    (
        "excessive_delimiters",
        re.compile(r"\{3,}|---+?|===(?!>)|:::(?!:)|\_+"),
        "Excessive use of delimiter characters to frame instruction blocks",
    ),
]


# ---------------------------------------------------------------------------
# Main heuristic check
# ---------------------------------------------------------------------------

def check_heuristics(text: str) -> list[HeuristicMatch]:
    """
    Run all heuristic patterns against the input text.

    Returns a list of HeuristicMatch objects — empty list means no pattern
    matched. Each match has a rule_id (R01-R06), the pattern name, the
    matched text snippet, and a confidence score.
    """
    matches: list[HeuristicMatch] = []
    text_for_matching = text

    # Check for invisible Unicode first — if present, boost confidence of
    # any other matches since this is a strong obfuscation signal
    invisible_found = False
    for name, pattern, desc in R06_PATTERNS:
        if name == "foreign_char_injection":
            if pattern.search(text):
                invisible_found = True
                matches.append(HeuristicMatch(
                    rule_id="R06",
                    pattern_name=name,
                    matched_text="<invisible_unicode_detected>",
                    confidence=0.8,
                ))
            break

    all_patterns = (
        R01_PATTERNS + R02_PATTERNS + R03_PATTERNS +
        R04_PATTERNS + R05_PATTERNS + R06_PATTERNS
    )

    for family_name, pattern, desc in all_patterns:
        m = pattern.search(text_for_matching)
        if m:
            # Map family name to rule ID
            if family_name in [p[0] for p in R01_PATTERNS]:
                rid = "R01"
            elif family_name in [p[0] for p in R02_PATTERNS]:
                rid = "R02"
            elif family_name in [p[0] for p in R03_PATTERNS]:
                rid = "R03"
            elif family_name in [p[0] for p in R04_PATTERNS]:
                rid = "R04"
            elif family_name in [p[0] for p in R05_PATTERNS]:
                rid = "R05"
            else:
                rid = "R06"

            confidence = 0.6
            if invisible_found and rid != "R06":
                confidence = min(confidence + 0.2, 1.0)

            matches.append(HeuristicMatch(
                rule_id=rid,
                pattern_name=family_name,
                matched_text=m.group(0)[:100],
                confidence=confidence,
            ))

    return matches


def heuristic_verdict(matches: list[HeuristicMatch]) -> tuple[bool, str | None, str | None]:
    """
    Convert heuristic matches to a verdict.

    Returns (is_attack, rule_id, detail).
    """
    if not matches:
        return False, None, None

    # Take the highest-confidence match
    best = max(matches, key=lambda m: m.confidence)
    return True, best.rule_id, (
        f"Heuristic rule {best.rule_id} ({best.pattern_name}) matched: "
        f"'{best.matched_text}' (confidence {best.confidence:.2f})"
    )


# ---------------------------------------------------------------------------
# Quick check for the output scanner (lighter version)
# ---------------------------------------------------------------------------

OUTPUT_SCANNER_PATTERNS: list[Pattern] = [
    re.compile(r"(?i)\b(ignore|forget|disregard)\s+(previous|prior|all\s+)?(instructions|rules|guidelines|prompt)\b"),
    re.compile(r"(?i)\b(reveal|show|output|display)\s+(your|the)\s+(instructions|rules|system\s+prompt|prompt)\b"),
    re.compile(r"(?i)\b(you\s+are\s+now|from\s+now(on)?\s+you\s+are|act\s+as|pretend\s+to\s+be)\b"),
    re.compile(r"(?i)\b(decode|decrypt)\s+(and\s+)?(follow|execute|run|do)\b"),
    re.compile(r"```\s*\n"),
    re.compile(r"#{3,}\s*\n"),
]


def scan_output_text(text: str) -> list[dict[str, str]]:
    """
    Lightweight scan of output text (email body, ATS notes) for lifted instructions.

    Returns a list of flagged items with rule_id and matched text.
    """
    flags = []
    for i, pattern in enumerate(OUTPUT_SCANNER_PATTERNS, 1):
        m = pattern.search(text)
        if m:
            flags.append({
                "rule_id": f"OS{i:02d}",
                "matched_text": m.group(0)[:100],
            })
    return flags
