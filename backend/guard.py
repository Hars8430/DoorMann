"""Input guard / classifier.

Two backends, picked by config:

  - HeuristicGuard   : rule-based, offline, zero dependencies beyond stdlib.
                       This is the default so the whole project runs with no
                       API keys and no model download.
  - HFModelGuard     : wraps a HuggingFace prompt-injection classifier
                       (e.g. protectai/deberta-v3-base-prompt-injection-v2).
                       Requires `transformers` + a one-time model download,
                       so it's opt-in via DOORMAN_GUARD_BACKEND=hf.

Both implement `.score(document) -> GuardResult`. The pipeline talks to the
interface, not the implementation — swapping backends is a one-line config
change, not a pipeline rewrite. In production you'd run both and ensemble
the verdicts; `EnsembleGuard` below does exactly that.

IMPORTANT: filtering the literal phrase "ignore previous instructions" is
theater — it's one rule out of many here, and a weak one. It's included so
the eval can show *specifically* how little it buys you (see eval/run_eval.py,
family "direct_override" is the easiest family to catch; the others are why
the rest of this file exists).
"""
from __future__ import annotations

import math
import re
from abc import ABC, abstractmethod

from .models import Document, GuardResult, RuleHit, Verdict

# ---------------------------------------------------------------------------
# Rule definitions. Each rule is independently traceable in the logs by ID.
# ---------------------------------------------------------------------------

_OVERRIDE_PATTERNS = re.compile(
    r"(ignore|disregard|forget)\s+(the\s+)?(above|previous|prior|earlier)\s+"
    r"(instructions?|prompt|context)"
    r"|new\s+instructions?\s*:"
    r"|^\s*system\s*:"
    r"|you\s+are\s+now\s+(a|the)\b",
    re.IGNORECASE | re.MULTILINE,
)

_PERSONA_HIJACK = re.compile(
    r"\b(act\s+as|pretend\s+(you\s+are|to\s+be)|roleplay\s+as|from\s+now\s+on\s+you)\b",
    re.IGNORECASE,
)

_SCORE_MANIPULATION = re.compile(
    r"\b(give|assign|set)\b.{0,20}\b(10/10|perfect|maximum|highest possible)\b"
    r"|\bmust\s+(be\s+)?(hired|scored|rated)\b"
    r"|\brate\s+this\s+candidate\s+10\b"
    r"|\bperfect\s+(fit|candidate|score)\b",
    re.IGNORECASE,
)

_TOOL_NAMING = re.compile(
    r"\b(call|invoke|trigger|run)\b.{0,15}\b(send_email|write_ats|update_status|score\()\b"
    r"|\bset\s+(the\s+)?status\s+to\s+['\"]?hired['\"]?"
    r"|\bsend\s+an?\s+email\s+(to|saying|with)\b",
    re.IGNORECASE,
)

_DECODE_LURE = re.compile(
    r"\bdecode\s+(this|the\s+following|and\s+follow)\b|\bbase64\b.{0,30}\b(decode|execute|follow)\b",
    re.IGNORECASE,
)

_INSTRUCTIONAL_META = re.compile(
    r"\b(instructions?|ignore|system prompt|you are|rate|score)\b", re.IGNORECASE
)

_SUSPICIOUS_URL = re.compile(
    r"https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|bit\.ly|tinyurl\.com|[a-z0-9]{16,}\.\w+)",
    re.IGNORECASE,
)


# --- homoglyph normalization -----------------------------------------------
# Found during red-teaming (see eval/bypass_case_study.py): swapping a
# handful of Latin letters in a trigger phrase for Cyrillic/Greek lookalikes
# ("Ignоre previous instructions" with a Cyrillic о) drops the homoglyph
# ratio below the 5% detection threshold while still reading as plain
# English to a human — and to any regex expecting literal ASCII. The fix is
# to normalize confusable characters back to Latin *before* running the
# phrase-matching rules, while still measuring the ratio against the
# original text so the obfuscation itself stays a separate detectable signal.
_HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ѕ": "s", "ј": "j", "ԁ": "d", "ɡ": "g", "ա": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "ı": "i", "ℓ": "l",
})


def normalize_homoglyphs(text: str) -> str:
    return text.translate(_HOMOGLYPH_MAP)


def _homoglyph_ratio(text: str) -> float:
    """Rough proxy for lookalike-unicode obfuscation: share of letters outside
    basic ASCII + common Latin-1 in an otherwise-Latin-script document."""
    letters = [c for c in text if c.isalpha()]
    if len(letters) < 20:
        return 0.0
    odd = sum(1 for c in letters if ord(c) > 0x24F and ord(c) not in range(0x2018, 0x2020))
    return odd / len(letters)


class Guard(ABC):
    @abstractmethod
    def score(self, document: Document) -> GuardResult: ...


class HeuristicGuard(Guard):
    """Rule-based guard. Every hit is a named, independently-auditable rule —
    this is what makes 'traceable to a rule in the log' possible."""

    def score(self, document: Document) -> GuardResult:
        hits: list[RuleHit] = []
        # phrase-matching runs on the normalized text (catches homoglyph
        # evasion); the ratio check runs on the raw text (that's what
        # measures the evasion attempt itself).
        raw_text = document.visible_text
        text = normalize_homoglyphs(raw_text)

        # Structural signal first: hidden content existing at all is the
        # single strongest tell in this whole system. A legitimate resume
        # has zero reason to contain white-on-white or off-page text.
        if document.hidden_spans:
            reasons = sorted({s.reason for s in document.hidden_spans})
            hits.append(
                RuleHit(
                    rule_id="INJ-002-HIDDEN-CONTENT",
                    family="structural",
                    detail=f"{len(document.hidden_spans)} hidden span(s): {', '.join(reasons)}",
                )
            )
            # and scan what the hidden text actually says
            hidden_blob = normalize_homoglyphs(" ".join(s.text for s in document.hidden_spans))
            if _OVERRIDE_PATTERNS.search(hidden_blob) or _SCORE_MANIPULATION.search(hidden_blob):
                hits.append(
                    RuleHit(
                        rule_id="INJ-002B-HIDDEN-PAYLOAD",
                        family="structural",
                        detail="hidden text contains override/scoring-manipulation language",
                    )
                )

        if _OVERRIDE_PATTERNS.search(text):
            hits.append(RuleHit(rule_id="INJ-001-DIRECT-OVERRIDE", family="direct_override",
                                 detail="visible text contains an instruction-override phrase"))

        if _PERSONA_HIJACK.search(text):
            hits.append(RuleHit(rule_id="INJ-008-PERSONA-HIJACK", family="direct_override",
                                 detail="visible text attempts to reassign the model's role"))

        if _SCORE_MANIPULATION.search(text):
            hits.append(RuleHit(rule_id="INJ-005-SCORE-MANIPULATION", family="structured_field",
                                 detail="text explicitly demands a maximal/forced score"))

        if _TOOL_NAMING.search(text):
            hits.append(RuleHit(rule_id="INJ-010-TOOL-NAMING", family="direct_override",
                                 detail="text names or invokes a downstream tool directly"))

        if _DECODE_LURE.search(text):
            hits.append(RuleHit(rule_id="INJ-004-DECODE-LURE", family="encoding",
                                 detail="text asks the reader to decode and follow an encoded payload"))

        ratio = _homoglyph_ratio(raw_text)
        if ratio > 0.05:
            hits.append(RuleHit(rule_id="INJ-009-HOMOGLYPH", family="encoding",
                                 detail=f"{ratio:.0%} of letters are non-standard Unicode lookalikes"))

        for field, value in document.metadata_text.items():
            if _INSTRUCTIONAL_META.search(normalize_homoglyphs(value)):
                hits.append(RuleHit(rule_id="INJ-003-METADATA-INJECTION", family="metadata",
                                     detail=f"PDF metadata field '{field}' contains instructional language"))

        for url in document.linked_urls:
            if _SUSPICIOUS_URL.search(url):
                hits.append(RuleHit(rule_id="INJ-007-SUSPICIOUS-LINK", family="tool_result",
                                     detail=f"linked URL uses a suspicious/obscured host: {url}"))

        score = 1 - math.exp(-0.55 * len(hits))  # saturating combine, diminishing per extra hit
        if score >= 0.7:
            verdict = Verdict.DENY
        elif score >= 0.3:
            verdict = Verdict.HOLD
        else:
            verdict = Verdict.ALLOW

        return GuardResult(verdict=verdict, score=round(score, 3), hits=hits)


class HFModelGuard(Guard):
    """Wraps a HuggingFace sequence-classification prompt-injection model.
    Opt-in — requires `pip install transformers torch` and a model download,
    so it's not the default. See README for enabling it."""

    def __init__(self, model_name: str = "protectai/deberta-v3-base-prompt-injection-v2"):
        from transformers import pipeline  # local import: optional dependency

        self._clf = pipeline("text-classification", model=model_name, truncation=True)

    def score(self, document: Document) -> GuardResult:
        result = self._clf(document.visible_text[:2000])[0]
        label, prob = result["label"], float(result["score"])
        is_injection = label.upper() in {"INJECTION", "LABEL_1"}
        s = prob if is_injection else 1 - prob
        verdict = Verdict.DENY if s >= 0.85 else Verdict.HOLD if s >= 0.5 else Verdict.ALLOW
        hits = [RuleHit(rule_id="INJ-HF-MODEL", family="model", detail=f"{label} ({prob:.2f})")] if is_injection else []
        return GuardResult(verdict=verdict, score=round(s, 3), hits=hits)


class EnsembleGuard(Guard):
    """Runs multiple guards, takes the more severe verdict, unions the hits."""

    def __init__(self, guards: list[Guard]):
        self._guards = guards

    def score(self, document: Document) -> GuardResult:
        results = [g.score(document) for g in self._guards]
        order = {Verdict.ALLOW: 0, Verdict.HOLD: 1, Verdict.DENY: 2}
        worst = max(results, key=lambda r: order[r.verdict])
        all_hits = [h for r in results for h in r.hits]
        return GuardResult(verdict=worst.verdict, score=max(r.score for r in results), hits=all_hits)


def build_default_guard() -> Guard:
    return HeuristicGuard()
