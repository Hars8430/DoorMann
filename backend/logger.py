"""Structured logging.

Ship-gate requirement: every block must be traceable to a rule in the log.
So every LogEntry carries stage, rule_id (nullable only for a clean ALLOW),
verdict, and a content hash instead of the raw candidate content (don't log PII).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .models import LogEntry, Stage, Verdict


def content_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


class DecisionLog:
    """In-memory + optionally file-backed structured log for one pipeline run."""

    def __init__(self, sink_path: Optional[Path] = None):
        self.entries: list[LogEntry] = []
        self.sink_path = sink_path

    def record(
        self,
        stage: Stage,
        verdict: Verdict,
        detail: str,
        input_text: str,
        rule_id: Optional[str] = None,
        action_attempted: Optional[str] = None,
    ) -> LogEntry:
        entry = LogEntry(
            stage=stage,
            rule_id=rule_id,
            verdict=verdict,
            detail=detail,
            timestamp=datetime.now(timezone.utc).isoformat(),
            input_hash=content_hash(input_text),
            action_attempted=action_attempted,
        )
        self.entries.append(entry)
        if self.sink_path:
            with open(self.sink_path, "a") as f:
                f.write(entry.model_dump_json() + "\n")
        return entry

    def as_json(self) -> str:
        return json.dumps([e.model_dump(mode="json") for e in self.entries], indent=2)
