"""
Structured logging setup for Doorman.

Every guardrail decision emits one structured log line:
  {timestamp, stage, rule_id, input_hash, action_attempted, verdict, detail}

This is what makes the "every block traceable to a rule ID" claim real.
"""

import hashlib
import json
import logging
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

import structlog


def _hash_input(text: str, length: int = 16) -> str:
    """Short hash of input text for log traceability without dumping payloads."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:length]


def setup_logging(output_dir: str = "output/logs", verbose: bool = False) -> None:
    """
    Configure structlog to emit JSON-lines to both stdout and a log file.

    Each line is a self-contained JSON object — easy to grep, parse, or
    load into a DataFrame for the evaluation report.
    """
    log_path = Path(output_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    log_file = log_path / "doorman.log"

    # Shared processor chain
    chain = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        # If the log record has an "event_dict" with a "timestamp" key, use it;
        # otherwise add one.
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.UnicodeDecoder(),
    ]

    # Renderer: JSON for file (machine-parseable), human-readable for console
    json_renderer = structlog.processors.JSONRenderer()

    # Console renderer
    if verbose:
        console_renderer = structlog.dev.ConsoleRenderer()
    else:
        console_renderer = json_renderer

    # Configure structlog
    structlog.configure(
        processors=chain + [structlog.processors.EventRenamer("event"), json_renderer],
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        wrapper_class=structlog.BoundLogger,
        cache_logger_on_first_use=True,
    )

    # Also set up a file handler that writes JSON lines
    _setup_file_handler(log_file)


# Keeping it simpler: use stdlib logging + JSON format for the file,
# and structlog for the in-code API.
#

def get_logger(name: str = "doorman") -> structlog.BoundLogger:
    """Get a bound logger for the given module name."""
    return structlog.get_logger(name)


class JsonFileHandler(logging.Handler):
    """logging.Handler that writes JSON-lines to a file."""

    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        # Format: just emit the raw record dict as JSON
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record):
        try:
            # Build a dict from the record
            msg = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
            }
            # Include any structured extra fields
            if hasattr(record, "structured"):
                msg.update(record.structured)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(msg, default=str) + "\n")
        except Exception:
            self.handleError(record)


_file_handler: JsonFileHandler | None = None


def _setup_file_handler(log_file: Path) -> None:
    global _file_handler
    _file_handler = JsonFileHandler(log_file)
    _file_handler.setLevel(logging.DEBUG)


def log_decision(
    logger: structlog.BoundLogger,
    stage: str,
    rule_id: str | None,
    input_hash: str,
    action_attempted: str | None,
    verdict: str,
    detail: str | None = None,
    **extra,
) -> None:
    """
    Emit one structured decision log line.

    Parameters
    ----------
    stage : str
        Pipeline stage, e.g. "ingest", "classify", "score", "scan_output".
    rule_id : str | None
        The fired rule identifier, e.g. "R01", "R05". None if no rule fired.
    input_hash : str
        Short hash of the input that triggered this decision.
    action_attempted : str | None
        Tool / action that was attempted, e.g. "send_email".
    verdict : str
        One of: "blocked", "allowed", "flagged", "passed".
    detail : str | None
        Human-readable explanation.
    **extra
        Any additional fields to include in the log line.
    """
    entry = {
        "stage": stage,
        "rule_id": rule_id,
        "input_hash": input_hash,
        "action_attempted": action_attempted,
        "verdict": verdict,
        "detail": detail or "",
        **extra,
    }
    logger.info("guardrail_decision", **entry)
