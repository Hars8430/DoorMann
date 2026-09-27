"""
Config loader -- reads settings.yaml and provides a typed config dict.

Usage:
    config = load_config()  # reads config/settings.yaml
    # config['pipeline']['llm_model'] -> "llama3.1"
    # config['guard']['classifier']['hf_threshold'] -> 0.5
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger("doorman.config")


DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "settings.yaml"


def load_config(path: Path | str | None = None) -> dict[str, Any]:
    """
    Load the pipeline configuration from a YAML file.

    Parameters
    ----------
    path : Path | str | None
        Path to the config file. Defaults to config/settings.yaml.

    Returns
    -------
    dict
        Configuration dictionary.
    """
    if path is None:
        path = DEFAULT_CONFIG_PATH
    elif isinstance(path, str):
        path = Path(path)

    if not path.exists():
        logger.warning("Config file not found at %s -- using defaults", path)
        return _default_config()

    try:
        with open(path, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}
        logger.info("Config loaded from %s", path)
        return config
    except Exception as e:
        logger.error("Failed to load config from %s: %s", path, e)
        return _default_config()


def _default_config() -> dict[str, Any]:
    """Return a minimal default configuration."""
    return {
        "pipeline": {
            "llm_backend": "ollama",
            "llm_model": "llama3.1",
            "llm_base_url": "http://localhost:11434/v1",
            "temperature": 0.1,
            "max_tokens": 1024,
            "score_stage_allowed_tools": ["score", "flag_for_review"],
            "action_stage_allowed_tools": ["send_email", "write_ats", "flag_for_review"],
        },
        "ingestion": {
            "extract_hidden_text": True,
        },
        "guard": {
            "classifier": {
                "use_hf_model": True,
                "hf_model_name": "protectai/deberta-v3-base-prompt-injection-v2",
                "hf_threshold": 0.5,
                "use_heuristics": True,
                "use_llm_judge": True,
                "ensemble_policy": "any",
            },
            "isolation": {
                "fence_tag": "candidate_document",
                "framing": True,
            },
            "output_scanner": {
                "scan_email_body": True,
                "scan_score_evidence": True,
                "scan_ats_bypass": True,
            },
        },
        "evaluation": {
            "corpus_file": "corpus/corpus.yaml",
            "benign_file": "corpus/benign_resumes.yaml",
            "output_dir": "output",
            "log_dir": "output/logs",
            "random_seed": 42,
        },
    }
