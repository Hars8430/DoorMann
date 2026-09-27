"""
Litellm-backed LLM client for Doorman.

Uses litellm to unify access to different LLM backends (Ollama, OpenAI-compatible,
etc.) through a single interface. Litellm handles the HTTP protocol translation.

This is the RECOMMENDED client because it's actively maintained and supports
many backends without custom code.
"""

from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import litellm
from litellm import completion

from pipeline_state import PipelineState

logger = logging.getLogger("doorman.llm.litellm_client")


@dataclass
class LlmRequest:
    """Input to the LLM for a single turn."""
    system_prompt: str
    user_content: str


@dataclass
class LlmResponse:
    """Output from the LLM."""
    content: str = ""
    raw_response: dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    status: str = "ok"  # "ok", "error", "mocked"
    model: str = ""


class LitellmClient:
    """
    LLM client backed by litellm.

    Supports:
    - Ollama (local LLMs, free, no API key)
    - OpenAI-compatible endpoints (any provider with OpenAI-compatible API)
    - LiteLLM proxy (if you're using one)

    Configuration is read from the pipeline config dict.
    """

    def __init__(self, config: dict[str, Any]):
        self.config = config
        self._client = None

        pipeline_cfg = config.get("pipeline", {})
        self.backend = pipeline_cfg.get("llm_backend", "ollama")
        self.model = pipeline_cfg.get("llm_model", "llama3.1")
        self.base_url = pipeline_cfg.get("llm_base_url", "http://localhost:11434/v1")
        self.api_key = pipeline_cfg.get("llm_api_key")  # optional
        self.temperature = pipeline_cfg.get("temperature", 0.1)
        self.max_tokens = pipeline_cfg.get("max_tokens", 1024)
        self.mock_mode = config.get("pipeline", {}).get("mock_mode", False)

        logger.info(
            "LitellmClient.init: backend=%s model=%s base_url=%s mock_mode=%s",
            self.backend,
            self.model,
            self.base_url,
            self.mock_mode,
        )

    def _build_litellm_params(self) -> dict[str, Any]:
        """Build the litellm completion() parameters for the current config."""
        params: dict[str, Any] = {
            "model": self._model_string(),
            "messages": [],  # filled per-call
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
            "top_p": 0.9,
        }

        # Add backend-specific params
        if self.backend == "ollama":
            params["api_base"] = self.base_url
            # Ollama doesn't need an API key usually
            if self.api_key:
                params["api_key"] = self.api_key
        elif self.backend == "openai-compatible":
            params["api_base"] = self.base_url
            if self.api_key:
                params["api_key"] = self.api_key

        return params

    def _model_string(self) -> str:
        """Return the model identifier string for litellm."""
        if self.backend == "ollama":
            return f"ollama/{self.model}"
        elif self.backend == "openai-compatible":
            return self.model
        else:
            return self.model

    def call(self, request: LlmRequest, state: PipelineState | None = None) -> LlmResponse:
        """
        Call the LLM with the given request.

        Parameters
        ----------
        request : LlmRequest
            The system prompt and user content.
        state : PipelineState, optional
            The current pipeline state (for logging).

        Returns
        -------
        LlmResponse
            The LLM's response.
        """
        if self.mock_mode:
            return self._mock_response(request, state)

        messages = [
            {"role": "system", "content": request.system_prompt},
            {"role": "user", "content": request.user_content},
        ]

        params = self._build_litellm_params()
        params["messages"] = messages

        start = time.perf_counter()

        try:
            response = completion(**params)

            elapsed_ms = (time.perf_counter() - start) * 1000

            # Parse the response
            choice = response.get("choices", [{}])[0] if response else {}
            message = choice.get("message", {}) if choice else {}
            content = message.get("content", "") or ""

            usage = response.get("usage", {}) if response else {}
            input_tokens = int(usage.get("prompt_tokens", 0) or 0)
            output_tokens = int(usage.get("completion_tokens", 0) or 0)

            return LlmResponse(
                content=content,
                raw_response=response if isinstance(response, dict) else {},
                latency_ms=elapsed_ms,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                status="ok",
                model=self.model,
            )
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.error(
                "LitellmClient.call ERROR: %s (backend=%s, model=%s, base_url=%s)",
                str(e),
                self.backend,
                self.model,
                self.base_url,
            )

            return LlmResponse(
                content="",
                raw_response={"error": str(e)},
                latency_ms=elapsed_ms,
                input_tokens=0,
                output_tokens=0,
                status="error",
                model=self.model,
            )

    def _mock_response(self, request: LlmRequest, state: PipelineState | None = None) -> LlmResponse:
        """
        Return a mocked LLM response for demo/eval purposes.

        The mock response is deterministic and designed to:
        1. Score candidates reasonably based on keyword presence
        2. Generate a plausible evidence summary
        3. NOT contain injection patterns
        4. Be fast (no actual LLM call)
        """
        user_content = request.user_content

        # Determine score based on keywords
        text_lower = user_content.lower()

        has_python = "python" in text_lower or "py" in text_lower
        has_cloud = "aws" in text_lower or "gcp" in text_lower or "azure" in text_lower or "cloud" in text_lower
        has_kubernetes = "kubernetes" in text_lower or "k8s" in text_lower
        has_leadership = "lead" in text_lower or "leadership" in text_lower or "manager" in text_lower or "team" in text_lower
        has_degree = "bs" in text_lower or "ms" in text_lower or "degree" in text_lower or "university" in text_lower or "computer science" in text_lower

        # Simple scoring heuristic
        score = 5.0  # baseline

        if has_python:
            score += 1.5
        if has_cloud:
            score += 1.0
        if has_kubernetes:
            score += 1.0
        if has_leadership:
            score += 0.5
        if has_degree:
            score += 0.5

        # Cap at 9.5/10 for mock (never perfect)
        score = min(score, 9.5)

        # Category
        if score >= 8.0:
            category = "strong"
        elif score >= 6.0:
            category = "qualified"
        elif score >= 4.0:
            category = "borderline"
        else:
            category = "weak"

        # Evidence summary
        strengths = []
        weaknesses = []

        if has_python:
            strengths.append("Strong Python experience")
        else:
            weaknesses.append("No Python experience mentioned")

        if has_cloud:
            strengths.append("Cloud infrastructure experience")
        else:
            weaknesses.append("No cloud experience mentioned")

        if has_kubernetes:
            strengths.append("Kubernetes/container orchestration experience")
        if has_leadership:
            strengths.append("Leadership/mentoring experience")
        if has_degree:
            strengths.append(f"Computer science degree")

        evidence = "Candidate shows relevant experience for the role. " + (
            "; ".join(strengths) if strengths else "Limited relevant experience demonstrated."
        )

        # Suggested questions
        questions = [
            "Can you describe a challenging technical problem you solved recently?",
            "What is your experience with production deployments?",
        ]
        if has_leadership:
            questions.append("Tell me about a time you led a technical initiative.")

        # Build the response
        import json

        response_obj = {
            "overall_score": score,
            "category": category,
            "flagged": False,
            "strengths": strengths,
            "weaknesses": weaknesses,
            "evidence_summary": evidence,
            "suggested_questions": questions,
        }

        # The scoring stage expects a structured response with fields it can parse.
        # We return a JSON-like string that includes the structured data.
        structured = (
            f"## SCORE\n{score}/10\n\n"
            f"## CATEGORY\n{category}\n\n"
            f"## EVIDENCE\n{evidence}\n\n"
            f"## STRENGTHS\n" + "\n".join(f"- {s}" for s in strengths) + "\n\n"
            f"## WEAKNESSES\n" + ("\n".join(f"- {w}" for w in weaknesses) if weaknesses else "None identified.\n") + "\n\n"
            f"## QUESTIONS\n" + "\n".join(f"1. {q}" for q in questions) + "\n\n"
            f"## JSON\n{json.dumps(response_obj, indent=2)}\n"
        )

        latency_ms = 50.0  # mock latency

        logger.debug(
            "LitellmClient._mock_response: score=%s category=%s (mock mode)",
            score,
            category,
        )

        return LlmResponse(
            content=structured,
            raw_response={"mock": True, "score": score, "category": category},
            latency_ms=latency_ms,
            input_tokens=0,
            output_tokens=0,
            status="mocked",
            model=self.model,
        )

    def close(self):
        """Clean up resources."""
        pass


def create_client(config: dict[str, Any]) -> LitellmClient:
    """Factory function to create a LitellmClient from config."""
    return LitellmClient(config)
