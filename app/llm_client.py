"""
Ollama LLM client with retry logic, timeout handling, and
temperature / context-window configuration optimised for deepseek-r1:7b.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

import ollama

logger = logging.getLogger(__name__)


# ── Default tuning for deepseek-r1:7b ──────────────────────────────────────

_DEFAULT_OPTIONS = {
    "temperature": 0.0,       # near-deterministic for structured output
    "top_p": 0.9,
    "num_ctx": 8192,          # 8K context: still fits within 8GB VRAM / 16GB RAM
    "num_predict": 8192,      # headroom for separate thinking plus final JSON
    "repeat_penalty": 1.1,    # discourage repetitive output
}


class LLMClient:
    """
    Thin wrapper around ``ollama.chat`` with:
        - configurable model / host
        - automatic retries with exponential back-off
        - request-level timeout via ``keep_alive``
        - consistent option defaults tuned for structured JSON output
    """

    def __init__(
        self,
        model: str = "deepseek-r1:8b",
        host: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        timeout_seconds: int = 300,
        options: Optional[dict] = None,
        response_format: str | dict[str, Any] | None = "json",
        think: bool | str | None = True,
    ) -> None:
        """
        Args:
            model:           Ollama model tag.
            host:            Ollama server URL (default: http://localhost:11434).
            max_retries:     Number of retries on transient failures.
            retry_delay:     Base delay (seconds) between retries (doubles each time).
            timeout_seconds: Per-request timeout for the Ollama server.
            options:         Override default generation options.
            response_format: Ollama response format. Use "json" for structured output.
            think:           Controls separate thinking for supported Ollama models.
        """
        self.model = model
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout_seconds = timeout_seconds
        self.response_format = response_format
        self.think = think

        # Merge caller overrides on top of defaults
        self.options = {**_DEFAULT_OPTIONS, **(options or {})}

        # Build client — only pass host when explicitly set
        client_kwargs = {}
        if host:
            client_kwargs["host"] = host
        self._client = ollama.Client(**client_kwargs)

    # ── Public API ──────────────────────────────────────────────────────

    def generate(self, system_prompt: str, user_prompt: str) -> tuple[str, Optional[str]]:
        """
        Send a chat completion request and return the raw assistant text and thinking process.

        Args:
            system_prompt: System-level instructions.
            user_prompt:   User-level message (typically the contract code).

        Returns:
            Tuple of (raw text content, thinking process if available).

        Raises:
            RuntimeError: After all retries are exhausted.
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                response = self._client.chat(
                    model=self.model,
                    messages=messages,
                    think=self.think,
                    format=self.response_format,
                    options=self.options,
                    keep_alive=f"{self.timeout_seconds}s",
                )
                
                msg = getattr(response, "message", None) or response.get("message", {})
                content = getattr(msg, "content", None)
                if content is None:
                    content = msg.get("content", "")
                    
                thinking = getattr(msg, "thinking", None)
                if thinking is None and isinstance(msg, dict):
                    thinking = msg.get("thinking")

                logger.debug(
                    "LLM response received (attempt %d, %d chars)",
                    attempt,
                    len(content),
                )
                return content, thinking

            except Exception as exc:
                last_error = exc
                wait = self.retry_delay * (2 ** (attempt - 1))
                logger.warning(
                    "Ollama request failed (attempt %d/%d): %s  — retrying in %.1fs",
                    attempt,
                    self.max_retries,
                    exc,
                    wait,
                )
                time.sleep(wait)

        raise RuntimeError(
            f"LLM call failed after {self.max_retries} retries: {last_error}"
        )
