"""
Ollama LLM client with retry logic, timeout handling, and
temperature / context-window configuration optimised for deepseek-r1:7b.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

import ollama

logger = logging.getLogger(__name__)


# ── Default tuning for deepseek-r1:7b ──────────────────────────────────────

_DEFAULT_OPTIONS = {
    "temperature": 0.0,       # near-deterministic for structured output
    "top_p": 0.9,
    "num_predict": 4096,      # leave room for long JSON responses
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
        model: str = "deepseek-r1:7b",
        host: Optional[str] = None,
        max_retries: int = 3,
        retry_delay: float = 2.0,
        timeout_seconds: int = 300,
        options: Optional[dict] = None,
    ) -> None:
        """
        Args:
            model:           Ollama model tag.
            host:            Ollama server URL (default: http://localhost:11434).
            max_retries:     Number of retries on transient failures.
            retry_delay:     Base delay (seconds) between retries (doubles each time).
            timeout_seconds: Per-request timeout for the Ollama server.
            options:         Override default generation options.
        """
        self.model = model
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.timeout_seconds = timeout_seconds

        # Merge caller overrides on top of defaults
        self.options = {**_DEFAULT_OPTIONS, **(options or {})}

        # Build client — only pass host when explicitly set
        client_kwargs = {}
        if host:
            client_kwargs["host"] = host
        self._client = ollama.Client(**client_kwargs)

    # ── Public API ──────────────────────────────────────────────────────

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        """
        Send a chat completion request and return the raw assistant text.

        Args:
            system_prompt: System-level instructions.
            user_prompt:   User-level message (typically the contract code).

        Returns:
            Raw text content of the assistant's reply.

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
                    options=self.options,
                    keep_alive=f"{self.timeout_seconds}s",
                )
                content = response["message"]["content"]
                logger.debug(
                    "LLM response received (attempt %d, %d chars)",
                    attempt,
                    len(content),
                )
                return content

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
