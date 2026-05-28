"""
Smart Contract Vulnerability Analysis Agent.

Orchestrates prompt construction, LLM invocation, JSON extraction,
and Pydantic validation with fallback retries.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import List, Optional

from app.llm_client import LLMClient
from app.json_extract import extract_json
from app.schemas import AnalysisResult

logger = logging.getLogger(__name__)

_MAX_PARSE_RETRIES = 2
_THINK_RE = re.compile(r"<think>(.*?)(?:</think>|$)", re.DOTALL)


class AnalysisParseError(ValueError):
    """Raised when the model response cannot be parsed into AnalysisResult."""

    def __init__(self, message: str, thinking_process: Optional[str] = None) -> None:
        super().__init__(message)
        self.thinking_process = thinking_process


def _extract_thinking(raw: str) -> Optional[str]:
    """Extract DeepSeek-style reasoning, including truncated think blocks."""
    match = _THINK_RE.search(raw or "")
    if not match:
        return None
    thinking = match.group(1).strip()
    return thinking or None


class SmartContractVulnAgent:
    """
    Analyse a Solidity contract for vulnerabilities.

    Used by run.py and runzeusvul.py as::

        agent = SmartContractVulnAgent(model, prompt_path, owasp_categories)
        result = agent.analyze(code_with_lines)
    """

    def __init__(
        self,
        model: str = "deepseek-r1:8b",
        prompt_path: str = "prompts/detect_vuln_prompt.txt",
        owasp_categories: Optional[List[str]] = None,
        host: Optional[str] = None,
        llm_options: Optional[dict] = None,
    ) -> None:
        self.model = model
        self.owasp_categories = owasp_categories or []
        self._prompt_template = Path(prompt_path).read_text(encoding="utf-8")
        self._vuln_list_str = ", ".join(self.owasp_categories)
        self._llm = LLMClient(model=model, host=host, options=llm_options)

    def analyze(self, code_with_lines: str) -> AnalysisResult:
        """Analyze code and return validated AnalysisResult."""
        system_prompt = self._build_system_prompt(code_with_lines)
        last_error: Optional[Exception] = None
        last_thinking_process: Optional[str] = None

        for attempt in range(1, _MAX_PARSE_RETRIES + 2):
            raw, native_thinking = self._llm.generate(
                system_prompt,
                "Analyze the provided code_with_lines and return valid JSON only.",
            )
            logger.debug("LLM response attempt %d: %s…", attempt, raw[:300])

            thinking_process = native_thinking or _extract_thinking(raw)
            if thinking_process:
                last_thinking_process = thinking_process

            parsed = extract_json(raw)
            if parsed is None:
                last_error = ValueError(f"No JSON found (attempt {attempt})")
                logger.warning("%s", last_error)
                continue

            if thinking_process and isinstance(parsed, dict):
                parsed["thinking_process"] = thinking_process

            try:
                return AnalysisResult.model_validate(parsed)
            except Exception as exc:
                last_error = exc
                logger.warning("Validation failed (attempt %d): %s", attempt, exc)

        logger.error("Parse failed after %d attempts: %s", _MAX_PARSE_RETRIES + 1, last_error)
        raise AnalysisParseError(
            f"Model response could not be parsed as valid analysis JSON: {last_error}",
            thinking_process=last_thinking_process,
        )

    def _build_system_prompt(self, code_with_lines: str) -> str:
        """Replace template placeholders with actual values."""
        prompt = self._prompt_template
        prompt = prompt.replace("<INSERT SOURCE CODE HERE>", code_with_lines)
        prompt = prompt.replace("<VULNERABILITY_LIST>", self._vuln_list_str)
        return prompt
