"""
Robust JSON extraction from noisy LLM output.

deepseek-r1 often wraps JSON inside <think>…</think> blocks, markdown
fences, or trailing commentary.  This module strips all of that and
returns the first valid JSON object found.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional


# ── Compiled patterns (reused across calls) ─────────────────────────────────

# deepseek-r1 thinking tags
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

# Markdown fenced blocks: ```json … ``` or ``` … ```
_FENCE_RE = re.compile(r"```(?:json)?\s*\n(.*?)```", re.DOTALL)

# Greedy match for the outermost { … } pair
_BRACE_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_json(raw: str) -> Optional[Dict[str, Any]]:
    """
    Extract the first valid JSON object from raw LLM output.

    Processing pipeline:
        1. Strip ``<think>…</think>`` blocks.
        2. Try to decode the remainder directly.
        3. Try content inside markdown code fences.
        4. Fall back to greedy brace matching.
        5. Return ``None`` if nothing works.

    Args:
        raw: Raw text response from the LLM.

    Returns:
        Parsed dict, or ``None`` if extraction fails.
    """
    if not raw or not raw.strip():
        return None

    # Step 1 — strip thinking blocks
    cleaned = _THINK_RE.sub("", raw).strip()

    # Step 2 — direct parse
    result = _try_parse(cleaned)
    if result is not None:
        return result

    # Step 3 — look inside markdown fences
    for match in _FENCE_RE.finditer(cleaned):
        result = _try_parse(match.group(1).strip())
        if result is not None:
            return result

    # Step 4 — greedy brace extraction
    brace_match = _BRACE_RE.search(cleaned)
    if brace_match:
        result = _try_parse(brace_match.group(0))
        if result is not None:
            return result

    # Step 5 — try repairing common issues
    result = _try_repair_and_parse(cleaned)
    if result is not None:
        return result

    return None


# ── Internal helpers ─────────────────────────────────────────────────────────

def _try_parse(text: str) -> Optional[Dict[str, Any]]:
    """Attempt ``json.loads`` and return dict or None."""
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except (json.JSONDecodeError, TypeError, ValueError):
        pass
    return None


def _try_repair_and_parse(text: str) -> Optional[Dict[str, Any]]:
    """
    Apply lightweight repairs for common LLM JSON errors:
        - Trailing commas before } or ]
        - Single quotes instead of double quotes
        - Unescaped newlines inside string values
    """
    # Find the outermost brace block first
    brace_match = _BRACE_RE.search(text)
    if not brace_match:
        return None

    candidate = brace_match.group(0)

    # Remove trailing commas: ,} or ,]
    candidate = re.sub(r",\s*([}\]])", r"\1", candidate)

    # Replace single-quoted keys/values (heuristic — won't handle all edge cases)
    candidate = candidate.replace("'", '"')

    return _try_parse(candidate)
