"""
Solidity source-code pre-processing.

Provides line-numbering and (optional) chunking for large contracts
so they fit within the LLM context window.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List


@dataclass
class CodeChunk:
    """A numbered slice of Solidity source code."""

    code_with_lines: str
    """Full source with '1: …\\n2: …' line-number prefix."""

    start_line: int = 1
    """1-based first line number in this chunk."""

    end_line: int = 0
    """1-based last line number in this chunk (inclusive)."""

    total_lines: int = 0
    """Total number of lines in the original file."""


def _add_line_numbers(source: str) -> str:
    """Prefix every line with its 1-based line number."""
    lines = source.splitlines()
    width = len(str(len(lines)))  # dynamic width for alignment
    numbered = [f"{i + 1:>{width}}: {line}" for i, line in enumerate(lines)]
    return "\n".join(numbered)


def chunk_whole_file(source: str) -> CodeChunk:
    """
    Number lines for the entire file and return a single CodeChunk.

    This is the primary entry point used by ``run.py`` and ``runzeusvul.py``::

        from app.chunker import chunk_whole_file
        chunk = chunk_whole_file(sol_text)
        code_with_lines = chunk.code_with_lines
    """
    lines = source.splitlines()
    total = len(lines)
    return CodeChunk(
        code_with_lines=_add_line_numbers(source),
        start_line=1,
        end_line=total,
        total_lines=total,
    )


def chunk_by_lines(
    source: str,
    max_lines: int = 300,
    overlap: int = 20,
) -> List[CodeChunk]:
    """
    Split a large contract into overlapping line-numbered chunks.

    Useful when the contract exceeds the model's context window.

    Args:
        source:    Raw Solidity source text.
        max_lines: Maximum lines per chunk.
        overlap:   Lines of overlap between consecutive chunks for context.

    Returns:
        Ordered list of ``CodeChunk`` objects.
    """
    lines = source.splitlines()
    total = len(lines)

    if total <= max_lines:
        return [chunk_whole_file(source)]

    chunks: List[CodeChunk] = []
    start = 0

    while start < total:
        end = min(start + max_lines, total)
        slice_lines = lines[start:end]

        # Build numbered text for this slice
        width = len(str(total))
        numbered = [
            f"{start + i + 1:>{width}}: {line}"
            for i, line in enumerate(slice_lines)
        ]

        chunks.append(
            CodeChunk(
                code_with_lines="\n".join(numbered),
                start_line=start + 1,
                end_line=end,
                total_lines=total,
            )
        )

        # Advance with overlap
        start = end - overlap if end < total else total

    return chunks
