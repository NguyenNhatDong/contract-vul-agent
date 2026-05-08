"""
Pydantic models for structured vulnerability analysis output.

These schemas enforce the JSON contract expected by run.py / runzeusvul.py
and validated by the agent after every LLM call.
"""

from typing import List, Optional
from pydantic import BaseModel, Field


class Execution(BaseModel):
    """How the vulnerability manifests during execution."""
    trigger: str = Field(
        ...,
        description="Operation that introduces the vulnerability",
    )
    state_issue: str = Field(
        ...,
        description="Unsafe or incorrect state handling",
    )
    exploitable_behavior: str = Field(
        ...,
        description="How execution flow allows attacker interaction",
    )


class Causality(BaseModel):
    """Root-cause chain from state to exploit outcome."""
    state: str = Field(
        ...,
        description="Relevant state conditions required for exploitation",
    )
    guard: str = Field(
        ...,
        description="Conditions allowing execution (e.g. require, if); 'None' if absent",
    )
    transition: str = Field(
        ...,
        description="Incorrect execution order or logic flaw",
    )
    capability: str = Field(
        ...,
        description="What the attacker can do",
    )
    outcome: str = Field(
        ...,
        description="Result of the exploit",
    )


class Vulnerability(BaseModel):
    """A single detected vulnerability with full evidence chain."""
    vulnerability_type: str = Field(
        ...,
        description="Category from OWASP list or 'Other'",
    )
    evidence: str = Field(
        ...,
        description="Line number or range (e.g. '45' or '45-48')",
    )
    function_name: str = Field(
        default="N/A",
        description="Solidity function name if determinable",
    )
    evidence_snippet: str = Field(
        ...,
        description="Short exact excerpt from code_with_lines",
    )
    execution: Execution
    causality: Causality


class AnalysisResult(BaseModel):
    """Top-level analysis output — may contain zero or more vulnerabilities."""
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list,
        description="List of detected vulnerabilities; empty means contract is normal",
    )
