from typing import List
from pydantic import BaseModel, Field

class Execution(BaseModel):
    trigger: str
    state_issue: str
    exploitable_behavior: str

class Causality(BaseModel):
    state: str
    guard: str
    transition: str
    capability: str
    outcome: str

class Vulnerability(BaseModel):
    vulnerability_type: str
    evidence: str
    execution: Execution
    causality: Causality

class DetectionOutput(BaseModel):
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)