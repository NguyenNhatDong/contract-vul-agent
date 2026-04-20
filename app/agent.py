import json
from pathlib import Path
from typing import List

from .llm_client import LLMClient
from .json_extract import extract_json_object
from .schemas import DetectionOutput

class SmartContractVulnAgent:
    def __init__(self, model: str, prompt_path: str, owasp_categories: List[str]):
        self.llm = LLMClient(model=model)
        self.prompt_template = Path(prompt_path).read_text(encoding="utf-8")
        self.owasp_categories = [c.strip() for c in owasp_categories if c.strip()]

    def build_prompt(self, code_with_lines: str) -> str:
        vuln_list = self.owasp_categories[:] + ["Other"]
        vuln_list_str = ", ".join([f"\"{x}\"" for x in vuln_list])

        prompt = self.prompt_template
        prompt = prompt.replace("<CODE_WITH_LINES>", code_with_lines)
        prompt = prompt.replace("{<VULNERABILITY_LIST>}", vuln_list_str)
        return prompt

    def analyze(self, code_with_lines: str) -> DetectionOutput:
        prompt = self.build_prompt(code_with_lines)
        raw = self.llm.chat(prompt, temperature=0.2)

        json_str = extract_json_object(raw)
        try:
            return DetectionOutput.model_validate_json(json_str)
        except Exception:
            # Retry: enforce strict JSON
            retry_prompt = (
                "Return ONLY a valid JSON object that matches the required schema.\n"
                "Do not output any other text.\n"
                f"Your previous output was:\n{raw}\n"
            )
            raw2 = self.llm.chat(retry_prompt, temperature=0.0)
            json_str2 = extract_json_object(raw2)
            return DetectionOutput.model_validate_json(json_str2)