"""
CLI entry point for running smart contract vulnerability analysis.

Can be invoked as::

    python -m app                        # analyse contracts/ (default)
    python -m app --contracts-dir zeus_vulnerable_contracts --output-dir zeus_results
    python -m app --model deepseek-r1:7b --max-files 5
"""

import argparse
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.agent import SmartContractVulnAgent
from app.chunker import chunk_whole_file


def load_categories(path: str) -> List[str]:
    """Load OWASP vulnerability categories from config file."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip()]


def format_code_with_lines(sol_text: str) -> str:
    """Format Solidity code by adding line numbers."""
    return chunk_whole_file(sol_text).code_with_lines


def analyze_contract(
    contract_path: Path,
    agent: SmartContractVulnAgent,
) -> Dict[str, Any]:
    """Analyze a single contract and return a result dict."""
    contract_name = contract_path.name
    try:
        sol_text = contract_path.read_text(encoding="utf-8")
        code_with_lines = format_code_with_lines(sol_text)

        start = time.perf_counter()
        result = agent.analyze(code_with_lines)
        elapsed = time.perf_counter() - start

        vulns = []
        if result.vulnerabilities:
            for v in result.vulnerabilities:
                vulns.append({
                    "vulnerability_type": v.vulnerability_type,
                    "evidence": v.evidence,
                    "function_name": v.function_name,
                    "evidence_snippet": v.evidence_snippet,
                    "execution": {
                        "trigger": v.execution.trigger,
                        "state_issue": v.execution.state_issue,
                        "exploitable_behavior": v.execution.exploitable_behavior,
                    },
                    "causality": {
                        "state": v.causality.state,
                        "guard": v.causality.guard,
                        "transition": v.causality.transition,
                        "capability": v.causality.capability,
                        "outcome": v.causality.outcome,
                    },
                })

        return {
            "contract_name": contract_name,
            "contract_path": str(contract_path),
            "status": "Normal" if not vulns else "Vulnerable",
            "vulnerabilities_count": len(vulns),
            "vulnerabilities": vulns,
            "analysis_time_seconds": round(elapsed, 2),
            "timestamp": datetime.now().isoformat(),
            "error": None,
        }
    except Exception as e:
        return {
            "contract_name": contract_name,
            "contract_path": str(contract_path),
            "status": "Error",
            "vulnerabilities_count": 0,
            "vulnerabilities": [],
            "analysis_time_seconds": 0,
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
        }


def run_audit(
    contracts_dir: Path = Path("contracts"),
    config_path: str = "config/owasp_2023_categories.txt",
    prompt_path: str = "prompts/detect_vuln_prompt.txt",
    model: str = "deepseek-r1:7b",
    output_dir: Path = Path("my_results"),
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    """Run vulnerability audit on all .sol files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    owasp_categories = load_categories(config_path)

    agent = SmartContractVulnAgent(
        model=model,
        prompt_path=prompt_path,
        owasp_categories=owasp_categories,
    )

    sol_files = sorted(contracts_dir.glob("**/*.sol"))
    if max_files:
        sol_files = sol_files[:max_files]

    if not sol_files:
        print(f"No .sol files found in {contracts_dir}")
        return {}

    print(f"\nSmart Contract Vulnerability Audit")
    print(f"{'=' * 60}")
    print(f"Model: {model}")
    print(f"Categories: {len(owasp_categories)}")
    print(f"Contracts: {len(sol_files)}")
    print(f"Output: {output_dir}")
    print(f"{'=' * 60}\n")

    results = []
    audit_start = time.perf_counter()

    for idx, path in enumerate(sol_files, 1):
        print(f"[{idx}/{len(sol_files)}] {path.name}...", end=" ", flush=True)
        result = analyze_contract(path, agent)
        results.append(result)

        out_file = output_dir / f"result_{path.stem}.json"
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        if result["error"]:
            print(f"ERROR: {result['error']}")
        else:
            icon = "VULN" if result["status"] == "Vulnerable" else "OK"
            print(f"{icon} ({result['analysis_time_seconds']}s, {result['vulnerabilities_count']} vulns)")

    total_time = time.perf_counter() - audit_start
    successful = [r for r in results if r["error"] is None]
    vulnerable = [r for r in successful if r["status"] == "Vulnerable"]

    summary = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "total_time_seconds": round(total_time, 2),
        },
        "summary": {
            "total_contracts": len(sol_files),
            "successful": len(successful),
            "failed": len(results) - len(successful),
            "vulnerable": len(vulnerable),
            "safe": len(successful) - len(vulnerable),
        },
    }

    summary_file = output_dir / "audit_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"\nAudit complete: {len(vulnerable)} vulnerable / {len(sol_files)} total ({total_time:.1f}s)")
    return summary


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Smart contract vulnerability audit")
    parser.add_argument("--contracts-dir", type=Path, default=Path("contracts"))
    parser.add_argument("--config", type=str, default="config/owasp_2023_categories.txt")
    parser.add_argument("--prompt", type=str, default="prompts/detect_vuln_prompt.txt")
    parser.add_argument("--model", type=str, default="deepseek-r1:7b")
    parser.add_argument("--output-dir", type=Path, default=Path("my_results"))
    parser.add_argument("--max-files", type=int, default=None)
    args = parser.parse_args()

    run_audit(
        contracts_dir=args.contracts_dir,
        config_path=args.config,
        prompt_path=args.prompt,
        model=args.model,
        output_dir=args.output_dir,
        max_files=args.max_files,
    )


if __name__ == "__main__":
    main()
