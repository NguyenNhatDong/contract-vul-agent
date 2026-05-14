#!/usr/bin/env python3
"""
Automate smart contract vulnerability auditing on Zeus vulnerable contracts.

Processes all Solidity contracts in the zeus_vulnerable_contracts/ directory:
1. Loads vulnerability categories from OWASP 2023 Smart Contract Top 10
2. Formats each contract with line numbers
3. Analyzes each contract for vulnerabilities
4. Saves individual JSON results for each contract with naming: result_<CONTRACT_NAME>.json

Optimizations over run.py:
- Concurrent analysis via ThreadPoolExecutor (configurable workers)
- Skip-existing results to allow resuming interrupted runs
- Progress bar with ETA estimation
- Memory-efficient: streams results to disk immediately
- Fixes typo in default output dir ("my_result  s" -> "zeus_results")
"""

import csv
import json
import time
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

from app.agent import SmartContractVulnAgent


def format_with_line_numbers(source_code: str) -> str:
    """Formats contract source code with line numbers.

    Prepends each line with its 1-based line number so the LLM can
    reference exact locations when reporting vulnerabilities.

    Example::

        1: pragma solidity ^0.8.0;
        2: contract Foo {
        3:     ...
    """
    lines = source_code.splitlines()
    width = len(str(len(lines)))
    return "\n".join(
        f"{i:{width}d}: {line}" for i, line in enumerate(lines, 1)
    )


# ─── Helpers ────────────────────────────────────────────────────────────────

def load_categories(path: str) -> List[str]:
    """Load OWASP vulnerability categories from config file."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip()]


def _format_duration(seconds: float) -> str:
    """Human-readable duration string."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, secs = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {secs}s"


# ─── Single contract analysis ──────────────────────────────────────────────

def analyze_contract(
    contract_path: Path,
    agent: SmartContractVulnAgent,
) -> Dict[str, Any]:
    """
    Analyze a single Solidity contract for vulnerabilities.

    Returns a dict with contract_name, status, vulnerabilities, timing, etc.
    """
    contract_name = contract_path.name

    try:
        sol_text = contract_path.read_text(encoding="utf-8")
        sol_with_lines = format_with_line_numbers(sol_text)

        start_time = time.perf_counter()
        result = agent.analyze(sol_with_lines)
        analysis_time = time.perf_counter() - start_time

        vulnerabilities = []
        if result.vulnerabilities:
            for vuln in result.vulnerabilities:
                vulnerabilities.append({
                    "vulnerability_type": vuln.vulnerability_type,
                    "evidence": vuln.evidence,
                    "function_name": vuln.function_name,
                    "evidence_snippet": vuln.evidence_snippet,
                    "execution": {
                        "trigger": vuln.execution.trigger,
                        "state_issue": vuln.execution.state_issue,
                        "exploitable_behavior": vuln.execution.exploitable_behavior,
                    },
                    "causality": {
                        "state": vuln.causality.state,
                        "guard": vuln.causality.guard,
                        "transition": vuln.causality.transition,
                        "capability": vuln.causality.capability,
                        "outcome": vuln.causality.outcome,
                    },
                })

        status = "Normal" if not vulnerabilities else "Vulnerable"

        return {
            "contract_name": contract_name,
            "contract_path": str(contract_path),
            "status": status,
            "vulnerabilities_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "analysis_time_seconds": round(analysis_time, 2),
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


# ─── Audit orchestrator ────────────────────────────────────────────────────

def _result_filename(contract_path: Path) -> str:
    """Derive the result JSON filename for a given contract."""
    return f"result_{contract_path.stem}.json"


def run_audit(
    contracts_dir: Path = Path("zeus_vulnerable_contracts"),
    config_path: str = "config/owasp_2023_categories.txt",
    prompt_path: str = "prompts/detect_vuln_prompt.txt",
    model: str = "deepseek-r1:7b",
    output_dir: Path = Path("zeus_results"),
    max_files: Optional[int] = None,
    workers: int = 1,
    skip_existing: bool = True,
) -> Dict[str, Any]:
    """
    Run vulnerability audit on all .sol files in zeus_vulnerable_contracts/.

    Args:
        contracts_dir:  Directory containing .sol files
        config_path:    Path to OWASP categories config file
        prompt_path:    Path to system prompt template
        model:          Ollama model to use
        output_dir:     Directory to save individual result files
        max_files:      Limit number of files to analyze (None = all)
        workers:        Number of parallel workers (default 1 = sequential)
        skip_existing:  Skip contracts that already have result files
    """
    # ── Setup ───────────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    owasp_categories = load_categories(config_path)

    # ── Discover contracts ──────────────────────────────────────────────
    sol_files = sorted(contracts_dir.glob("**/*.sol"))
    total_discovered = len(sol_files)

    if not sol_files:
        print(f"❌ No .sol files found in {contracts_dir}")
        return {}

    # ── Filter already-processed contracts ──────────────────────────────
    skipped = 0
    if skip_existing:
        pending = []
        for f in sol_files:
            result_path = output_dir / _result_filename(f)
            if result_path.exists():
                skipped += 1
            else:
                pending.append(f)
        sol_files = pending

    if max_files:
        sol_files = sol_files[:max_files]

    total_to_process = len(sol_files)

    print(f"\n🔐 Zeus Vulnerable Contracts — Vulnerability Audit")
    print(f"{'=' * 60}")
    print(f"Model            : {model}")
    print(f"Categories       : {len(owasp_categories)}")
    print(f"Total discovered : {total_discovered}")
    print(f"Skipped (cached) : {skipped}")
    print(f"To process       : {total_to_process}")
    print(f"Workers          : {workers}")
    print(f"Output directory : {output_dir}")
    print(f"{'=' * 60}")

    if total_to_process == 0:
        print("✅ All contracts already processed. Nothing to do.")
        return _build_summary(output_dir, model, owasp_categories, 0)

    print(f"\n🔍 Starting analysis...\n")

    # ── Create one agent per worker ─────────────────────────────────────
    # Ollama client is thread-safe for separate requests, but we create
    # per-worker agents so prompt templates are not shared mutably.
    def _make_agent() -> SmartContractVulnAgent:
        return SmartContractVulnAgent(
            model=model,
            prompt_path=prompt_path,
            owasp_categories=owasp_categories,
        )

    # ── Progress tracking ───────────────────────────────────────────────
    completed_count = 0
    print_lock = Lock()
    audit_start = time.perf_counter()
    times_list: List[float] = []

    def _process_one(contract_path: Path, agent: SmartContractVulnAgent) -> Dict[str, Any]:
        nonlocal completed_count
        result = analyze_contract(contract_path, agent)

        # Immediately flush result to disk
        result_path = output_dir / _result_filename(contract_path)
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        # Thread-safe progress output
        with print_lock:
            completed_count += 1
            times_list.append(result["analysis_time_seconds"])
            avg = sum(times_list) / len(times_list)
            remaining = (total_to_process - completed_count) * avg / max(workers, 1)
            eta_str = _format_duration(remaining)

            if result["error"]:
                icon = "❌"
                detail = f"ERROR: {result['error'][:80]}"
            else:
                icon = "🚨" if result["status"] == "Vulnerable" else "✓ "
                detail = (
                    f"{result['status']} "
                    f"({result['analysis_time_seconds']}s, "
                    f"{result['vulnerabilities_count']} vulns)"
                )

            print(
                f"[{completed_count}/{total_to_process}] "
                f"{icon} {contract_path.name}  {detail}  "
                f"(ETA: ~{eta_str})"
            )

        return result

    # ── Execute ─────────────────────────────────────────────────────────
    audit_results: List[Dict[str, Any]] = []

    if workers <= 1:
        # Sequential — reuse a single agent
        agent = _make_agent()
        for contract_path in sol_files:
            audit_results.append(_process_one(contract_path, agent))
    else:
        # Parallel — one agent per worker
        agents = [_make_agent() for _ in range(workers)]
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {}
            for idx, contract_path in enumerate(sol_files):
                agent = agents[idx % workers]
                fut = pool.submit(_process_one, contract_path, agent)
                futures[fut] = contract_path

            for fut in as_completed(futures):
                audit_results.append(fut.result())

    total_time = time.perf_counter() - audit_start

    # ── Build & save summary ────────────────────────────────────────────
    summary_report = _build_summary(
        output_dir, model, owasp_categories, total_time
    )

    _print_summary(summary_report, output_dir, total_time)
    return summary_report


def _build_summary(
    output_dir: Path,
    model: str,
    owasp_categories: List[str],
    total_time: float,
) -> Dict[str, Any]:
    """
    Rebuild the summary from all result files on disk.
    This is idempotent and works even for resumed runs.
    """
    result_files = sorted(output_dir.glob("result_*.json"))

    all_results: List[Dict[str, Any]] = []
    for rf in result_files:
        try:
            with open(rf, "r", encoding="utf-8") as f:
                all_results.append(json.load(f))
        except (json.JSONDecodeError, OSError):
            continue

    successful = [r for r in all_results if r.get("error") is None]
    failed = [r for r in all_results if r.get("error") is not None]
    vulnerable = [r for r in successful if r["status"] == "Vulnerable"]
    safe = [r for r in successful if r["status"] == "Normal"]

    total_vulns = sum(r.get("vulnerabilities_count", 0) for r in successful)
    avg_time = (
        sum(r.get("analysis_time_seconds", 0) for r in successful) / len(successful)
        if successful
        else 0
    )

    vuln_types: Dict[str, int] = {}
    for r in successful:
        for vuln in r.get("vulnerabilities", []):
            vt = vuln.get("vulnerability_type", "Unknown")
            vuln_types[vt] = vuln_types.get(vt, 0) + 1

    summary = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "contracts_source": "zeus_vulnerable_contracts",
            "owasp_categories": len(owasp_categories),
            "total_time_seconds": round(total_time, 2),
        },
        "summary": {
            "total_contracts": len(all_results),
            "successful_analyses": len(successful),
            "failed_analyses": len(failed),
            "vulnerable_contracts": len(vulnerable),
            "safe_contracts": len(safe),
            "total_vulnerabilities_found": total_vulns,
            "average_analysis_time_seconds": round(avg_time, 2),
            "vulnerability_types_distribution": vuln_types,
        },
        "contracts_analyzed": [
            {
                "contract_name": r["contract_name"],
                "status": r["status"],
                "vulnerabilities_count": r.get("vulnerabilities_count", 0),
                "analysis_time_seconds": r.get("analysis_time_seconds", 0),
                "result_file": f"result_{Path(r['contract_name']).stem}.json",
            }
            for r in all_results
        ],
    }

    summary_file = output_dir / "audit_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    return summary


def _print_summary(
    summary: Dict[str, Any], output_dir: Path, total_time: float
) -> None:
    """Pretty-print the audit summary to stdout."""
    s = summary["summary"]
    print(f"\n{'=' * 60}")
    print(f"✅ Zeus Audit Complete!")
    print(f"{'=' * 60}")
    print(f"Total contracts analyzed : {s['total_contracts']}")
    print(f"Vulnerable contracts    : {s['vulnerable_contracts']}")
    print(f"Safe contracts          : {s['safe_contracts']}")
    print(f"Failed analyses         : {s['failed_analyses']}")
    print(f"Total vulnerabilities   : {s['total_vulnerabilities_found']}")
    print(f"Avg analysis time       : {s['average_analysis_time_seconds']}s")
    print(f"Total wall time         : {_format_duration(total_time)}")
    print(f"\n📁 Results in : {output_dir}")
    print(f"📋 Summary   : {output_dir / 'audit_summary.json'}")

    vuln_dist = s.get("vulnerability_types_distribution", {})
    if vuln_dist:
        print(f"\nVulnerability Types Found:")
        for vt, count in sorted(vuln_dist.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {vt}: {count}")


# ─── Vulnerability report ───────────────────────────────────────────────────

def generate_vulnerability_report(output_dir: Path = Path("zeus_results")) -> Path:
    """
    Scan all result_*.json files in *output_dir* and produce a consolidated
    vulnerability summary containing a table of:
        file_name | vulnerability_type | evidence

    Outputs:
        - zeus_vulnerability_report.md   (Markdown table)
        - zeus_vulnerability_report.csv  (machine-readable)

    Returns the path to the Markdown report.
    """
    result_files = sorted(output_dir.glob("result_*.json"))
    if not result_files:
        print(f"No result files found in {output_dir}")
        return output_dir / "zeus_vulnerability_report.md"

    # ── Collect rows ────────────────────────────────────────────────────
    rows: List[Dict[str, str]] = []          # each row = one vulnerability
    contracts_total = 0
    contracts_vulnerable = 0
    contracts_safe = 0
    contracts_error = 0

    for rf in result_files:
        try:
            with open(rf, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue

        contracts_total += 1
        file_name = data.get("contract_name", rf.stem)
        status = data.get("status", "Unknown")

        if status == "Error":
            contracts_error += 1
            continue

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            contracts_safe += 1
            # Include a row so the file still appears in the table
            rows.append({
                "file_name": file_name,
                "vulnerability_type": "(none)",
                "evidence": "-",
            })
            continue

        contracts_vulnerable += 1
        for vuln in vulns:
            rows.append({
                "file_name": file_name,
                "vulnerability_type": vuln.get("vulnerability_type", "Unknown"),
                "evidence": vuln.get("evidence", "N/A"),
            })

    # ── Aggregate by vulnerability type ─────────────────────────────────
    vuln_type_counts: Dict[str, int] = {}
    for row in rows:
        vt = row["vulnerability_type"]
        if vt != "(none)":
            vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1

    # ── Write Markdown report ───────────────────────────────────────────
    md_path = output_dir / "zeus_vulnerability_report.md"
    lines: List[str] = []
    lines.append("# Zeus Vulnerable Contracts — Vulnerability Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total contracts scanned | {contracts_total} |")
    lines.append(f"| Vulnerable contracts    | {contracts_vulnerable} |")
    lines.append(f"| Safe contracts          | {contracts_safe} |")
    lines.append(f"| Errored contracts       | {contracts_error} |")
    lines.append(f"| Total vulnerabilities   | {sum(vuln_type_counts.values())} |")
    lines.append("")

    if vuln_type_counts:
        lines.append("## Vulnerability Type Distribution")
        lines.append("")
        lines.append("| Vulnerability Type | Count |")
        lines.append("|-------------------|-------|")
        for vt, count in sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True):
            lines.append(f"| {vt} | {count} |")
        lines.append("")

    lines.append("## Detailed Findings")
    lines.append("")
    lines.append("| File Name | Vulnerability Type | Evidence |")
    lines.append("|-----------|-------------------|----------|")
    for row in rows:
        # Escape pipe characters inside cell values
        fn = row["file_name"].replace("|", "\\|")
        vt = row["vulnerability_type"].replace("|", "\\|")
        ev = row["evidence"].replace("|", "\\|")
        lines.append(f"| {fn} | {vt} | {ev} |")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")

    # ── Write CSV report ────────────────────────────────────────────────
    csv_path = output_dir / "zeus_vulnerability_report.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file_name", "vulnerability_type", "evidence"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n📊 Vulnerability report generated:")
    print(f"   Markdown : {md_path}")
    print(f"   CSV      : {csv_path}")
    print(f"   Rows     : {len(rows)} ({sum(vuln_type_counts.values())} vulnerabilities across {contracts_vulnerable} contracts)")

    return md_path


# ─── CLI ────────────────────────────────────────────────────────────────────

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Audit Zeus vulnerable smart contracts for vulnerabilities"
    )
    parser.add_argument(
        "--contracts-dir",
        type=Path,
        default=Path("zeus_vulnerable_contracts"),
        help="Directory containing .sol files (default: zeus_vulnerable_contracts)",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/owasp_2023_categories.txt",
        help="Path to OWASP categories config",
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default="prompts/detect_vuln_prompt.txt",
        help="Path to system prompt template",
    )
    parser.add_argument(
        "--model",
        type=str,
        default="deepseek-r1:7b",
        help="Ollama model to use (default: deepseek-r1:7b)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("zeus_results"),
        help="Directory to save result files (default: zeus_results)",
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Limit number of files to analyze (default: all)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=1,
        help="Number of parallel workers (default: 1 = sequential)",
    )
    parser.add_argument(
        "--no-skip",
        action="store_true",
        help="Re-analyze contracts even if results already exist",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate vulnerability summary report from existing results (no analysis)",
    )

    args = parser.parse_args()

    if args.report:
        # Report-only mode: skip analysis, just build the summary file
        generate_vulnerability_report(output_dir=args.output_dir)
    else:
        run_audit(
            contracts_dir=args.contracts_dir,
            config_path=args.config,
            prompt_path=args.prompt,
            model=args.model,
            output_dir=args.output_dir,
            max_files=args.max_files,
            workers=args.workers,
            skip_existing=not args.no_skip,
        )
        # Auto-generate report after audit completes
        generate_vulnerability_report(output_dir=args.output_dir)


if __name__ == "__main__":
    main()
