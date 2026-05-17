#!/usr/bin/env python3
"""
Automate smart contract vulnerability auditing process.

Processes all Solidity contracts in smartbugs_dataset/:
1. Iterates over each sub-folder (e.g. access_control, reentrancy, …)
2. Loads vulnerability categories from OWASP 2023 Smart Contract Top 10
3. Formats each contract with line numbers
4. Analyzes each contract for vulnerabilities
5. Saves individual JSON results per contract into LOGs/my_results/<FOLDER_NAME>/
   Example: LOGs/my_results/access_control/result_arbitrary_location_write_simple.json
"""

import csv
import json
import time
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

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


def load_categories(path: str) -> List[str]:
    """Load OWASP vulnerability categories from config file"""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip()]


def analyze_contract(
    contract_path: Path,
    agent: SmartContractVulnAgent,
) -> Dict[str, Any]:
    """
    Analyze a single Solidity contract for vulnerabilities.
    
    Args:
        contract_path: Path to the .sol file
        agent: SmartContractVulnAgent instance
    
    Returns:
        Dictionary with analysis results including:
        - contract_name: Name of the contract file
        - contract_path: Path to the contract
        - status: 'Normal' (safe) or 'Vulnerable'
        - vulnerabilities: List of detected vulnerabilities
        - analysis_time: Time taken for analysis in seconds
        - error: Error message if analysis failed
    """
    contract_name = contract_path.name
    
    try:
        # Read contract and format with line numbers
        sol_text = contract_path.read_text(encoding="utf-8")
        sol_with_lines = format_with_line_numbers(sol_text)
        
        # Analyze contract
        start_time = time.time()
        result = agent.analyze(sol_with_lines)
        analysis_time = time.time() - start_time
        
        # Process results
        vulnerabilities = []
        if result.vulnerabilities:
            for vuln in result.vulnerabilities:
                vuln_dict = {
                    "vulnerability_type": vuln.vulnerability_type,
                    "evidence": vuln.evidence,
                    "function_name": vuln.function_name,
                    "evidence_snippet": vuln.evidence_snippet,
                    "execution": {
                        "trigger": vuln.execution.trigger,
                        "state_issue": vuln.execution.state_issue,
                        "exploitable_behavior": vuln.execution.exploitable_behavior
                    },
                    "causality": {
                        "state": vuln.causality.state,
                        "guard": vuln.causality.guard,
                        "transition": vuln.causality.transition,
                        "capability": vuln.causality.capability,
                        "outcome": vuln.causality.outcome
                    }
                }
                vulnerabilities.append(vuln_dict)
        
        # Determine status
        status = "Normal" if not vulnerabilities else "Vulnerable"
        
        return {
            "contract_name": contract_name,
            "contract_path": str(contract_path),
            "status": status,
            "vulnerabilities_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "thinking_process": result.thinking_process,
            "analysis_time_seconds": round(analysis_time, 2),
            "timestamp": datetime.now().isoformat(),
            "error": None
        }
        
    except Exception as e:
        return {
            "contract_name": contract_name,
            "contract_path": str(contract_path),
            "status": "Error",
            "vulnerabilities_count": 0,
            "vulnerabilities": [],
            "thinking_process": getattr(e, "thinking_process", None),
            "analysis_time_seconds": 0,
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }


def run_folder_audit(
    folder_path: Path,
    agent: SmartContractVulnAgent,
    output_dir: Path,
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run vulnerability audit on all .sol files in a single category folder.
    
    Args:
        folder_path: Path to a category folder (e.g. smartbugs_dataset/access_control)
        agent: SmartContractVulnAgent instance (reused across folders)
        output_dir: Directory to save result files for this folder
        max_files: Limit number of files to analyze (None = all)
    
    Returns:
        Dictionary with audit summary for this folder
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    folder_name = folder_path.name
    
    # Find all .sol files in this folder
    sol_files = sorted(folder_path.glob("**/*.sol"))
    
    if max_files:
        sol_files = sol_files[:max_files]
    
    if not sol_files:
        print(f"  ⚠️  No .sol files found in {folder_name}")
        return {}
    
    print(f"\n  📂 {folder_name} — {len(sol_files)} contracts")
    print(f"  {'─' * 50}")
    
    # Analyze each contract
    audit_results = []
    folder_start = time.time()
    
    for idx, contract_path in enumerate(sol_files, 1):
        print(f"  [{idx}/{len(sol_files)}] {contract_path.name}...", end=" ", flush=True)
        
        result = analyze_contract(contract_path, agent)
        audit_results.append(result)
        
        # Save individual result file
        sol_filename = contract_path.stem
        result_filename = f"result_{sol_filename}.json"
        result_filepath = output_dir / result_filename
        
        with open(result_filepath, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        # Display result
        if result["error"]:
            print(f"❌ ERROR: {result['error']}")
        else:
            status_icon = "🚨" if result["status"] == "Vulnerable" else "✓"
            print(f"{status_icon} {result['status']} ({result['analysis_time_seconds']}s, {result['vulnerabilities_count']} vulns)")
    
    folder_time = time.time() - folder_start
    
    # Calculate folder-level summary
    successful = [r for r in audit_results if r["error"] is None]
    failed = [r for r in audit_results if r["error"] is not None]
    vulnerable = [r for r in successful if r["status"] == "Vulnerable"]
    safe = [r for r in successful if r["status"] == "Normal"]
    
    total_vulns = sum(r["vulnerabilities_count"] for r in successful)
    avg_time = sum(r["analysis_time_seconds"] for r in successful) / len(successful) if successful else 0
    
    # Vulnerability types summary
    all_vuln_types = {}
    for r in successful:
        for vuln in r["vulnerabilities"]:
            vuln_type = vuln["vulnerability_type"]
            all_vuln_types[vuln_type] = all_vuln_types.get(vuln_type, 0) + 1
    
    folder_summary = {
        "folder_name": folder_name,
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_time_seconds": round(folder_time, 2)
        },
        "summary": {
            "total_contracts": len(sol_files),
            "successful_analyses": len(successful),
            "failed_analyses": len(failed),
            "vulnerable_contracts": len(vulnerable),
            "safe_contracts": len(safe),
            "total_vulnerabilities_found": total_vulns,
            "average_analysis_time_seconds": round(avg_time, 2),
            "vulnerability_types_distribution": all_vuln_types
        },
        "contracts_analyzed": [
            {
                "contract_name": r["contract_name"],
                "status": r["status"],
                "vulnerabilities_count": r["vulnerabilities_count"],
                "analysis_time_seconds": r["analysis_time_seconds"],
                "result_file": f"result_{Path(r['contract_name']).stem}.json"
            }
            for r in audit_results
        ]
    }
    
    # Save folder summary
    summary_file = output_dir / "audit_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(folder_summary, f, indent=2, ensure_ascii=False)
    
    print(f"  ✅ {folder_name}: {len(vulnerable)} vulnerable, {len(safe)} safe, {len(failed)} failed ({folder_time:.1f}s)")
    
    return folder_summary


def run_audit(
    dataset_dir: Path = Path("smartbugs_dataset"),
    config_path: str = "config/owasp_2023_categories.txt",
    prompt_path: str = "prompts/detect_vuln_prompt.txt",
    model: str = "deepseek-r1:8b",
    output_base: Path = Path("LOGs/my_results"),
    max_files: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Run vulnerability audit on all .sol files across all folders in smartbugs_dataset.
    Each folder's results are saved to LOGs/my_results/<FOLDER_NAME>/.
    
    Args:
        dataset_dir: Root directory containing category sub-folders (default: smartbugs_dataset)
        config_path: Path to OWASP categories config file
        prompt_path: Path to system prompt template
        model: Ollama model to use (default: deepseek-r1:8b)
        output_base: Base output directory (default: LOGs/my_results)
        max_files: Limit number of files per folder (None = all)
    
    Returns:
        Dictionary with overall audit summary
    """
    # Discover all category sub-folders
    category_folders = sorted([
        d for d in dataset_dir.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])
    
    if not category_folders:
        print(f"❌ No sub-folders found in {dataset_dir}")
        return {}
    
    # Load categories
    owasp_categories = load_categories(config_path)
    
    # Initialize agent (single instance reused across all folders)
    agent = SmartContractVulnAgent(
        model=model,
        prompt_path=prompt_path,
        owasp_categories=owasp_categories
    )
    
    # Count total .sol files across all folders
    total_sol = sum(len(list(f.glob("**/*.sol"))) for f in category_folders)
    
    print(f"\n🔐 SmartBugs Dataset — Vulnerability Audit")
    print(f"{'=' * 60}")
    print(f"Model            : {model}")
    print(f"Categories       : {len(owasp_categories)}")
    print(f"Dataset folders  : {len(category_folders)}")
    print(f"Total contracts  : {total_sol}")
    print(f"Output base      : {output_base}")
    print(f"{'=' * 60}")
    
    # Process each folder
    all_folder_summaries = []
    audit_start = time.time()
    
    for folder_idx, folder_path in enumerate(category_folders, 1):
        print(f"\n{'━' * 60}")
        print(f"📁 [{folder_idx}/{len(category_folders)}] Processing: {folder_path.name}")
        print(f"{'━' * 60}")
        
        folder_output = output_base / folder_path.name
        
        folder_summary = run_folder_audit(
            folder_path=folder_path,
            agent=agent,
            output_dir=folder_output,
            max_files=max_files,
        )
        
        if folder_summary:
            all_folder_summaries.append(folder_summary)
    
    total_time = time.time() - audit_start
    
    # Build overall summary
    total_contracts = sum(s["summary"]["total_contracts"] for s in all_folder_summaries)
    total_successful = sum(s["summary"]["successful_analyses"] for s in all_folder_summaries)
    total_failed = sum(s["summary"]["failed_analyses"] for s in all_folder_summaries)
    total_vulnerable = sum(s["summary"]["vulnerable_contracts"] for s in all_folder_summaries)
    total_safe = sum(s["summary"]["safe_contracts"] for s in all_folder_summaries)
    total_vulns = sum(s["summary"]["total_vulnerabilities_found"] for s in all_folder_summaries)
    
    # Aggregate vulnerability types across all folders
    overall_vuln_types = {}
    for s in all_folder_summaries:
        for vt, count in s["summary"]["vulnerability_types_distribution"].items():
            overall_vuln_types[vt] = overall_vuln_types.get(vt, 0) + count
    
    overall_summary = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "model": model,
            "dataset": str(dataset_dir),
            "owasp_categories": len(owasp_categories),
            "total_time_seconds": round(total_time, 2)
        },
        "summary": {
            "total_folders": len(all_folder_summaries),
            "total_contracts": total_contracts,
            "successful_analyses": total_successful,
            "failed_analyses": total_failed,
            "vulnerable_contracts": total_vulnerable,
            "safe_contracts": total_safe,
            "total_vulnerabilities_found": total_vulns,
            "vulnerability_types_distribution": overall_vuln_types
        },
        "per_folder": [
            {
                "folder_name": s["folder_name"],
                "total_contracts": s["summary"]["total_contracts"],
                "vulnerable": s["summary"]["vulnerable_contracts"],
                "safe": s["summary"]["safe_contracts"],
                "failed": s["summary"]["failed_analyses"],
                "vulns_found": s["summary"]["total_vulnerabilities_found"],
                "time_seconds": s["audit_metadata"]["total_time_seconds"],
                "output_dir": str(output_base / s["folder_name"]),
            }
            for s in all_folder_summaries
        ]
    }
    
    # Save overall summary at the output base level
    output_base.mkdir(parents=True, exist_ok=True)
    overall_summary_file = output_base / "overall_audit_summary.json"
    with open(overall_summary_file, "w", encoding="utf-8") as f:
        json.dump(overall_summary, f, indent=2, ensure_ascii=False)
    
    # Print final summary
    print(f"\n{'=' * 60}")
    print(f"✅ SmartBugs Dataset Audit Complete!")
    print(f"{'=' * 60}")
    print(f"Folders processed       : {len(all_folder_summaries)}")
    print(f"Total contracts analyzed : {total_contracts}")
    print(f"Vulnerable contracts    : {total_vulnerable}")
    print(f"Safe contracts          : {total_safe}")
    print(f"Failed analyses         : {total_failed}")
    print(f"Total vulnerabilities   : {total_vulns}")
    print(f"Total time              : {total_time:.2f}s")
    print(f"\n📁 Results saved to: {output_base}")
    print(f"   Each folder has its own sub-directory with result_<CONTRACT>.json files")
    print(f"📋 Overall summary: {overall_summary_file}")
    
    if overall_vuln_types:
        print(f"\nVulnerability Types Found:")
        for vuln_type, count in sorted(overall_vuln_types.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {vuln_type}: {count}")
    
    print(f"\nPer-folder breakdown:")
    for s in all_folder_summaries:
        sm = s["summary"]
        print(f"  📂 {s['folder_name']:30s} | {sm['vulnerable_contracts']} vuln, {sm['safe_contracts']} safe, {sm['failed_analyses']} fail | {sm['total_vulnerabilities_found']} findings")
    
    # Auto-generate vulnerability report after audit
    generate_summary_report(output_base)

    return overall_summary


# ─── Summary report generation ──────────────────────────────────────────────

def generate_summary_report(results_base: Path) -> Path:
    """
    Scan all result_*.json files across sub-folders in *results_base* and
    produce a consolidated vulnerability report with:
        file_name | folder | vulnerability_type | evidence

    Outputs (saved to results_base):
        - vulnerability_report.md   (Markdown table)
        - vulnerability_report.csv  (machine-readable)

    Also generates per-folder reports inside each sub-folder.

    Returns the path to the overall Markdown report.
    """
    results_base = Path(results_base)
    if not results_base.is_dir():
        print(f"⚠️  Results directory not found: {results_base}")
        return results_base / "vulnerability_report.md"

    # ── Per-folder reports ──────────────────────────────────────────────
    sub_folders = sorted([
        d for d in results_base.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])

    for folder in sub_folders:
        _generate_folder_report(folder)

    # ── Overall report across all folders ───────────────────────────────
    all_rows: List[Dict[str, str]] = []
    contracts_total = 0
    contracts_vulnerable = 0
    contracts_safe = 0
    contracts_error = 0

    for folder in sub_folders:
        result_files = sorted(folder.glob("result_*.json"))
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
                all_rows.append({
                    "file_name": file_name,
                    "folder": folder.name,
                    "vulnerability_type": "error",
                    "evidence": "--",
                })
                continue

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                contracts_safe += 1
                all_rows.append({
                    "file_name": file_name,
                    "folder": folder.name,
                    "vulnerability_type": "(none)",
                    "evidence": "-",
                })
                continue

            contracts_vulnerable += 1
            for vuln in vulns:
                all_rows.append({
                    "file_name": file_name,
                    "folder": folder.name,
                    "vulnerability_type": vuln.get("vulnerability_type", "Unknown"),
                    "evidence": vuln.get("evidence", "N/A"),
                })

    # ── Aggregate by vulnerability type ─────────────────────────────────
    vuln_type_counts: Dict[str, int] = {}
    for row in all_rows:
        vt = row["vulnerability_type"]
        if vt not in {"(none)", "error"}:
            vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1

    # ── Write overall Markdown report ───────────────────────────────────
    md_path = results_base / "vulnerability_report.md"
    lines: List[str] = []
    lines.append(f"# Vulnerability Report — `{results_base}`")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
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

    # ── Per-folder breakdown ────────────────────────────────────────────
    lines.append("## Per-Folder Breakdown")
    lines.append("")
    lines.append("| Folder | Total | Vulnerable | Safe | Errors |")
    lines.append("|--------|-------|------------|------|--------|")
    for folder in sub_folders:
        f_total = 0
        f_vuln = 0
        f_safe = 0
        f_err = 0
        for rf in sorted(folder.glob("result_*.json")):
            try:
                with open(rf, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            f_total += 1
            st = data.get("status", "Unknown")
            if st == "Error":
                f_err += 1
            elif data.get("vulnerabilities", []):
                f_vuln += 1
            else:
                f_safe += 1
        if f_total > 0:
            lines.append(f"| {folder.name} | {f_total} | {f_vuln} | {f_safe} | {f_err} |")
    lines.append("")

    lines.append("## Detailed Findings")
    lines.append("")
    lines.append("| Folder | File Name | Vulnerability Type | Evidence |")
    lines.append("|--------|-----------|-------------------|----------|")
    for row in all_rows:
        fd = row["folder"].replace("|", "\\|")
        fn = row["file_name"].replace("|", "\\|")
        vt = row["vulnerability_type"].replace("|", "\\|")
        ev = row["evidence"].replace("|", "\\|")
        lines.append(f"| {fd} | {fn} | {vt} | {ev} |")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")

    # ── Write overall CSV report ────────────────────────────────────────
    csv_path = results_base / "vulnerability_report.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["folder", "file_name", "vulnerability_type", "evidence"])
        writer.writeheader()
        writer.writerows(all_rows)

    # ── Console output ──────────────────────────────────────────────────
    print(f"\n📊 Vulnerability summary report generated:")
    print(f"   Source    : {results_base}  ({contracts_total} contracts across {len(sub_folders)} folders)")
    print(f"   Markdown  : {md_path}")
    print(f"   CSV       : {csv_path}")
    print(f"   Vulnerable: {contracts_vulnerable}   Safe: {contracts_safe}   Errors: {contracts_error}")
    print(f"   Total vulns: {sum(vuln_type_counts.values())}")

    if vuln_type_counts:
        print(f"\n   Top vulnerability types:")
        for vt, count in sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"     {count:>4}x  {vt}")

    return md_path


def _generate_folder_report(folder: Path) -> Path:
    """
    Generate a per-folder vulnerability report (MD + CSV) inside the given folder.
    """
    result_files = sorted(folder.glob("result_*.json"))
    if not result_files:
        return folder / "vulnerability_report.md"

    rows: List[Dict[str, str]] = []
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
            rows.append({
                "file_name": file_name,
                "vulnerability_type": "error",
                "evidence": "--",
            })
            continue

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            contracts_safe += 1
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

    vuln_type_counts: Dict[str, int] = {}
    for row in rows:
        vt = row["vulnerability_type"]
        if vt not in {"(none)", "error"}:
            vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1

    # Markdown
    md_path = folder / "vulnerability_report.md"
    lines: List[str] = []
    lines.append(f"# Vulnerability Report — `{folder.name}`")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
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
        fn = row["file_name"].replace("|", "\\|")
        vt = row["vulnerability_type"].replace("|", "\\|")
        ev = row["evidence"].replace("|", "\\|")
        lines.append(f"| {fn} | {vt} | {ev} |")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")

    # CSV
    csv_path = folder / "vulnerability_report.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file_name", "vulnerability_type", "evidence"])
        writer.writeheader()
        writer.writerows(rows)

    return md_path


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Automate smart contract vulnerability auditing on SmartBugs dataset"
    )
    parser.add_argument(
        "--dataset-dir",
        type=Path,
        default=Path("smartbugs_dataset"),
        help="Root directory containing category sub-folders (default: smartbugs_dataset)"
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config/owasp_2023_categories.txt",
        help="Path to OWASP categories config (default: config/owasp_2023_categories.txt)"
    )
    parser.add_argument(
        "--prompt",
        type=str,
        default="prompts/detect_vuln_prompt.txt",
        help="Path to system prompt template (default: prompts/detect_vuln_prompt.txt)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="deepseek-r1:8b",
        help="Ollama model to use (default: deepseek-r1:8b)"
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("LOGs/my_results"),
        help="Base directory for result files (default: LOGs/my_results)"
    )
    parser.add_argument(
        "--max-files",
        type=int,
        default=None,
        help="Limit number of files per folder (default: all)"
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate vulnerability summary report from existing results (no analysis)"
    )
    
    args = parser.parse_args()
    
    if args.report:
        # Report-only mode: skip analysis, just build the summary report
        generate_summary_report(args.output_dir)
    else:
        # Run audit across all folders (report is auto-generated at the end)
        run_audit(
            dataset_dir=args.dataset_dir,
            config_path=args.config,
            prompt_path=args.prompt,
            model=args.model,
            output_base=args.output_dir,
            max_files=args.max_files,
        )


if __name__ == "__main__":
    main()
