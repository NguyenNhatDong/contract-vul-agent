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

import json
import time
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from app.agent import SmartContractVulnAgent
from app.chunker import chunk_whole_file


def load_categories(path: str) -> List[str]:
    """Load OWASP vulnerability categories from config file"""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [ln.strip() for ln in lines if ln.strip()]


def format_code_with_lines(sol_text: str) -> str:
    """
    Format Solidity code by adding line numbers to each line.
    
    Args:
        sol_text: Raw Solidity code
    
    Returns:
        Code with line numbers (e.g., '1: pragma solidity...')
    """
    chunk = chunk_whole_file(sol_text)
    return chunk.code_with_lines


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
        # Read and format contract
        sol_text = contract_path.read_text(encoding="utf-8")
        code_with_lines = format_code_with_lines(sol_text)
        
        # Analyze contract
        start_time = time.time()
        result = agent.analyze(code_with_lines)
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
    model: str = "deepseek-r1:7b",
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
        model: Ollama model to use (default: deepseek-r1:7b)
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
    
    return overall_summary


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
        default="deepseek-r1:7b",
        help="Ollama model to use (default: deepseek-r1:7b)"
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
    
    args = parser.parse_args()
    
    # Run audit across all folders
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
