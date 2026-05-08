#!/usr/bin/env python3
"""
Generate a consolidated vulnerability report from any folder of result JSON files.

Usage:
    python generate_vul_report.py zeus_results
    python generate_vul_report.py my_results_5
    python generate_vul_report.py my_results_6 --output report_v6.md
"""

import csv
import json
import argparse
from pathlib import Path
from typing import List, Dict
from datetime import datetime


def generate_vul_report(
    results_dir: Path,
    output_md: Path = None,
    output_csv: Path = None,
) -> Path:
    """
    Scan all result_*.json files in *results_dir* and produce a consolidated
    vulnerability report with a table of:
        file_name | vulnerability_type | evidence

    Args:
        results_dir: Directory containing result_*.json files
        output_md:   Path for Markdown output (default: <results_dir>/vulnerability_report.md)
        output_csv:  Path for CSV output       (default: <results_dir>/vulnerability_report.csv)

    Returns:
        Path to the generated Markdown report.
    """
    results_dir = Path(results_dir)
    if not results_dir.is_dir():
        raise FileNotFoundError(f"Directory not found: {results_dir}")

    if output_md is None:
        output_md = results_dir / "vulnerability_report.md"
    if output_csv is None:
        output_csv = results_dir / "vulnerability_report.csv"

    result_files = sorted(results_dir.glob("result_*.json"))
    if not result_files:
        print(f"No result_*.json files found in {results_dir}")
        return output_md

    # ── Collect rows ────────────────────────────────────────────────────
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

    # ── Aggregate by vulnerability type ─────────────────────────────────
    vuln_type_counts: Dict[str, int] = {}
    for row in rows:
        vt = row["vulnerability_type"]
        if vt != "(none)":
            vuln_type_counts[vt] = vuln_type_counts.get(vt, 0) + 1

    # ── Write Markdown report ───────────────────────────────────────────
    lines: List[str] = []
    lines.append(f"# Vulnerability Report — `{results_dir}`")
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

    output_md.write_text("\n".join(lines), encoding="utf-8")

    # ── Write CSV report ────────────────────────────────────────────────
    with open(output_csv, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file_name", "vulnerability_type", "evidence"])
        writer.writeheader()
        writer.writerows(rows)

    # ── Print summary to console ────────────────────────────────────────
    print(f"\nVulnerability report generated:")
    print(f"  Source    : {results_dir}  ({contracts_total} contracts)")
    print(f"  Markdown  : {output_md}")
    print(f"  CSV       : {output_csv}")
    print(f"  Vulnerable: {contracts_vulnerable}   Safe: {contracts_safe}   Errors: {contracts_error}")
    print(f"  Total vulns: {sum(vuln_type_counts.values())}")

    if vuln_type_counts:
        print(f"\n  Top vulnerability types:")
        for vt, count in sorted(vuln_type_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"    {count:>4}x  {vt}")

    return output_md


def main():
    parser = argparse.ArgumentParser(
        description="Generate a vulnerability report from a folder of result JSON files"
    )
    parser.add_argument(
        "results_dir",
        type=Path,
        help="Directory containing result_*.json files (e.g. zeus_results, my_results_5)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path for the Markdown report (default: <results_dir>/vulnerability_report.md)",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Path for the CSV report (default: <results_dir>/vulnerability_report.csv)",
    )

    args = parser.parse_args()
    generate_vul_report(
        results_dir=args.results_dir,
        output_md=args.output,
        output_csv=args.csv,
    )


if __name__ == "__main__":
    main()
