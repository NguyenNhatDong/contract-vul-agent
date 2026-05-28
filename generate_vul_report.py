#!/usr/bin/env python3
"""
Generate audit summary and vulnerability reports from existing result JSON files.

This is a report-only helper for folders that already contain result_*.json files,
for example LOGs/my_results_l5. It mirrors the summary/report behavior in run.py
without rerunning model analysis.

Outputs written to the selected results folder:
    - overall_audit_summary.json
    - vulnerability_report.csv
    - vulnerability_report.md

It also writes per-folder vulnerability_report.csv and vulnerability_report.md for
each child folder that contains result_*.json files.

Usage:
    python generate_vul_report.py LOGs/my_results_l5
    python generate_vul_report.py LOGs/my_results_l5 --no-folder-reports
"""

import argparse
import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


NONE_TYPE = "(none)"
ERROR_TYPE = "error"


def _safe_cell(value: Any, default: str = "") -> str:
    text = default if value is None else str(value)
    return text.replace("|", "\\|")


def _load_result_file(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        print(f"Skipping unreadable result file {path}: {exc}")
        return None

    if not isinstance(data, dict):
        print(f"Skipping non-object result file {path}")
        return None

    return data


def _is_error_result(data: Dict[str, Any]) -> bool:
    return data.get("status") == "Error" or bool(data.get("error"))


def _result_folders(results_base: Path) -> List[Path]:
    """Return folders that directly contain result_*.json files."""
    folders = {p.parent for p in results_base.rglob("result_*.json")}
    return sorted(folders, key=lambda p: p.relative_to(results_base).as_posix().lower())


def _display_folder_name(folder: Path, results_base: Path) -> str:
    if folder == results_base:
        return results_base.name
    return folder.relative_to(results_base).as_posix()


def _collect_folder_summary(folder: Path, results_base: Path) -> Dict[str, Any]:
    result_files = sorted(folder.glob("result_*.json"))
    rows: List[Dict[str, str]] = []
    contracts_analyzed: List[Dict[str, Any]] = []

    total_contracts = 0
    successful_analyses = 0
    failed_analyses = 0
    vulnerable_contracts = 0
    safe_contracts = 0
    total_vulnerabilities = 0
    total_analysis_time = 0.0
    vulnerability_types: Dict[str, int] = {}

    for result_file in result_files:
        data = _load_result_file(result_file)
        if data is None:
            continue

        total_contracts += 1
        contract_name = data.get("contract_name") or f"{result_file.stem}.sol"
        analysis_time = float(data.get("analysis_time_seconds") or 0)
        total_analysis_time += analysis_time

        if _is_error_result(data):
            failed_analyses += 1
            rows.append(
                {
                    "file_name": contract_name,
                    "vulnerability_type": ERROR_TYPE,
                    "evidence": "--",
                }
            )
            contracts_analyzed.append(
                {
                    "contract_name": contract_name,
                    "status": "Error",
                    "vulnerabilities_count": 0,
                    "analysis_time_seconds": analysis_time,
                    "result_file": result_file.name,
                }
            )
            continue

        successful_analyses += 1
        vulnerabilities = data.get("vulnerabilities") or []

        if not vulnerabilities:
            safe_contracts += 1
            rows.append(
                {
                    "file_name": contract_name,
                    "vulnerability_type": NONE_TYPE,
                    "evidence": "-",
                }
            )
        else:
            vulnerable_contracts += 1
            total_vulnerabilities += len(vulnerabilities)
            for vuln in vulnerabilities:
                if not isinstance(vuln, dict):
                    continue
                vuln_type = str(vuln.get("vulnerability_type") or "Unknown")
                vulnerability_types[vuln_type] = vulnerability_types.get(vuln_type, 0) + 1
                rows.append(
                    {
                        "file_name": contract_name,
                        "vulnerability_type": vuln_type,
                        "evidence": str(vuln.get("evidence") or "N/A"),
                    }
                )

        contracts_analyzed.append(
            {
                "contract_name": contract_name,
                "status": data.get("status", "Unknown"),
                "vulnerabilities_count": len(vulnerabilities),
                "analysis_time_seconds": analysis_time,
                "result_file": result_file.name,
            }
        )

    avg_time = total_analysis_time / total_contracts if total_contracts else 0.0
    folder_name = _display_folder_name(folder, results_base)

    return {
        "folder": folder,
        "folder_name": folder_name,
        "rows": rows,
        "audit_summary": {
            "folder_name": folder_name,
            "audit_metadata": {
                "timestamp": datetime.now().isoformat(),
                "source_dir": str(folder),
            },
            "summary": {
                "total_contracts": total_contracts,
                "successful_analyses": successful_analyses,
                "failed_analyses": failed_analyses,
                "vulnerable_contracts": vulnerable_contracts,
                "safe_contracts": safe_contracts,
                "total_vulnerabilities_found": total_vulnerabilities,
                "average_analysis_time_seconds": round(avg_time, 2),
                "vulnerability_types_distribution": vulnerability_types,
            },
            "contracts_analyzed": contracts_analyzed,
        },
    }


def _write_folder_vulnerability_report(folder_summary: Dict[str, Any]) -> None:
    folder: Path = folder_summary["folder"]
    rows: List[Dict[str, str]] = folder_summary["rows"]
    summary = folder_summary["audit_summary"]["summary"]

    vuln_type_counts = summary["vulnerability_types_distribution"]

    md_path = folder / "vulnerability_report.md"
    lines: List[str] = []
    lines.append(f"# Vulnerability Report — `{folder_summary['folder_name']}`")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total contracts scanned | {summary['total_contracts']} |")
    lines.append(f"| Vulnerable contracts    | {summary['vulnerable_contracts']} |")
    lines.append(f"| Safe contracts          | {summary['safe_contracts']} |")
    lines.append(f"| Errored contracts       | {summary['failed_analyses']} |")
    lines.append(f"| Total vulnerabilities   | {summary['total_vulnerabilities_found']} |")
    lines.append("")

    if vuln_type_counts:
        lines.append("## Vulnerability Type Distribution")
        lines.append("")
        lines.append("| Vulnerability Type | Count |")
        lines.append("|-------------------|-------|")
        for vt, count in sorted(vuln_type_counts.items(), key=lambda item: item[1], reverse=True):
            lines.append(f"| {_safe_cell(vt)} | {count} |")
        lines.append("")

    lines.append("## Detailed Findings")
    lines.append("")
    lines.append("| File Name | Vulnerability Type | Evidence |")
    lines.append("|-----------|-------------------|----------|")
    for row in rows:
        lines.append(
            f"| {_safe_cell(row['file_name'])} | "
            f"{_safe_cell(row['vulnerability_type'])} | "
            f"{_safe_cell(row['evidence'])} |"
        )
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    csv_path = folder / "vulnerability_report.csv"
    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["file_name", "vulnerability_type", "evidence"])
        writer.writeheader()
        writer.writerows(rows)


def _write_overall_summary(results_base: Path, folder_summaries: List[Dict[str, Any]]) -> Path:
    total_contracts = sum(s["audit_summary"]["summary"]["total_contracts"] for s in folder_summaries)
    total_successful = sum(s["audit_summary"]["summary"]["successful_analyses"] for s in folder_summaries)
    total_failed = sum(s["audit_summary"]["summary"]["failed_analyses"] for s in folder_summaries)
    total_vulnerable = sum(s["audit_summary"]["summary"]["vulnerable_contracts"] for s in folder_summaries)
    total_safe = sum(s["audit_summary"]["summary"]["safe_contracts"] for s in folder_summaries)
    total_vulns = sum(s["audit_summary"]["summary"]["total_vulnerabilities_found"] for s in folder_summaries)

    overall_vuln_types: Dict[str, int] = {}
    for folder_summary in folder_summaries:
        distribution = folder_summary["audit_summary"]["summary"]["vulnerability_types_distribution"]
        for vuln_type, count in distribution.items():
            overall_vuln_types[vuln_type] = overall_vuln_types.get(vuln_type, 0) + count

    overall_summary = {
        "audit_metadata": {
            "timestamp": datetime.now().isoformat(),
            "source_dir": str(results_base),
        },
        "summary": {
            "total_folders": len(folder_summaries),
            "total_contracts": total_contracts,
            "successful_analyses": total_successful,
            "failed_analyses": total_failed,
            "vulnerable_contracts": total_vulnerable,
            "safe_contracts": total_safe,
            "total_vulnerabilities_found": total_vulns,
            "vulnerability_types_distribution": overall_vuln_types,
        },
        "per_folder": [
            {
                "folder_name": s["folder_name"],
                "total_contracts": s["audit_summary"]["summary"]["total_contracts"],
                "vulnerable": s["audit_summary"]["summary"]["vulnerable_contracts"],
                "safe": s["audit_summary"]["summary"]["safe_contracts"],
                "failed": s["audit_summary"]["summary"]["failed_analyses"],
                "vulns_found": s["audit_summary"]["summary"]["total_vulnerabilities_found"],
                "output_dir": str(s["folder"]),
            }
            for s in folder_summaries
        ],
    }

    output_path = results_base / "overall_audit_summary.json"
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(overall_summary, f, indent=2, ensure_ascii=False)
    return output_path


def _overall_rows(folder_summaries: Iterable[Dict[str, Any]]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for folder_summary in folder_summaries:
        for row in folder_summary["rows"]:
            rows.append(
                {
                    "folder": folder_summary["folder_name"],
                    "file_name": row["file_name"],
                    "vulnerability_type": row["vulnerability_type"],
                    "evidence": row["evidence"],
                }
            )
    return rows


def _write_overall_vulnerability_reports(
    results_base: Path,
    folder_summaries: List[Dict[str, Any]],
    output_md: Optional[Path] = None,
    output_csv: Optional[Path] = None,
) -> Path:
    rows = _overall_rows(folder_summaries)
    total_contracts = sum(s["audit_summary"]["summary"]["total_contracts"] for s in folder_summaries)
    total_vulnerable = sum(s["audit_summary"]["summary"]["vulnerable_contracts"] for s in folder_summaries)
    total_safe = sum(s["audit_summary"]["summary"]["safe_contracts"] for s in folder_summaries)
    total_errors = sum(s["audit_summary"]["summary"]["failed_analyses"] for s in folder_summaries)
    total_vulns = sum(s["audit_summary"]["summary"]["total_vulnerabilities_found"] for s in folder_summaries)

    vuln_type_counts: Dict[str, int] = {}
    for folder_summary in folder_summaries:
        distribution = folder_summary["audit_summary"]["summary"]["vulnerability_types_distribution"]
        for vuln_type, count in distribution.items():
            vuln_type_counts[vuln_type] = vuln_type_counts.get(vuln_type, 0) + count

    md_path = output_md or results_base / "vulnerability_report.md"
    csv_path = output_csv or results_base / "vulnerability_report.csv"

    lines: List[str] = []
    lines.append(f"# Vulnerability Report — `{results_base}`")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("## Overview")
    lines.append("")
    lines.append("| Metric | Count |")
    lines.append("|--------|-------|")
    lines.append(f"| Total contracts scanned | {total_contracts} |")
    lines.append(f"| Vulnerable contracts    | {total_vulnerable} |")
    lines.append(f"| Safe contracts          | {total_safe} |")
    lines.append(f"| Errored contracts       | {total_errors} |")
    lines.append(f"| Total vulnerabilities   | {total_vulns} |")
    lines.append("")

    if vuln_type_counts:
        lines.append("## Vulnerability Type Distribution")
        lines.append("")
        lines.append("| Vulnerability Type | Count |")
        lines.append("|-------------------|-------|")
        for vt, count in sorted(vuln_type_counts.items(), key=lambda item: item[1], reverse=True):
            lines.append(f"| {_safe_cell(vt)} | {count} |")
        lines.append("")

    lines.append("## Per-Folder Breakdown")
    lines.append("")
    lines.append("| Folder | Total | Vulnerable | Safe | Errors |")
    lines.append("|--------|-------|------------|------|--------|")
    for folder_summary in folder_summaries:
        summary = folder_summary["audit_summary"]["summary"]
        lines.append(
            f"| {_safe_cell(folder_summary['folder_name'])} | "
            f"{summary['total_contracts']} | "
            f"{summary['vulnerable_contracts']} | "
            f"{summary['safe_contracts']} | "
            f"{summary['failed_analyses']} |"
        )
    lines.append("")

    lines.append("## Detailed Findings")
    lines.append("")
    lines.append("| Folder | File Name | Vulnerability Type | Evidence |")
    lines.append("|--------|-----------|-------------------|----------|")
    for row in rows:
        lines.append(
            f"| {_safe_cell(row['folder'])} | "
            f"{_safe_cell(row['file_name'])} | "
            f"{_safe_cell(row['vulnerability_type'])} | "
            f"{_safe_cell(row['evidence'])} |"
        )
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    with open(csv_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["folder", "file_name", "vulnerability_type", "evidence"],
        )
        writer.writeheader()
        writer.writerows(rows)

    return md_path


def generate_reports(
    results_dir: Path,
    output_md: Optional[Path] = None,
    output_csv: Optional[Path] = None,
    write_folder_reports: bool = True,
) -> Dict[str, Path]:
    results_base = Path(results_dir)
    if not results_base.is_dir():
        raise FileNotFoundError(f"Directory not found: {results_base}")

    folders = _result_folders(results_base)
    if not folders:
        raise FileNotFoundError(f"No result_*.json files found under {results_base}")

    folder_summaries = [_collect_folder_summary(folder, results_base) for folder in folders]
    if write_folder_reports:
        for folder_summary in folder_summaries:
            _write_folder_vulnerability_report(folder_summary)

    summary_path = _write_overall_summary(results_base, folder_summaries)
    md_path = _write_overall_vulnerability_reports(
        results_base,
        folder_summaries,
        output_md=output_md,
        output_csv=output_csv,
    )
    csv_path = output_csv or results_base / "vulnerability_report.csv"

    total_contracts = sum(s["audit_summary"]["summary"]["total_contracts"] for s in folder_summaries)
    total_vulnerable = sum(s["audit_summary"]["summary"]["vulnerable_contracts"] for s in folder_summaries)
    total_safe = sum(s["audit_summary"]["summary"]["safe_contracts"] for s in folder_summaries)
    total_errors = sum(s["audit_summary"]["summary"]["failed_analyses"] for s in folder_summaries)
    total_vulns = sum(s["audit_summary"]["summary"]["total_vulnerabilities_found"] for s in folder_summaries)

    print("\nVulnerability reports generated:")
    print(f"  Source          : {results_base}")
    print(f"  Folders         : {len(folder_summaries)}")
    print(f"  Contracts       : {total_contracts}")
    print(f"  Vulnerable/Safe : {total_vulnerable}/{total_safe}")
    print(f"  Errors          : {total_errors}")
    print(f"  Total vulns     : {total_vulns}")
    print(f"  Overall summary : {summary_path}")
    print(f"  Markdown report : {md_path}")
    print(f"  CSV report      : {csv_path}")

    return {
        "overall_summary": summary_path,
        "markdown_report": md_path,
        "csv_report": csv_path,
    }


# Backward-compatible name used by the old script.
def generate_vul_report(
    results_dir: Path,
    output_md: Optional[Path] = None,
    output_csv: Optional[Path] = None,
) -> Path:
    return generate_reports(results_dir, output_md=output_md, output_csv=output_csv)[
        "markdown_report"
    ]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate overall audit summary and vulnerability reports from existing result JSON files"
    )
    parser.add_argument(
        "results_dir",
        type=Path,
        help="Directory containing result_*.json files directly or in subfolders, e.g. LOGs/my_results_l5",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Path for the overall Markdown report (default: <results_dir>/vulnerability_report.md)",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Path for the overall CSV report (default: <results_dir>/vulnerability_report.csv)",
    )
    parser.add_argument(
        "--no-folder-reports",
        action="store_true",
        help="Only write the three overall files; skip per-folder vulnerability reports",
    )

    args = parser.parse_args()
    generate_reports(
        results_dir=args.results_dir,
        output_md=args.output,
        output_csv=args.csv,
        write_folder_reports=not args.no_folder_reports,
    )


if __name__ == "__main__":
    main()
