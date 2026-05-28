#!/usr/bin/env python3
"""Explain why Reentrancy EMT is much lower than TOP-k accuracy."""

import argparse
import csv
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


TARGET_LABEL = "Reentrancy_Attacks"
PREFERRED_EXAMPLES = [
    "0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol",
    "0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol",
    "0x561eac93c92360949ab1f1403323e6db345cbf31.sol",
    "etherbank.sol",
    "reentrancy_simple.sol",
    "reentrancy_bonus.sol",
]


@dataclass
class QueryRow:
    folder: str
    file_name: str
    model_prediction_count: int
    predicted_labels: List[str]
    exact_match: bool
    top1_hit: bool
    top3_hit: bool
    topmax_hit: bool


@dataclass
class JsonEvidence:
    path: Path
    status: str
    vulnerabilities_count: int
    vulnerabilities: List[Dict[str, object]]
    thinking_process: str


def read_csv(path: Path) -> List[Dict[str, str]]:
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def to_bool(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes"}


def parse_labels(value: str) -> List[str]:
    raw = (value or "").strip()
    if not raw:
        return []
    return [part.strip() for part in raw.split("|") if part.strip()]


def build_reentrancy_rows(emt_details: Path, topk_details: Path) -> List[QueryRow]:
    topk_by_file: Dict[str, Dict[str, str]] = {}
    for row in read_csv(topk_details):
        if row.get("label") == TARGET_LABEL and row.get("folder") == "reentrancy":
            topk_by_file[row.get("file_name", "")] = row

    rows: List[QueryRow] = []
    for row in read_csv(emt_details):
        if row.get("label") != TARGET_LABEL or row.get("folder") != "reentrancy":
            continue
        file_name = row.get("file_name", "")
        topk = topk_by_file.get(file_name, {})
        rows.append(
            QueryRow(
                folder=row.get("folder", ""),
                file_name=file_name,
                model_prediction_count=int(row.get("model_prediction_count") or 0),
                predicted_labels=parse_labels(row.get("predicted_labels", "")),
                exact_match=to_bool(row.get("exact_match", "")),
                top1_hit=to_bool(topk.get("top1_hit", "")),
                top3_hit=to_bool(topk.get("top3_hit", "")),
                topmax_hit=to_bool(topk.get("topmax_hit", "")),
            )
        )
    return rows


def json_path_for(results_dir: Path, file_name: str) -> Path:
    stem = file_name[:-4] if file_name.endswith(".sol") else file_name
    return results_dir / "reentrancy" / f"result_{stem}.json"


def read_json_evidence(path: Path) -> Optional[JsonEvidence]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    vulnerabilities = data.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        vulnerabilities = []
    return JsonEvidence(
        path=path,
        status=str(data.get("status") or ""),
        vulnerabilities_count=int(data.get("vulnerabilities_count") or len(vulnerabilities)),
        vulnerabilities=[v for v in vulnerabilities if isinstance(v, dict)],
        thinking_process=str(data.get("thinking_process") or ""),
    )


def metric_row(path: Path, label: str) -> Dict[str, str]:
    for row in read_csv(path):
        if row.get("label") == label:
            return row
    raise ValueError(f"Missing {label} in {path}")


def classify_failure(row: QueryRow) -> str:
    if row.top1_hit and not row.exact_match and row.model_prediction_count > 1:
        return "TOP-1 correct but EMT fails because the model emitted extra predictions"
    if not row.topmax_hit and row.model_prediction_count > 0:
        return "TOP-max fails because Reentrancy_Attacks is absent"
    if row.model_prediction_count == 0:
        return "No valid prediction/status Normal or Error"
    if row.topmax_hit and not row.exact_match:
        return "Correct label present but EMT fails because exact-match conditions are not met"
    return "Other"


def failure_summary(rows: List[QueryRow]) -> Counter:
    return Counter(classify_failure(row) for row in rows if not row.exact_match)


def clean_text(text: str) -> str:
    return " ".join((text or "").split())


def excerpt_around(text: str, terms: List[str], limit: int = 520, min_index: int = 900) -> str:
    clean = clean_text(text)
    if not clean:
        return "(thinking_process is empty)"
    lower = clean.lower()
    best_index = -1
    for term in terms:
        term = term.strip()
        if not term:
            continue
        best_index = lower.find(term.lower(), min_index)
        if best_index < 0:
            best_index = lower.find(term.lower())
        if best_index >= 0:
            break
    if best_index < 0:
        best_index = 0
    start = max(0, best_index - 150)
    end = min(len(clean), start + limit)
    excerpt = clean[start:end]
    if start > 0:
        excerpt = "..." + excerpt
    if end < len(clean):
        excerpt += "..."
    return excerpt


def vulnerability_summary(evidence: JsonEvidence) -> str:
    if not evidence.vulnerabilities:
        return "`vulnerabilities`: []"
    parts = []
    for item in evidence.vulnerabilities:
        parts.append(
            "`{}` evidence `{}` function `{}`".format(
                item.get("vulnerability_type", ""),
                item.get("evidence", ""),
                item.get("function_name", ""),
            )
        )
    return "<br>".join(parts)


def select_examples(rows: List[QueryRow]) -> List[QueryRow]:
    candidates = [
        row
        for row in rows
        if row.top1_hit and not row.exact_match and row.model_prediction_count > 1
    ]
    by_file = {row.file_name: row for row in candidates}
    selected: List[QueryRow] = []
    seen = set()
    for file_name in PREFERRED_EXAMPLES:
        row = by_file.get(file_name)
        if row and row.file_name not in seen:
            selected.append(row)
            seen.add(row.file_name)
        if len(selected) == 5:
            return selected
    for row in sorted(candidates, key=lambda item: (-item.model_prediction_count, item.file_name)):
        if row.file_name in seen:
            continue
        selected.append(row)
        seen.add(row.file_name)
        if len(selected) == 5:
            break
    return selected


def extra_labels(row: QueryRow) -> List[str]:
    return [label for label in row.predicted_labels if label != TARGET_LABEL]


def terms_for_extra_labels(labels: List[str]) -> List[str]:
    terms: List[str] = []
    for label in labels:
        if label == "Arithmetic":
            terms.extend(["potential overflow", "overflow", "arithmetic operation", "wrap around"])
        elif label == "Access_Control":
            terms.extend(["Access control", "no restriction", "public", "owner"])
        elif label == "Denial_of_Service_Attacks":
            terms.extend(["Denial", "DoS", "out of gas", "unbounded"])
        elif label == "Time_Manipulation":
            terms.extend(["Time", "timestamp", "now", "block"])
        elif label == "Short_Addresses":
            terms.extend(["Short", "address truncation"])
        elif label == "Unchecked_External_Calls":
            terms.extend(["Unchecked", "return value", "call failure"])
        elif label == "Other":
            terms.extend(["Other", "none", "not fit"])
        terms.append(label)
    return terms


def explanation_for(row: QueryRow, evidence: JsonEvidence) -> str:
    extras = extra_labels(row)
    if not extras:
        return "EMT fails for an exact-match condition, but no extra labels were parsed from the query details."
    return (
        "TOP-k considers this successful because `Reentrancy_Attacks` appears at rank 1. "
        "EMT marks it as failed because the same output also contains extra label(s): "
        + ", ".join(f"`{label}`" for label in extras)
        + ". The thinking_process shows the model continuing beyond the reentrancy finding and considering additional vulnerability categories, which turns a correct top prediction into a non-exact multi-label answer."
    )


def write_report(
    output_path: Path,
    rows: List[QueryRow],
    emt_label_row: Dict[str, str],
    topk_label_row: Dict[str, str],
    examples: List[QueryRow],
    results_dir: Path,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    failed_rows = [row for row in rows if not row.exact_match]
    top1_correct_emt_failed = [
        row for row in failed_rows if row.top1_hit and row.model_prediction_count > 1
    ]
    summary = failure_summary(rows)

    lines: List[str] = []
    lines.append("# Reentrancy EMT vs TOP-k Failure Analysis")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append("## Metric Gap")
    lines.append("")
    lines.append("| Metric | Hits | N | Score |")
    lines.append("|---|---:|---:|---:|")
    lines.append(
        f"| EMT | {emt_label_row.get('E_exact_matches')} | {emt_label_row.get('N_contracts')} | {emt_label_row.get('EMT')} |"
    )
    lines.append(
        f"| TOP-1 Accuracy | {topk_label_row.get('O_top1_hits')} | {topk_label_row.get('N_contracts')} | {topk_label_row.get('TOP1_accuracy')} |"
    )
    lines.append(
        f"| TOP-3 Accuracy | {topk_label_row.get('T_top3_hits')} | {topk_label_row.get('N_contracts')} | {topk_label_row.get('TOP3_accuracy')} |"
    )
    lines.append(
        f"| TOP-max Accuracy | {topk_label_row.get('M_topmax_hits')} | {topk_label_row.get('N_contracts')} | {topk_label_row.get('TOPMAX_accuracy')} |"
    )
    lines.append("")
    lines.append("## Main Answer")
    lines.append("")
    lines.append(
        "`Reentrancy_Attacks` has high TOP-k accuracy because the model usually ranks the correct reentrancy label first. "
        "However, EMT is much lower because EMT requires exactly one prediction and that prediction must be correct. "
        f"In the query details, {len(top1_correct_emt_failed)} reentrancy contracts have TOP-1 correct but fail EMT because the model emits multiple labels."
    )
    lines.append("")
    lines.append("## EMT Failure Categories")
    lines.append("")
    lines.append("| Category | Count |")
    lines.append("|---|---:|")
    for category, count in summary.most_common():
        lines.append(f"| {category} | {count} |")
    lines.append("")
    lines.append("## Evidence From JSON Thinking Process")
    lines.append("")

    for idx, row in enumerate(examples, start=1):
        path = json_path_for(results_dir, row.file_name)
        evidence = read_json_evidence(path)
        lines.append(f"### Example {idx}: `{row.file_name}`")
        lines.append("")
        lines.append(f"- JSON: `{path}`")
        lines.append(f"- Query predicted labels: `{ ' | '.join(row.predicted_labels) }`")
        lines.append(f"- EMT exact_match: `{int(row.exact_match)}`")
        lines.append(
            f"- TOP-k: top1=`{int(row.top1_hit)}`, top3=`{int(row.top3_hit)}`, topmax=`{int(row.topmax_hit)}`"
        )
        if evidence is None:
            lines.append("- JSON could not be read.")
            lines.append("")
            continue
        lines.append(f"- JSON status: `{evidence.status}`, vulnerabilities_count: `{evidence.vulnerabilities_count}`")
        lines.append(f"- Model output vulnerabilities: {vulnerability_summary(evidence)}")
        lines.append("")
        lines.append("Thinking excerpt showing reentrancy recognition:")
        lines.append("")
        lines.append(
            "> "
            + excerpt_around(
                evidence.thinking_process,
                [
                    "classic reentrancy",
                    "reentrant",
                    "external call",
                    "call.value",
                    "transfer before",
                    "Reentrancy Attacks",
                ],
                min_index=1200,
            )
        )
        lines.append("")
        extra_terms = terms_for_extra_labels(extra_labels(row))
        lines.append("Thinking excerpt showing expansion to extra labels:")
        lines.append("")
        lines.append(
            "> "
            + excerpt_around(
                evidence.thinking_process,
                extra_terms,
                min_index=1600,
            )
        )
        lines.append("")
        lines.append("Explanation based on thinking_process:")
        lines.append("")
        lines.append(explanation_for(row, evidence))
        lines.append("")

    lines.append("## Conclusion")
    lines.append("")
    lines.append(
        "The gap is primarily an exact-match strictness issue amplified by model over-prediction. "
        "The thinking_process often identifies the correct reentrancy pattern, then continues scanning for additional possible vulnerabilities and emits extra labels. "
        "TOP-k rewards the correct first label, while EMT penalizes the same output because it is not a single-label exact match."
    )
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, default=Path("1705report"))
    parser.add_argument("--results-dir", type=Path, default=Path("LOGs/my_results_l5"))
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("Failure_analysis/Reentrancy_EMT_vs_TOPK.md"),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    emt_by_label = args.report_dir / "emt_by_label.csv"
    topk_by_label = args.report_dir / "topk_accuracy_by_label.csv"
    emt_details = args.report_dir / "emt_query_details.csv"
    topk_details = args.report_dir / "topk_accuracy_query_details.csv"

    rows = build_reentrancy_rows(emt_details, topk_details)
    emt_label_row = metric_row(emt_by_label, TARGET_LABEL)
    topk_label_row = metric_row(topk_by_label, TARGET_LABEL)
    examples = select_examples(rows)

    if emt_label_row.get("EMT") != "0.322581":
        raise AssertionError(f"Unexpected EMT: {emt_label_row.get('EMT')}")
    if topk_label_row.get("TOP1_accuracy") != "0.903226":
        raise AssertionError(f"Unexpected TOP1: {topk_label_row.get('TOP1_accuracy')}")
    if len(examples) < 5:
        raise AssertionError(f"Expected at least 5 examples, got {len(examples)}")
    for row in examples:
        path = json_path_for(args.results_dir, row.file_name)
        if not path.exists():
            raise AssertionError(f"Missing JSON example: {path}")

    write_report(
        output_path=args.output,
        rows=rows,
        emt_label_row=emt_label_row,
        topk_label_row=topk_label_row,
        examples=examples,
        results_dir=args.results_dir,
    )
    print(f"Wrote {args.output}")
    print(f"Examples: {len(examples)}")


if __name__ == "__main__":
    main()
