#!/usr/bin/env python3
"""Evaluate Coverage@K for vulnerability line localization rankings."""

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

from evaluate_tlp import (
    PredictionEntry,
    build_prediction_entries,
    closest_line_to_gt,
)
from evaluate_tlr import (
    build_ground_truth,
    format_lines,
    percent,
)


TOP_K_VALUES = (1, 3, 5)
TOLERANCES = (1, 3, 5)
SCOPES = ("All Labels", "Correct Label Only")
SCENARIOS = ("Global", "Conditional")


@dataclass
class CoverageSampleDetail:
    scope: str
    folder: str
    file_name: str
    label: str
    gt_lines: Set[int]
    ranked_predicted_lines: List[int]
    is_conditional_sample: bool
    covered_by_grid: Dict[Tuple[int, int], Set[int]]
    missed_by_grid: Dict[Tuple[int, int], Set[int]]


def dedupe_preserve_order(lines: Iterable[int]) -> List[int]:
    seen: Set[int] = set()
    ordered: List[int] = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            ordered.append(line)
    return ordered


def aligned_lines_from_segment(
    entry: PredictionEntry,
    segment: Set[int],
    gt_lines: Set[int],
    gt_label: str,
    correct_label_only: bool,
) -> List[int]:
    if correct_label_only and entry.label != gt_label:
        return []

    same_label = entry.label == gt_label
    overlap = segment & gt_lines

    if same_label and overlap:
        return sorted(overlap)
    if same_label:
        return [closest_line_to_gt(segment, gt_lines)]
    if len(segment) > 1:
        return [closest_line_to_gt(segment, gt_lines)]
    return sorted(segment)


def ranked_lines_for_sample(
    entries: List[PredictionEntry],
    gt_lines: Set[int],
    gt_label: str,
    correct_label_only: bool,
) -> List[int]:
    ranked: List[int] = []
    for entry in entries:
        for segment in entry.segments:
            if not segment:
                continue
            ranked.extend(
                aligned_lines_from_segment(
                    entry=entry,
                    segment=segment,
                    gt_lines=gt_lines,
                    gt_label=gt_label,
                    correct_label_only=correct_label_only,
                )
            )
    return dedupe_preserve_order(ranked)


def covered_gt_lines(
    gt_lines: Set[int],
    predicted_lines: List[int],
    top_k: int,
    tolerance: int,
) -> Set[int]:
    top_predictions = predicted_lines[:top_k]
    return {
        gt_line
        for gt_line in gt_lines
        if any(abs(pred_line - gt_line) <= tolerance for pred_line in top_predictions)
    }


def evaluate_details(
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    predictions_by_contract: Dict[Tuple[str, str], List[PredictionEntry]],
) -> List[CoverageSampleDetail]:
    details: List[CoverageSampleDetail] = []

    for folder, file_name, label in sorted(gt_samples):
        gt_lines = set(gt_samples[(folder, file_name, label)])
        entries = predictions_by_contract.get((folder, file_name), [])
        is_conditional = any(entry.label == label for entry in entries)

        for scope in SCOPES:
            correct_label_only = scope == "Correct Label Only"
            ranked_predicted_lines = ranked_lines_for_sample(
                entries=entries,
                gt_lines=gt_lines,
                gt_label=label,
                correct_label_only=correct_label_only,
            )
            covered_by_grid: Dict[Tuple[int, int], Set[int]] = {}
            missed_by_grid: Dict[Tuple[int, int], Set[int]] = {}

            for top_k in TOP_K_VALUES:
                for tolerance in TOLERANCES:
                    covered = covered_gt_lines(
                        gt_lines=gt_lines,
                        predicted_lines=ranked_predicted_lines,
                        top_k=top_k,
                        tolerance=tolerance,
                    )
                    covered_by_grid[(top_k, tolerance)] = covered
                    missed_by_grid[(top_k, tolerance)] = gt_lines - covered

            details.append(
                CoverageSampleDetail(
                    scope=scope,
                    folder=folder,
                    file_name=file_name,
                    label=label,
                    gt_lines=gt_lines,
                    ranked_predicted_lines=ranked_predicted_lines,
                    is_conditional_sample=is_conditional,
                    covered_by_grid=covered_by_grid,
                    missed_by_grid=missed_by_grid,
                )
            )

    return details


def summarize(
    details: List[CoverageSampleDetail],
    scope: str,
    scenario: str,
) -> List[Dict[str, object]]:
    included = [detail for detail in details if detail.scope == scope]
    if scenario == "Conditional":
        included = [detail for detail in included if detail.is_conditional_sample]

    labels = sorted({detail.label for detail in included})
    rows = [
        summary_row(scope, scenario, label, [d for d in included if d.label == label])
        for label in labels
    ]
    rows.append(summary_row(scope, scenario, "Overall", included))
    return rows


def summary_row(
    scope: str,
    scenario: str,
    label: str,
    details: List[CoverageSampleDetail],
) -> Dict[str, object]:
    gt_line_count = sum(len(detail.gt_lines) for detail in details)
    row: Dict[str, object] = {
        "scope": scope,
        "scenario": scenario,
        "label": label,
        "samples": len(details),
        "gt_lines": gt_line_count,
    }

    for top_k in TOP_K_VALUES:
        for tolerance in TOLERANCES:
            covered_count = sum(
                len(detail.covered_by_grid[(top_k, tolerance)])
                for detail in details
            )
            row[f"covered_at_{top_k}_tol_{tolerance}"] = covered_count
            row[f"coverage_at_{top_k}_tol_{tolerance}_percent"] = (
                f"{percent(covered_count, gt_line_count):.2f}"
            )

    return row


def by_label_fieldnames() -> List[str]:
    fields = ["scope", "scenario", "label", "samples", "gt_lines"]
    for top_k in TOP_K_VALUES:
        for tolerance in TOLERANCES:
            fields.append(f"covered_at_{top_k}_tol_{tolerance}")
            fields.append(f"coverage_at_{top_k}_tol_{tolerance}_percent")
    return fields


def write_by_label(rows: List[Dict[str, object]], output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=by_label_fieldnames())
        writer.writeheader()
        writer.writerows(rows)


def detail_fieldnames() -> List[str]:
    fields = [
        "scope",
        "folder",
        "file_name",
        "label",
        "is_conditional_sample",
        "gt_lines",
        "ranked_predicted_lines",
        "top1_lines",
        "top3_lines",
        "top5_lines",
    ]
    for top_k in TOP_K_VALUES:
        for tolerance in TOLERANCES:
            fields.append(f"covered_at_{top_k}_tol_{tolerance}")
            fields.append(f"missed_at_{top_k}_tol_{tolerance}")
    return fields


def write_query_details(details: List[CoverageSampleDetail], output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=detail_fieldnames())
        writer.writeheader()
        for detail in details:
            row = {
                "scope": detail.scope,
                "folder": detail.folder,
                "file_name": detail.file_name,
                "label": detail.label,
                "is_conditional_sample": str(detail.is_conditional_sample),
                "gt_lines": format_lines(detail.gt_lines),
                "ranked_predicted_lines": ";".join(str(line) for line in detail.ranked_predicted_lines),
                "top1_lines": ";".join(str(line) for line in detail.ranked_predicted_lines[:1]),
                "top3_lines": ";".join(str(line) for line in detail.ranked_predicted_lines[:3]),
                "top5_lines": ";".join(str(line) for line in detail.ranked_predicted_lines[:5]),
            }
            for top_k in TOP_K_VALUES:
                for tolerance in TOLERANCES:
                    row[f"covered_at_{top_k}_tol_{tolerance}"] = format_lines(
                        detail.covered_by_grid[(top_k, tolerance)]
                    )
                    row[f"missed_at_{top_k}_tol_{tolerance}"] = format_lines(
                        detail.missed_by_grid[(top_k, tolerance)]
                    )
            writer.writerow(row)


def coverage_percent_key(top_k: int, tolerance: int) -> str:
    return f"coverage_at_{top_k}_tol_{tolerance}_percent"


def markdown_table(rows: List[Dict[str, object]]) -> List[str]:
    headers = ["Label", "Samples", "GT Lines"]
    headers.extend(f"C@{top_k}±{tol}" for top_k in TOP_K_VALUES for tol in TOLERANCES)
    align = ["---", "---:", "---:"]
    align.extend(["---:"] * (len(headers) - 3))
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(align) + " |",
    ]

    for row in rows:
        values = [str(row["label"]), str(row["samples"]), str(row["gt_lines"])]
        values.extend(
            f"{row[coverage_percent_key(top_k, tol)]}%"
            for top_k in TOP_K_VALUES
            for tol in TOLERANCES
        )
        lines.append("| " + " | ".join(values) + " |")
    return lines


def overall_markdown_table(rows: List[Dict[str, object]]) -> List[str]:
    headers = ["Scope", "Scenario", "Samples", "GT Lines"]
    headers.extend(f"C@{top_k}±{tol}" for top_k in TOP_K_VALUES for tol in TOLERANCES)
    align = ["---", "---", "---:", "---:"]
    align.extend(["---:"] * (len(headers) - 4))
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(align) + " |",
    ]

    for row in rows:
        values = [
            str(row["scope"]),
            str(row["scenario"]),
            str(row["samples"]),
            str(row["gt_lines"]),
        ]
        values.extend(
            f"{row[coverage_percent_key(top_k, tol)]}%"
            for top_k in TOP_K_VALUES
            for tol in TOLERANCES
        )
        lines.append("| " + " | ".join(values) + " |")
    return lines


def write_markdown_report(
    all_rows: List[Dict[str, object]],
    output_path: Path,
    model_csv: Path,
    gt_csv: Path,
) -> None:
    overall_rows = [row for row in all_rows if row["label"] == "Overall"]

    lines: List[str] = []
    lines.append("# Coverage@K Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append(f"Model output: `{model_csv}`")
    lines.append(f"Ground truth: `{gt_csv}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("- Coverage@K evaluates how many GT vulnerable lines are covered by the first K ranked predicted lines.")
    lines.append("- Top-K values are `1`, `3`, and `5`; tolerance values are `±1`, `±3`, and `±5`.")
    lines.append("- Model CSV order is used as ranking order because no confidence scores are available.")
    lines.append("- `All Labels` uses ranked predictions from every vulnerability type for the same contract.")
    lines.append("- `Correct Label Only` uses ranked predictions whose normalized type matches the GT label.")
    lines.append("- Conditional includes only samples where the correct normalized vulnerability type appears at least once for the same contract.")
    lines.append("- Predicted line ranges use the same range-aware alignment as TLP before ranking/deduplication.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.extend(overall_markdown_table(overall_rows))
    lines.append("")

    for scope in SCOPES:
        for scenario in SCENARIOS:
            rows = [
                row
                for row in all_rows
                if row["scope"] == scope
                and row["scenario"] == scenario
                and row["label"] != "Overall"
            ]
            lines.append(f"## {scope} - {scenario} By Label")
            lines.append("")
            lines.extend(markdown_table(rows))
            lines.append("")

    lines.append("## Notes")
    lines.append("")
    lines.append("- Placeholder predictions `(none)`, `error`, `-`, and `--` are ignored.")
    lines.append("- Duplicate predicted lines are deduplicated by first occurrence after range alignment.")
    lines.append("- Label aliases are inherited from `evaluate_tlr.py`.")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def validate_rows(rows: List[Dict[str, object]]) -> None:
    for row in rows:
        for top_k in TOP_K_VALUES:
            values = [
                float(row[coverage_percent_key(top_k, tolerance)])
                for tolerance in TOLERANCES
            ]
            if any(value < 0 or value > 100 for value in values):
                raise ValueError(f"Coverage percentage out of range: {row}")
            if values != sorted(values):
                raise ValueError(f"Coverage tolerance monotonicity failed: {row}")

        for tolerance in TOLERANCES:
            values = [
                float(row[coverage_percent_key(top_k, tolerance)])
                for top_k in TOP_K_VALUES
            ]
            if values != sorted(values):
                raise ValueError(f"Coverage top-K monotonicity failed: {row}")


def evaluate_coverage(model_csv: Path, gt_csv: Path, output_dir: Path) -> Dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    gt_samples = build_ground_truth(gt_csv)
    predictions_by_contract = build_prediction_entries(model_csv)
    details = evaluate_details(gt_samples, predictions_by_contract)

    all_rows: List[Dict[str, object]] = []
    for scope in SCOPES:
        for scenario in SCENARIOS:
            all_rows.extend(summarize(details, scope, scenario))

    validate_rows(all_rows)

    by_label_path = output_dir / "coverage_by_label.csv"
    details_path = output_dir / "coverage_query_details.csv"
    report_path = output_dir / "coverage_report.md"

    write_by_label(all_rows, by_label_path)
    write_query_details(details, details_path)
    write_markdown_report(all_rows, report_path, model_csv, gt_csv)

    return {
        "by_label": by_label_path,
        "details": details_path,
        "report": report_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Coverage@K for vulnerability line localization.")
    parser.add_argument(
        "--model-csv",
        type=Path,
        default=Path("LOGs/my_results_l5/vulnerability_report.csv"),
        help="Model vulnerability report CSV.",
    )
    parser.add_argument(
        "--gt-csv",
        type=Path,
        default=Path("Description/smartbugs_dataset.csv"),
        help="Ground-truth description CSV.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("1705report"),
        help="Directory where Coverage reports will be written.",
    )
    args = parser.parse_args()

    outputs = evaluate_coverage(args.model_csv, args.gt_csv, args.output_dir)
    print("Coverage reports generated:")
    for name, path in outputs.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()
