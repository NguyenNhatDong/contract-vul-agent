#!/usr/bin/env python3
"""Evaluate Average Predicted Lines (APL-Line) for vulnerability localization."""

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

from evaluate_coverage import SCENARIOS, SCOPES, ranked_lines_for_sample
from evaluate_tlp import PredictionEntry, build_prediction_entries
from evaluate_tlr import build_ground_truth, format_lines


@dataclass
class APLLineSampleDetail:
    scope: str
    folder: str
    file_name: str
    label: str
    gt_lines: Set[int]
    ranked_predicted_lines: List[int]
    is_conditional_sample: bool

    @property
    def predicted_line_count(self) -> int:
        return len(self.ranked_predicted_lines)


def evaluate_details(
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    predictions_by_contract: Dict[Tuple[str, str], List[PredictionEntry]],
) -> List[APLLineSampleDetail]:
    details: List[APLLineSampleDetail] = []

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
            details.append(
                APLLineSampleDetail(
                    scope=scope,
                    folder=folder,
                    file_name=file_name,
                    label=label,
                    gt_lines=gt_lines,
                    ranked_predicted_lines=ranked_predicted_lines,
                    is_conditional_sample=is_conditional,
                )
            )

    return details


def summarize(
    details: List[APLLineSampleDetail],
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
    details: List[APLLineSampleDetail],
) -> Dict[str, object]:
    total_predicted_lines = sum(detail.predicted_line_count for detail in details)
    samples = len(details)
    apl_line = total_predicted_lines / samples if samples else None
    return {
        "scope": scope,
        "scenario": scenario,
        "label": label,
        "samples": samples,
        "total_predicted_lines": total_predicted_lines,
        "apl_line": f"{apl_line:.6f}" if apl_line is not None else "NA",
    }


def by_label_fieldnames() -> List[str]:
    return [
        "scope",
        "scenario",
        "label",
        "samples",
        "total_predicted_lines",
        "apl_line",
    ]


def write_by_label(rows: List[Dict[str, object]], output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=by_label_fieldnames())
        writer.writeheader()
        writer.writerows(rows)


def write_query_details(
    details: List[APLLineSampleDetail],
    output_path: Path,
) -> None:
    fieldnames = [
        "scope",
        "folder",
        "file_name",
        "label",
        "is_conditional_sample",
        "gt_lines",
        "ranked_predicted_lines",
        "predicted_line_count",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for detail in details:
            writer.writerow(
                {
                    "scope": detail.scope,
                    "folder": detail.folder,
                    "file_name": detail.file_name,
                    "label": detail.label,
                    "is_conditional_sample": str(detail.is_conditional_sample),
                    "gt_lines": format_lines(detail.gt_lines),
                    "ranked_predicted_lines": ";".join(
                        str(line) for line in detail.ranked_predicted_lines
                    ),
                    "predicted_line_count": detail.predicted_line_count,
                }
            )


def markdown_table(rows: List[Dict[str, object]], include_scope: bool = False) -> List[str]:
    headers = ["Label", "Samples", "Total Predicted Lines", "APL-Line"]
    if include_scope:
        headers = ["Scope", "Scenario", *headers]

    align = ["---"] * len(headers)
    for idx, header in enumerate(headers):
        if header not in {"Scope", "Scenario", "Label"}:
            align[idx] = "---:"

    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join(align) + " |",
    ]
    for row in rows:
        values: List[str] = []
        if include_scope:
            values.extend([str(row["scope"]), str(row["scenario"])])
        values.extend(
            [
                str(row["label"]),
                str(row["samples"]),
                str(row["total_predicted_lines"]),
                str(row["apl_line"]),
            ]
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
    lines.append("# APL-Line Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append(f"Model output: `{model_csv}`")
    lines.append(f"Ground truth: `{gt_csv}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("- APL-Line is the average number of predicted vulnerable lines per included sample.")
    lines.append("- Formula: `APL-Line = total predicted_line_count / number of included samples`.")
    lines.append("- APL-Line does not use a line tolerance value.")
    lines.append("- `All Labels` counts aligned predicted lines from every vulnerability type for the same contract.")
    lines.append("- `Correct Label Only` counts aligned predicted lines whose normalized type matches the GT label.")
    lines.append("- `Global` includes every GT sample; `Conditional` includes only samples where the model predicted the correct vulnerability type at least once.")
    lines.append("- Model CSV order is preserved before deduplicating predicted lines by first occurrence after range alignment.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.extend(markdown_table(overall_rows, include_scope=True))

    for scope in SCOPES:
        for scenario in SCENARIOS:
            group_rows = [
                row
                for row in all_rows
                if row["scope"] == scope
                and row["scenario"] == scenario
                and row["label"] != "Overall"
            ]
            lines.append("")
            lines.append(f"## {scope} - {scenario} By Label")
            lines.append("")
            lines.extend(markdown_table(group_rows))

    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Prediction parsing and range alignment are shared with Coverage/FCLR so the same `P` definition is used.")
    lines.append("- Placeholder predictions such as `(none)`, `error`, `-`, and `--` do not contribute predicted lines.")
    lines.append("- Ranges are aligned against GT lines before counting, so broad ranges are not blindly expanded into many predicted lines.")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate(rows: List[Dict[str, object]]) -> None:
    overall_rows = [row for row in rows if row["label"] == "Overall"]
    global_overall = [
        row
        for row in overall_rows
        if row["scenario"] == "Global"
    ]
    for row in global_overall:
        if int(row["samples"]) != 143:
            raise AssertionError(
                f"{row['scope']} Global Overall samples expected 143, got {row['samples']}"
            )

    for scope in SCOPES:
        global_row = next(
            row for row in overall_rows if row["scope"] == scope and row["scenario"] == "Global"
        )
        conditional_row = next(
            row
            for row in overall_rows
            if row["scope"] == scope and row["scenario"] == "Conditional"
        )
        if int(conditional_row["samples"]) > int(global_row["samples"]):
            raise AssertionError(f"{scope} Conditional samples exceed Global samples")

    for row in rows:
        samples = int(row["samples"])
        total_predicted_lines = int(row["total_predicted_lines"])
        apl_line = row["apl_line"]
        if samples == 0:
            if apl_line != "NA":
                raise AssertionError(f"Expected NA APL-Line for empty row: {row}")
            continue
        expected = total_predicted_lines / samples
        if abs(float(apl_line) - expected) > 0.000001:
            raise AssertionError(f"APL-Line mismatch for row: {row}")

    for scope in SCOPES:
        for scenario in SCENARIOS:
            per_label = [
                row
                for row in rows
                if row["scope"] == scope
                and row["scenario"] == scenario
                and row["label"] != "Overall"
            ]
            overall = next(
                row
                for row in rows
                if row["scope"] == scope
                and row["scenario"] == scenario
                and row["label"] == "Overall"
            )
            if sum(int(row["samples"]) for row in per_label) != int(overall["samples"]):
                raise AssertionError(f"Sample totals do not match for {scope} {scenario}")
            if sum(int(row["total_predicted_lines"]) for row in per_label) != int(
                overall["total_predicted_lines"]
            ):
                raise AssertionError(
                    f"Predicted-line totals do not match for {scope} {scenario}"
                )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model-csv",
        type=Path,
        default=Path("LOGs/my_results_l5/vulnerability_report.csv"),
    )
    parser.add_argument(
        "--gt-csv",
        type=Path,
        default=Path("Description/smartbugs_dataset.csv"),
    )
    parser.add_argument("--output-dir", type=Path, default=Path("1705report"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    gt_samples = build_ground_truth(args.gt_csv)
    predictions_by_contract = build_prediction_entries(args.model_csv)
    details = evaluate_details(gt_samples, predictions_by_contract)

    all_rows: List[Dict[str, object]] = []
    for scope in SCOPES:
        for scenario in SCENARIOS:
            all_rows.extend(summarize(details, scope, scenario))

    validate(all_rows)

    write_by_label(all_rows, args.output_dir / "apl_line_by_label.csv")
    write_query_details(details, args.output_dir / "apl_line_query_details.csv")
    write_markdown_report(
        all_rows,
        args.output_dir / "apl_line_report.md",
        args.model_csv,
        args.gt_csv,
    )

    print(f"Wrote {args.output_dir / 'apl_line_by_label.csv'}")
    print(f"Wrote {args.output_dir / 'apl_line_query_details.csv'}")
    print(f"Wrote {args.output_dir / 'apl_line_report.md'}")


if __name__ == "__main__":
    main()
