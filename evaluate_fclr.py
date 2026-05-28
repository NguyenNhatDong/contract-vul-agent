#!/usr/bin/env python3
"""Evaluate First Correct Line Rank (FCLR) for vulnerability line localization."""

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from evaluate_coverage import SCENARIOS, SCOPES, ranked_lines_for_sample
from evaluate_tlp import PredictionEntry, build_prediction_entries
from evaluate_tlr import build_ground_truth, format_lines, percent


TOLERANCES = (1, 3, 5)


@dataclass
class FCLRSampleDetail:
    scope: str
    folder: str
    file_name: str
    label: str
    gt_lines: Set[int]
    ranked_predicted_lines: List[int]
    is_conditional_sample: bool
    fclr_by_tolerance: Dict[int, Optional[int]]


def first_correct_rank(
    ranked_predicted_lines: List[int],
    gt_lines: Set[int],
    tolerance: int,
) -> Optional[int]:
    for rank, predicted_line in enumerate(ranked_predicted_lines, start=1):
        if any(abs(predicted_line - gt_line) <= tolerance for gt_line in gt_lines):
            return rank
    return None


def evaluate_details(
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    predictions_by_contract: Dict[Tuple[str, str], List[PredictionEntry]],
) -> List[FCLRSampleDetail]:
    details: List[FCLRSampleDetail] = []

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
            fclr_by_tolerance = {
                tolerance: first_correct_rank(
                    ranked_predicted_lines=ranked_predicted_lines,
                    gt_lines=gt_lines,
                    tolerance=tolerance,
                )
                for tolerance in TOLERANCES
            }

            details.append(
                FCLRSampleDetail(
                    scope=scope,
                    folder=folder,
                    file_name=file_name,
                    label=label,
                    gt_lines=gt_lines,
                    ranked_predicted_lines=ranked_predicted_lines,
                    is_conditional_sample=is_conditional,
                    fclr_by_tolerance=fclr_by_tolerance,
                )
            )

    return details


def summarize(
    details: List[FCLRSampleDetail],
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


def finite_ranks(details: List[FCLRSampleDetail], tolerance: int) -> List[int]:
    ranks: List[int] = []
    for detail in details:
        rank = detail.fclr_by_tolerance[tolerance]
        if rank is not None:
            ranks.append(rank)
    return ranks


def summary_row(
    scope: str,
    scenario: str,
    label: str,
    details: List[FCLRSampleDetail],
) -> Dict[str, object]:
    row: Dict[str, object] = {
        "scope": scope,
        "scenario": scenario,
        "label": label,
        "samples": len(details),
    }

    for tolerance in TOLERANCES:
        ranks = finite_ranks(details, tolerance)
        finite_count = len(ranks)
        inf_count = len(details) - finite_count
        mean_rank = sum(ranks) / finite_count if finite_count else None

        row[f"finite_at_{tolerance}"] = finite_count
        row[f"found_rate_at_{tolerance}_percent"] = f"{percent(finite_count, len(details)):.2f}"
        row[f"mean_fclr_at_{tolerance}"] = f"{mean_rank:.6f}" if mean_rank is not None else "NA"
        row[f"inf_count_at_{tolerance}"] = inf_count

    return row


def by_label_fieldnames() -> List[str]:
    fields = ["scope", "scenario", "label", "samples"]
    for tolerance in TOLERANCES:
        fields.extend(
            [
                f"finite_at_{tolerance}",
                f"found_rate_at_{tolerance}_percent",
                f"mean_fclr_at_{tolerance}",
                f"inf_count_at_{tolerance}",
            ]
        )
    return fields


def write_by_label(rows: List[Dict[str, object]], output_path: Path) -> None:
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=by_label_fieldnames())
        writer.writeheader()
        writer.writerows(rows)


def write_query_details(details: List[FCLRSampleDetail], output_path: Path) -> None:
    fieldnames = [
        "scope",
        "folder",
        "file_name",
        "label",
        "is_conditional_sample",
        "gt_lines",
        "ranked_predicted_lines",
        "fclr_at_1",
        "fclr_at_3",
        "fclr_at_5",
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
                    "fclr_at_1": detail.fclr_by_tolerance[1] or "inf",
                    "fclr_at_3": detail.fclr_by_tolerance[3] or "inf",
                    "fclr_at_5": detail.fclr_by_tolerance[5] or "inf",
                }
            )


def markdown_table(rows: List[Dict[str, object]], include_scope: bool = False) -> List[str]:
    headers = ["Label", "Samples"]
    if include_scope:
        headers = ["Scope", "Scenario", *headers]
    for tolerance in TOLERANCES:
        headers.extend(
            [
                f"Finite@{tolerance}",
                f"Found%@{tolerance}",
                f"Mean FCLR@{tolerance}",
                f"Inf@{tolerance}",
            ]
        )

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
        values.extend([str(row["label"]), str(row["samples"])])
        for tolerance in TOLERANCES:
            values.extend(
                [
                    str(row[f"finite_at_{tolerance}"]),
                    f"{row[f'found_rate_at_{tolerance}_percent']}%",
                    str(row[f"mean_fclr_at_{tolerance}"]),
                    str(row[f"inf_count_at_{tolerance}"]),
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
    lines.append("# First Correct Line Rank Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append(f"Model output: `{model_csv}`")
    lines.append(f"Ground truth: `{gt_csv}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("- FCLR@k is the rank of the first predicted line within tolerance `±k` of any GT vulnerable line.")
    lines.append("- Tolerance values are `1`, `3`, and `5`.")
    lines.append("- Model CSV order is used as ranking order because no confidence scores are available.")
    lines.append("- `All Labels` uses ranked predictions from every vulnerability type for the same contract.")
    lines.append("- `Correct Label Only` uses ranked predictions whose normalized type matches the GT label.")
    lines.append("- Conditional includes only samples where the correct normalized vulnerability type appears at least once for the same contract.")
    lines.append("- Mean FCLR excludes `inf`: `sum(finite FCLR ranks) / number of finite samples`.")
    lines.append("- Lower mean FCLR is better; Found% is the percentage of samples with finite FCLR.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.extend(markdown_table(overall_rows, include_scope=True))
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
    lines.append("- `inf` values are excluded from mean FCLR and counted in `Inf@k`.")
    lines.append("- Placeholder predictions `(none)`, `error`, `-`, and `--` are ignored.")
    lines.append("- Duplicate predicted lines are deduplicated by first occurrence after range alignment.")
    lines.append("- Label aliases and range alignment are shared with the existing Coverage/TLP scripts.")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def validate_rows(rows: List[Dict[str, object]]) -> None:
    for row in rows:
        found_rates = [
            float(row[f"found_rate_at_{tolerance}_percent"])
            for tolerance in TOLERANCES
        ]
        if any(rate < 0 or rate > 100 for rate in found_rates):
            raise ValueError(f"Found rate out of range: {row}")
        if found_rates != sorted(found_rates):
            raise ValueError(f"Found rate monotonicity failed: {row}")

        inf_counts = [int(row[f"inf_count_at_{tolerance}"]) for tolerance in TOLERANCES]
        if inf_counts != sorted(inf_counts, reverse=True):
            raise ValueError(f"Inf count monotonicity failed: {row}")

        for tolerance in TOLERANCES:
            finite = int(row[f"finite_at_{tolerance}"])
            inf_count = int(row[f"inf_count_at_{tolerance}"])
            samples = int(row["samples"])
            if finite + inf_count != samples:
                raise ValueError(f"Finite + inf != samples: {row}")
            mean_value = row[f"mean_fclr_at_{tolerance}"]
            if finite == 0 and mean_value != "NA":
                raise ValueError(f"Expected NA mean for no finite samples: {row}")
            if finite > 0 and float(mean_value) < 1:
                raise ValueError(f"Mean FCLR must be positive: {row}")


def evaluate_fclr(model_csv: Path, gt_csv: Path, output_dir: Path) -> Dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    gt_samples = build_ground_truth(gt_csv)
    predictions_by_contract = build_prediction_entries(model_csv)
    details = evaluate_details(gt_samples, predictions_by_contract)

    all_rows: List[Dict[str, object]] = []
    for scope in SCOPES:
        for scenario in SCENARIOS:
            all_rows.extend(summarize(details, scope, scenario))

    validate_rows(all_rows)

    by_label_path = output_dir / "fclr_by_label.csv"
    details_path = output_dir / "fclr_query_details.csv"
    report_path = output_dir / "fclr_report.md"

    write_by_label(all_rows, by_label_path)
    write_query_details(details, details_path)
    write_markdown_report(all_rows, report_path, model_csv, gt_csv)

    return {
        "by_label": by_label_path,
        "details": details_path,
        "report": report_path,
    }


def summarize(
    details: List[FCLRSampleDetail],
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate FCLR@1/3/5.")
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
        help="Directory where FCLR reports will be written.",
    )
    args = parser.parse_args()

    outputs = evaluate_fclr(args.model_csv, args.gt_csv, args.output_dir)
    print("FCLR reports generated:")
    for name, path in outputs.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()
