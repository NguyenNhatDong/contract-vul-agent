#!/usr/bin/env python3
"""Evaluate Tolerant Line Precision (TLP@k) for vulnerability line localization."""

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

from evaluate_tlr import (
    PLACEHOLDER_EVIDENCE,
    PLACEHOLDER_TYPES,
    TOLERANCES,
    build_ground_truth,
    format_lines,
    normalize_label,
    percent,
    read_rows,
)


@dataclass
class PrecisionSampleDetail:
    folder: str
    file_name: str
    label: str
    gt_lines: Set[int]
    predicted_lines: Set[int]
    is_conditional_sample: bool
    matched_pred_by_k: Dict[int, Set[int]]
    unmatched_pred_by_k: Dict[int, Set[int]]
    matched_label_predicted_lines: Set[int]
    matched_label_matched_pred_by_k: Dict[int, Set[int]]
    matched_label_unmatched_pred_by_k: Dict[int, Set[int]]


@dataclass
class PredictionEntry:
    folder: str
    file_name: str
    label: str
    segments: List[Set[int]]


def matched_predictions(
    predicted_lines: Iterable[int],
    gt_lines: Set[int],
    tolerance: int,
) -> Set[int]:
    matches: Set[int] = set()
    for pred_line in predicted_lines:
        if any(abs(pred_line - gt_line) <= tolerance for gt_line in gt_lines):
            matches.add(pred_line)
    return matches


def parse_evidence_segments(evidence: str) -> List[Set[int]]:
    """Parse evidence while preserving ranges as segments instead of expanding P globally."""
    raw = (evidence or "").strip()
    if raw.lower() in PLACEHOLDER_EVIDENCE:
        return []

    segments: List[Set[int]] = []
    for token in raw.replace(";", ",").split(","):
        token = token.strip()
        if not token or token.lower() in PLACEHOLDER_EVIDENCE:
            continue

        if "-" in token:
            parts = [part.strip() for part in token.split("-", 1)]
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                start, end = int(parts[0]), int(parts[1])
                if start > end:
                    start, end = end, start
                segments.append(set(range(start, end + 1)))
                continue

        digits = "".join(ch if ch.isdigit() else " " for ch in token).split()
        if digits:
            segments.append({int(digits[0])})

    return segments


def build_prediction_entries(model_csv: Path) -> Dict[Tuple[str, str], List[PredictionEntry]]:
    predictions: Dict[Tuple[str, str], List[PredictionEntry]] = {}
    for row in read_rows(model_csv):
        label = normalize_label(row.get("vulnerability_type", ""))
        if label in PLACEHOLDER_TYPES:
            continue
        segments = parse_evidence_segments(row.get("evidence", ""))
        if not segments:
            continue
        folder = row.get("folder", "")
        file_name = row.get("file_name", "")
        predictions.setdefault((folder, file_name), []).append(
            PredictionEntry(
                folder=folder,
                file_name=file_name,
                label=label,
                segments=segments,
            )
        )
    return predictions


def closest_line_to_gt(segment: Set[int], gt_lines: Set[int]) -> int:
    return min(
        segment,
        key=lambda pred_line: (
            min(abs(pred_line - gt_line) for gt_line in gt_lines),
            pred_line,
        ),
    )


def lines_for_sample(
    entries: List[PredictionEntry],
    gt_lines: Set[int],
    gt_label: str,
) -> Set[int]:
    predicted_lines: Set[int] = set()

    for entry in entries:
        same_label = entry.label == gt_label
        for segment in entry.segments:
            if not segment:
                continue

            overlap = segment & gt_lines
            if same_label and overlap:
                predicted_lines.update(overlap)
            elif same_label:
                predicted_lines.add(closest_line_to_gt(segment, gt_lines))
            elif len(segment) > 1:
                predicted_lines.add(closest_line_to_gt(segment, gt_lines))
            else:
                predicted_lines.update(segment)

    return predicted_lines


def lines_for_label(
    entries: List[PredictionEntry],
    gt_lines: Set[int],
    gt_label: str,
) -> Set[int]:
    predicted_lines: Set[int] = set()

    for entry in entries:
        if entry.label != gt_label:
            continue
        for segment in entry.segments:
            if not segment:
                continue

            overlap = segment & gt_lines
            if overlap:
                predicted_lines.update(overlap)
            else:
                predicted_lines.add(closest_line_to_gt(segment, gt_lines))

    return predicted_lines


def evaluate_samples(
    gt_samples: Dict[tuple, Set[int]],
    predictions_by_contract: Dict[Tuple[str, str], List[PredictionEntry]],
) -> List[PrecisionSampleDetail]:
    details: List[PrecisionSampleDetail] = []
    for folder, file_name, label in sorted(gt_samples):
        gt_lines = set(gt_samples[(folder, file_name, label)])
        entries = predictions_by_contract.get((folder, file_name), [])
        predicted_lines = lines_for_sample(entries, gt_lines, label)
        matched_label_predicted_lines = lines_for_label(entries, gt_lines, label)
        is_conditional = any(entry.label == label for entry in entries)
        matched_pred_by_k = {
            k: matched_predictions(predicted_lines, gt_lines, k) for k in TOLERANCES
        }
        unmatched_pred_by_k = {
            k: predicted_lines - matched_pred_by_k[k] for k in TOLERANCES
        }
        matched_label_matched_pred_by_k = {
            k: matched_predictions(matched_label_predicted_lines, gt_lines, k)
            for k in TOLERANCES
        }
        matched_label_unmatched_pred_by_k = {
            k: matched_label_predicted_lines - matched_label_matched_pred_by_k[k]
            for k in TOLERANCES
        }
        details.append(
            PrecisionSampleDetail(
                folder=folder,
                file_name=file_name,
                label=label,
                gt_lines=gt_lines,
                predicted_lines=predicted_lines,
                is_conditional_sample=is_conditional,
                matched_pred_by_k=matched_pred_by_k,
                unmatched_pred_by_k=unmatched_pred_by_k,
                matched_label_predicted_lines=matched_label_predicted_lines,
                matched_label_matched_pred_by_k=matched_label_matched_pred_by_k,
                matched_label_unmatched_pred_by_k=matched_label_unmatched_pred_by_k,
            )
        )
    return details


def summarize(
    details: List[PrecisionSampleDetail],
    scenario: str,
    use_matched_label_only: bool = False,
) -> List[Dict[str, object]]:
    if scenario in {"Conditional", "Conditional By Vuln"}:
        included = [detail for detail in details if detail.is_conditional_sample]
    else:
        included = list(details)

    labels = sorted({detail.label for detail in included})
    rows: List[Dict[str, object]] = []
    for label in labels:
        rows.append(
            summary_row(
                scenario,
                label,
                [d for d in included if d.label == label],
                use_matched_label_only=use_matched_label_only,
            )
        )
    rows.append(
        summary_row(
            scenario,
            "Overall",
            included,
            use_matched_label_only=use_matched_label_only,
        )
    )
    return rows


def summary_row(
    scenario: str,
    label: str,
    details: List[PrecisionSampleDetail],
    use_matched_label_only: bool = False,
) -> Dict[str, object]:
    gt_line_count = sum(len(detail.gt_lines) for detail in details)
    predicted_line_count = sum(
        len(detail.matched_label_predicted_lines if use_matched_label_only else detail.predicted_lines)
        for detail in details
    )
    row: Dict[str, object] = {
        "scenario": scenario,
        "label": label,
        "samples": len(details),
        "gt_lines": gt_line_count,
        "predicted_lines": predicted_line_count,
    }
    for k in TOLERANCES:
        matched_count = sum(
            len(
                detail.matched_label_matched_pred_by_k[k]
                if use_matched_label_only
                else detail.matched_pred_by_k[k]
            )
            for detail in details
        )
        row[f"matched_pred_at_{k}"] = matched_count
        row[f"tlp_at_{k}_percent"] = f"{percent(matched_count, predicted_line_count):.2f}"
    return row


def write_by_label(rows: List[Dict[str, object]], output_path: Path) -> None:
    fieldnames = [
        "scenario",
        "label",
        "samples",
        "gt_lines",
        "predicted_lines",
        "matched_pred_at_1",
        "tlp_at_1_percent",
        "matched_pred_at_3",
        "tlp_at_3_percent",
        "matched_pred_at_5",
        "tlp_at_5_percent",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_query_details(details: List[PrecisionSampleDetail], output_path: Path) -> None:
    fieldnames = [
        "folder",
        "file_name",
        "label",
        "is_conditional_sample",
        "gt_lines",
        "predicted_lines_all_labels",
        "predicted_lines_correct_label",
        "matched_pred_lines_at_1",
        "matched_pred_lines_at_3",
        "matched_pred_lines_at_5",
        "unmatched_pred_lines_at_1",
        "unmatched_pred_lines_at_3",
        "unmatched_pred_lines_at_5",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for detail in details:
            writer.writerow(
                {
                    "folder": detail.folder,
                    "file_name": detail.file_name,
                    "label": detail.label,
                    "is_conditional_sample": str(detail.is_conditional_sample),
                    "gt_lines": format_lines(detail.gt_lines),
                    "predicted_lines_all_labels": format_lines(detail.predicted_lines),
                    "predicted_lines_correct_label": format_lines(detail.matched_label_predicted_lines),
                    "matched_pred_lines_at_1": format_lines(detail.matched_pred_by_k[1]),
                    "matched_pred_lines_at_3": format_lines(detail.matched_pred_by_k[3]),
                    "matched_pred_lines_at_5": format_lines(detail.matched_pred_by_k[5]),
                    "unmatched_pred_lines_at_1": format_lines(detail.unmatched_pred_by_k[1]),
                    "unmatched_pred_lines_at_3": format_lines(detail.unmatched_pred_by_k[3]),
                    "unmatched_pred_lines_at_5": format_lines(detail.unmatched_pred_by_k[5]),
                }
            )


def markdown_table(rows: List[Dict[str, object]]) -> List[str]:
    lines = [
        "| Label | Samples | GT Lines | Pred Lines | Match@1 | TLP@1 | Match@3 | TLP@3 | Match@5 | TLP@5 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {label} | {samples} | {gt_lines} | {predicted_lines} | "
            "{matched_pred_at_1} | {tlp_at_1_percent}% | "
            "{matched_pred_at_3} | {tlp_at_3_percent}% | "
            "{matched_pred_at_5} | {tlp_at_5_percent}% |".format(**row)
        )
    return lines


def write_markdown_report(
    global_rows: List[Dict[str, object]],
    conditional_rows: List[Dict[str, object]],
    conditional_by_vuln_rows: List[Dict[str, object]],
    output_path: Path,
    model_csv: Path,
    gt_csv: Path,
) -> None:
    global_overall = next(row for row in global_rows if row["label"] == "Overall")
    conditional_overall = next(row for row in conditional_rows if row["label"] == "Overall")
    conditional_by_vuln_overall = next(
        row for row in conditional_by_vuln_rows if row["label"] == "Overall"
    )

    lines: List[str] = []
    lines.append("# Tolerant Line Precision Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append(f"Model output: `{model_csv}`")
    lines.append(f"Ground truth: `{gt_csv}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("- TLP@k uses line tolerance `±k` for `k = 1, 3, 5`.")
    lines.append("- For each ground-truth `(folder, file_name, label)` sample, `P` is built from all non-placeholder predicted vulnerable evidence for the same contract, across all predicted labels.")
    lines.append("- Predicted line ranges are aligned per GT vulnerability before counting P: same-label overlapping ranges keep only the GT-overlapping lines; non-overlapping ranges and wrong-label ranges are compressed to the line closest to GT.")
    lines.append("- Global evaluates all ground-truth samples.")
    lines.append("- Conditional evaluates only samples where the model predicted the correct label at least once for the same contract.")
    lines.append("- In Conditional, wrong-label predicted lines on an included contract still remain in the precision denominator.")
    lines.append("- Conditional By Vuln evaluates the same included samples, but `P` includes only predicted lines from the correctly predicted vulnerability type.")
    lines.append("- Percentages are `matched predicted lines / total predicted lines * 100`.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append("| Scenario | Samples | GT Lines | Pred Lines | TLP@1 | TLP@3 | TLP@5 |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for row in (global_overall, conditional_overall, conditional_by_vuln_overall):
        lines.append(
            f"| {row['scenario']} | {row['samples']} | {row['gt_lines']} | "
            f"{row['predicted_lines']} | {row['tlp_at_1_percent']}% | "
            f"{row['tlp_at_3_percent']}% | {row['tlp_at_5_percent']}% |"
        )
    lines.append("")
    lines.append("## Global By Label")
    lines.append("")
    lines.extend(markdown_table(global_rows))
    lines.append("")
    lines.append("## Conditional By Label")
    lines.append("")
    lines.extend(markdown_table(conditional_rows))
    lines.append("")
    lines.append("## Conditional By Vuln")
    lines.append("")
    lines.extend(markdown_table(conditional_by_vuln_rows))
    lines.append("")
    lines.append("## Notes")
    lines.append("")
    lines.append("- Label aliases and evidence parsing are shared with `evaluate_tlr.py`.")
    lines.append("- Placeholder predictions such as `(none)`, `error`, `-`, and `--` are ignored as line predictions.")
    lines.append("- Duplicate aligned predicted lines are deduplicated within each sample before precision is computed.")
    lines.append("- Labels with zero predicted vulnerable lines have TLP reported as `0.00%`.")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def validate_rows(rows: List[Dict[str, object]]) -> None:
    for row in rows:
        values = [float(row[f"tlp_at_{k}_percent"]) for k in TOLERANCES]
        if any(value < 0 or value > 100 for value in values):
            raise ValueError(f"TLP percentage out of range for {row['scenario']} {row['label']}: {values}")
        if values != sorted(values):
            raise ValueError(f"TLP values are not monotonic for {row['scenario']} {row['label']}: {values}")


def evaluate_tlp(model_csv: Path, gt_csv: Path, output_dir: Path) -> Dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    gt_samples = build_ground_truth(gt_csv)
    predictions_by_contract = build_prediction_entries(model_csv)
    details = evaluate_samples(gt_samples, predictions_by_contract)

    global_rows = summarize(details, "Global")
    conditional_rows = summarize(details, "Conditional")
    conditional_by_vuln_rows = summarize(
        details,
        "Conditional By Vuln",
        use_matched_label_only=True,
    )
    by_label_rows = global_rows + conditional_rows + conditional_by_vuln_rows
    validate_rows(by_label_rows)

    by_label_path = output_dir / "tlp_by_label.csv"
    details_path = output_dir / "tlp_query_details.csv"
    report_path = output_dir / "tlp_report.md"

    write_by_label(by_label_rows, by_label_path)
    write_query_details(details, details_path)
    write_markdown_report(
        global_rows,
        conditional_rows,
        conditional_by_vuln_rows,
        report_path,
        model_csv,
        gt_csv,
    )

    return {
        "by_label": by_label_path,
        "details": details_path,
        "report": report_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate TLP@1/3/5 Global and Conditional.")
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
        help="Directory where TLP reports will be written.",
    )
    args = parser.parse_args()

    outputs = evaluate_tlp(args.model_csv, args.gt_csv, args.output_dir)
    print("TLP reports generated:")
    for name, path in outputs.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()
