#!/usr/bin/env python3
"""Evaluate Tolerant Line Recall (TLR@k) for vulnerability line localization."""

import argparse
import csv
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple


TOLERANCES = (1, 3, 5)
PLACEHOLDER_TYPES = {"", "(none)", "error"}
PLACEHOLDER_EVIDENCE = {"", "-", "--", "n/a", "na", "none", "null"}

LABEL_ALIASES = {
    "Front-Running": "Front-running_Attacks",
    "Front-Running_Attacks": "Front-running_Attacks",
    "Front-Running_Attack": "Front-running_Attacks",
    "Front_Running": "Front-running_Attacks",
    "Front_Running_Attacks": "Front-running_Attacks",
    "Front-running": "Front-running_Attacks",
    "Reentrancy_Attack": "Reentrancy_Attacks",
    "Unchecked_External Calls": "Unchecked_External_Calls",
    "Unchecked External Calls": "Unchecked_External_Calls",
    "Unchecked_External_Call": "Unchecked_External_Calls",
    "other": "Other",
}


@dataclass
class SampleDetail:
    folder: str
    file_name: str
    label: str
    gt_lines: Set[int]
    predicted_lines: Set[int]
    is_conditional_sample: bool
    hits_by_k: Dict[int, Set[int]]
    missed_by_k: Dict[int, Set[int]]


def normalize_label(label: str) -> str:
    raw = (label or "").strip()
    return LABEL_ALIASES.get(raw, raw)


def parse_evidence_lines(evidence: str) -> Set[int]:
    """Parse line evidence like '27', '23-24', '19,20', or '10,12-14'."""
    raw = (evidence or "").strip()
    if raw.lower() in PLACEHOLDER_EVIDENCE:
        return set()

    lines: Set[int] = set()
    for token in re.split(r"[,;]", raw):
        token = token.strip()
        if not token or token.lower() in PLACEHOLDER_EVIDENCE:
            continue

        range_match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", token)
        if range_match:
            start, end = (int(range_match.group(1)), int(range_match.group(2)))
            if start > end:
                start, end = end, start
            lines.update(range(start, end + 1))
            continue

        int_match = re.search(r"\d+", token)
        if int_match:
            lines.add(int(int_match.group(0)))

    return lines


def read_rows(path: Path) -> List[Dict[str, str]]:
    """Read rows and recover unquoted comma evidence such as evidence=19,20."""
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        rows: List[Dict[str, str]] = []
        for row in reader:
            if None in row:
                extra = [value for value in row.pop(None) if value is not None]
                if extra:
                    evidence = row.get("evidence") or ""
                    row["evidence"] = ",".join([evidence, *extra]) if evidence else ",".join(extra)
            rows.append({key: (value or "").strip() for key, value in row.items()})
    return rows


def build_ground_truth(gt_csv: Path) -> Dict[Tuple[str, str, str], Set[int]]:
    samples: Dict[Tuple[str, str, str], Set[int]] = defaultdict(set)
    for row in read_rows(gt_csv):
        label = normalize_label(row.get("vulnerability_type", ""))
        if not label or label in PLACEHOLDER_TYPES:
            continue
        key = (row.get("folder", ""), row.get("file_name", ""), label)
        samples[key].update(parse_evidence_lines(row.get("evidence", "")))
    return dict(samples)


def build_predictions(model_csv: Path) -> Dict[Tuple[str, str, str], Set[int]]:
    predictions: Dict[Tuple[str, str, str], Set[int]] = defaultdict(set)
    for row in read_rows(model_csv):
        label = normalize_label(row.get("vulnerability_type", ""))
        if label in PLACEHOLDER_TYPES:
            continue
        key = (row.get("folder", ""), row.get("file_name", ""), label)
        predictions[key].update(parse_evidence_lines(row.get("evidence", "")))
    return dict(predictions)


def hit_lines(gt_lines: Iterable[int], predicted_lines: Set[int], tolerance: int) -> Set[int]:
    hits: Set[int] = set()
    for gt_line in gt_lines:
        if any(abs(pred_line - gt_line) <= tolerance for pred_line in predicted_lines):
            hits.add(gt_line)
    return hits


def evaluate_samples(
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    predictions: Dict[Tuple[str, str, str], Set[int]],
) -> List[SampleDetail]:
    details: List[SampleDetail] = []
    for folder, file_name, label in sorted(gt_samples):
        gt_lines = set(gt_samples[(folder, file_name, label)])
        predicted_lines = set(predictions.get((folder, file_name, label), set()))
        is_conditional = (folder, file_name, label) in predictions
        hits_by_k = {k: hit_lines(gt_lines, predicted_lines, k) for k in TOLERANCES}
        missed_by_k = {k: gt_lines - hits_by_k[k] for k in TOLERANCES}
        details.append(
            SampleDetail(
                folder=folder,
                file_name=file_name,
                label=label,
                gt_lines=gt_lines,
                predicted_lines=predicted_lines,
                is_conditional_sample=is_conditional,
                hits_by_k=hits_by_k,
                missed_by_k=missed_by_k,
            )
        )
    return details


def percent(numerator: int, denominator: int) -> float:
    return round((numerator / denominator * 100) if denominator else 0.0, 2)


def summarize(details: List[SampleDetail], scenario: str) -> List[Dict[str, object]]:
    if scenario == "Conditional":
        included = [detail for detail in details if detail.is_conditional_sample]
    else:
        included = list(details)

    labels = sorted({detail.label for detail in included})
    rows: List[Dict[str, object]] = []

    for label in labels:
        label_details = [detail for detail in included if detail.label == label]
        rows.append(summary_row(scenario, label, label_details))

    rows.append(summary_row(scenario, "Overall", included))
    return rows


def summary_row(scenario: str, label: str, details: List[SampleDetail]) -> Dict[str, object]:
    gt_line_count = sum(len(detail.gt_lines) for detail in details)
    row: Dict[str, object] = {
        "scenario": scenario,
        "label": label,
        "samples": len(details),
        "gt_lines": gt_line_count,
    }
    for k in TOLERANCES:
        hit_count = sum(len(detail.hits_by_k[k]) for detail in details)
        row[f"hit_at_{k}"] = hit_count
        row[f"tlr_at_{k}_percent"] = f"{percent(hit_count, gt_line_count):.2f}"
    return row


def format_lines(lines: Set[int]) -> str:
    return ";".join(str(line) for line in sorted(lines))


def write_by_label(rows: List[Dict[str, object]], output_path: Path) -> None:
    fieldnames = [
        "scenario",
        "label",
        "samples",
        "gt_lines",
        "hit_at_1",
        "tlr_at_1_percent",
        "hit_at_3",
        "tlr_at_3_percent",
        "hit_at_5",
        "tlr_at_5_percent",
    ]
    with open(output_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def write_query_details(details: List[SampleDetail], output_path: Path) -> None:
    fieldnames = [
        "folder",
        "file_name",
        "label",
        "is_conditional_sample",
        "gt_lines",
        "predicted_lines_matching_label",
        "hit_gt_lines_at_1",
        "hit_gt_lines_at_3",
        "hit_gt_lines_at_5",
        "missed_gt_lines_at_1",
        "missed_gt_lines_at_3",
        "missed_gt_lines_at_5",
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
                    "predicted_lines_matching_label": format_lines(detail.predicted_lines),
                    "hit_gt_lines_at_1": format_lines(detail.hits_by_k[1]),
                    "hit_gt_lines_at_3": format_lines(detail.hits_by_k[3]),
                    "hit_gt_lines_at_5": format_lines(detail.hits_by_k[5]),
                    "missed_gt_lines_at_1": format_lines(detail.missed_by_k[1]),
                    "missed_gt_lines_at_3": format_lines(detail.missed_by_k[3]),
                    "missed_gt_lines_at_5": format_lines(detail.missed_by_k[5]),
                }
            )


def markdown_table(rows: List[Dict[str, object]]) -> List[str]:
    lines = [
        "| Label | Samples | GT Lines | Hit@1 | TLR@1 | Hit@3 | TLR@3 | Hit@5 | TLR@5 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {label} | {samples} | {gt_lines} | {hit_at_1} | {tlr_at_1_percent}% | "
            "{hit_at_3} | {tlr_at_3_percent}% | {hit_at_5} | {tlr_at_5_percent}% |".format(
                **row
            )
        )
    return lines


def write_markdown_report(
    global_rows: List[Dict[str, object]],
    conditional_rows: List[Dict[str, object]],
    output_path: Path,
    model_csv: Path,
    gt_csv: Path,
) -> None:
    global_overall = next(row for row in global_rows if row["label"] == "Overall")
    conditional_overall = next(row for row in conditional_rows if row["label"] == "Overall")

    lines: List[str] = []
    lines.append("# Tolerant Line Recall Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append(f"Model output: `{model_csv}`")
    lines.append(f"Ground truth: `{gt_csv}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("- TLR@k uses line tolerance `±k` for `k = 1, 3, 5`.")
    lines.append("- For each ground-truth `(folder, file_name, label)` sample, predictions are filtered to the same normalized label.")
    lines.append("- Global evaluates all ground-truth samples.")
    lines.append("- Conditional evaluates only samples where the model predicted the correct label at least once for the same contract.")
    lines.append("- Percentages are `hit ground-truth lines / total ground-truth lines * 100`.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append("| Scenario | Samples | GT Lines | TLR@1 | TLR@3 | TLR@5 |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for row in (global_overall, conditional_overall):
        lines.append(
            f"| {row['scenario']} | {row['samples']} | {row['gt_lines']} | "
            f"{row['tlr_at_1_percent']}% | {row['tlr_at_3_percent']}% | {row['tlr_at_5_percent']}% |"
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
    lines.append("## Notes")
    lines.append("")
    lines.append("- Label aliases normalized: `Front-Running` -> `Front-running_Attacks`, `Unchecked_External Calls` -> `Unchecked_External_Calls`, `other` -> `Other`.")
    lines.append("- Evidence parser supports single lines, inclusive ranges, comma lists, and mixed comma/range values.")
    lines.append("- Placeholder predictions such as `(none)`, `error`, `-`, and `--` are ignored as line predictions.")
    lines.append("- Duplicate lines are deduplicated within each sample before recall is computed.")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")


def validate_rows(rows: List[Dict[str, object]]) -> None:
    for row in rows:
        values = [float(row[f"tlr_at_{k}_percent"]) for k in TOLERANCES]
        if any(value < 0 or value > 100 for value in values):
            raise ValueError(f"TLR percentage out of range for {row['scenario']} {row['label']}: {values}")
        if values != sorted(values):
            raise ValueError(f"TLR values are not monotonic for {row['scenario']} {row['label']}: {values}")


def evaluate_tlr(model_csv: Path, gt_csv: Path, output_dir: Path) -> Dict[str, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)

    gt_samples = build_ground_truth(gt_csv)
    predictions = build_predictions(model_csv)
    details = evaluate_samples(gt_samples, predictions)

    global_rows = summarize(details, "Global")
    conditional_rows = summarize(details, "Conditional")
    by_label_rows = global_rows + conditional_rows
    validate_rows(by_label_rows)

    by_label_path = output_dir / "tlr_by_label.csv"
    details_path = output_dir / "tlr_query_details.csv"
    report_path = output_dir / "tlr_report.md"

    write_by_label(by_label_rows, by_label_path)
    write_query_details(details, details_path)
    write_markdown_report(global_rows, conditional_rows, report_path, model_csv, gt_csv)

    return {
        "by_label": by_label_path,
        "details": details_path,
        "report": report_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate TLR@1/3/5 Global and Conditional.")
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
        help="Directory where TLR reports will be written.",
    )
    args = parser.parse_args()

    outputs = evaluate_tlr(args.model_csv, args.gt_csv, args.output_dir)
    print("TLR reports generated:")
    for name, path in outputs.items():
        print(f"  {name}: {path}")


if __name__ == "__main__":
    main()
