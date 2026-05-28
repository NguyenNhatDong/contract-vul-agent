#!/usr/bin/env python3
"""Evaluate Average Predicted Labels (APL) by ground-truth label."""

import argparse
import csv
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

from evaluate_tlr import PLACEHOLDER_TYPES, normalize_label, read_rows


def build_gt_samples(gt_csv: Path) -> Dict[str, Set[Tuple[str, str]]]:
    samples_by_label: Dict[str, Set[Tuple[str, str]]] = defaultdict(set)
    for row in read_rows(gt_csv):
        label = normalize_label(row.get("vulnerability_type", ""))
        if not label or label in PLACEHOLDER_TYPES:
            continue
        folder = row.get("folder", "")
        file_name = row.get("file_name", "")
        samples_by_label[label].add((folder, file_name))
    return dict(samples_by_label)


def build_model_predictions(model_csv: Path) -> Dict[Tuple[str, str], List[Dict[str, str]]]:
    predictions_by_contract: Dict[Tuple[str, str], List[Dict[str, str]]] = defaultdict(list)
    for row in read_rows(model_csv):
        label = normalize_label(row.get("vulnerability_type", ""))
        if label in PLACEHOLDER_TYPES:
            continue
        folder = row.get("folder", "")
        file_name = row.get("file_name", "")
        predictions_by_contract[(folder, file_name)].append(
            {
                "folder": folder,
                "file_name": file_name,
                "predicted_label": label,
                "evidence": row.get("evidence", ""),
            }
        )
    return dict(predictions_by_contract)


def build_summary_rows(
    gt_samples: Dict[str, Set[Tuple[str, str]]],
    predictions_by_contract: Dict[Tuple[str, str], List[Dict[str, str]]],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]], Counter]:
    labels = sorted(gt_samples)
    prediction_counts: Counter = Counter()
    details: List[Dict[str, object]] = []

    for gt_label in labels:
        for folder, file_name in sorted(gt_samples[gt_label]):
            predictions = predictions_by_contract.get((folder, file_name), [])
            for prediction in predictions:
                predicted_label = prediction["predicted_label"]
                prediction_counts[gt_label] += 1
                details.append(
                    {
                        "folder": folder,
                        "file_name": file_name,
                        "ground_truth_label": gt_label,
                        "predicted_label": predicted_label,
                        "evidence": prediction["evidence"],
                    }
                )

    rows: List[Dict[str, object]] = []
    for label in labels:
        denominator = len(gt_samples[label])
        total_predictions = prediction_counts[label]
        apl = total_predictions / denominator if denominator else 0.0
        rows.append(
            {
                "label": label,
                "total_predictions": total_predictions,
                "gt_contracts": denominator,
                "APL": f"{apl:.6f}",
            }
        )
    return rows, details, prediction_counts


def write_by_label(rows: List[Dict[str, object]], path: Path) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "label",
                "total_predictions",
                "gt_contracts",
                "APL",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_prediction_details(details: List[Dict[str, object]], path: Path) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "folder",
                "file_name",
                "ground_truth_label",
                "predicted_label",
                "evidence",
            ],
        )
        writer.writeheader()
        writer.writerows(details)


def write_report(
    rows: List[Dict[str, object]],
    prediction_counts: Counter,
    gt_samples: Dict[str, Set[Tuple[str, str]]],
    model_csv: Path,
    gt_csv: Path,
    output_path: Path,
) -> None:
    total_predictions = sum(prediction_counts.values())
    total_gt_contract_labels = sum(len(contracts) for contracts in gt_samples.values())
    overall_apl = (
        total_predictions / total_gt_contract_labels
        if total_gt_contract_labels
        else 0.0
    )

    lines: List[str] = []
    lines.append("# APL Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append(f"Model output: `{model_csv}`")
    lines.append("")
    lines.append(f"Ground truth: `{gt_csv}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("- APL is computed per ground-truth label as the average number of model predictions per GT contract.")
    lines.append("- Formula: `APL(label) = total model predictions on contracts of that GT label / total GT contracts of that label`.")
    lines.append("- For each GT sample `(folder, file_name, label)`, every non-placeholder model prediction on that same contract is counted, regardless of whether the predicted label is correct or wrong.")
    lines.append("- The denominator is the number of unique `(folder, file_name, label)` contract-label samples in the ground truth.")
    lines.append("- Duplicate evidence rows for the same contract-label in ground truth are counted once in `GT Contracts`.")
    lines.append("- Placeholder prediction rows `(none)` and `(error)` are excluded.")
    lines.append("- Label aliases are normalized, e.g. `Reentrancy_Attack` -> `Reentrancy_Attacks`, `Front-Running` -> `Front-running_Attacks`, `other` -> `Other`.")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total model predictions counted against GT labels: {total_predictions}")
    lines.append(f"- Total GT contract-label samples: {total_gt_contract_labels}")
    lines.append(f"- Overall APL: {overall_apl:.6f}")
    lines.append("")
    lines.append("## APL By Label")
    lines.append("")
    lines.append("| Label | Total Predictions | GT Contracts | APL |")
    lines.append("|---|---:|---:|---:|")
    for row in rows:
        lines.append(
            f"| {row['label']} | {row['total_predictions']} | {row['gt_contracts']} | {row['APL']} |"
        )
    lines.append("")
    lines.append("Detailed prediction rows are in `apl_prediction_details.csv`; machine-readable summary is in `apl_by_label.csv`.")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate(rows: List[Dict[str, object]], gt_samples: Dict[str, Set[Tuple[str, str]]]) -> None:
    total_gt_contract_labels = sum(len(contracts) for contracts in gt_samples.values())
    if total_gt_contract_labels != 143:
        raise AssertionError(
            f"Expected 143 GT contract-label samples, got {total_gt_contract_labels}"
        )
    for row in rows:
        denominator = int(row["gt_contracts"])
        total_predictions = int(row["total_predictions"])
        expected = total_predictions / denominator if denominator else 0.0
        if abs(float(row["APL"]) - expected) > 0.000001:
            raise AssertionError(f"APL mismatch: {row}")


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
    gt_samples = build_gt_samples(args.gt_csv)
    predictions_by_contract = build_model_predictions(args.model_csv)
    rows, prediction_details, prediction_counts = build_summary_rows(
        gt_samples,
        predictions_by_contract,
    )
    validate(rows, gt_samples)

    write_by_label(rows, args.output_dir / "apl_by_label.csv")
    write_prediction_details(
        prediction_details,
        args.output_dir / "apl_prediction_details.csv",
    )
    write_report(
        rows=rows,
        prediction_counts=prediction_counts,
        gt_samples=gt_samples,
        model_csv=args.model_csv,
        gt_csv=args.gt_csv,
        output_path=args.output_dir / "apl_report.md",
    )
    print(f"Wrote {args.output_dir / 'apl_by_label.csv'}")
    print(f"Wrote {args.output_dir / 'apl_prediction_details.csv'}")
    print(f"Wrote {args.output_dir / 'apl_report.md'}")


if __name__ == "__main__":
    main()
