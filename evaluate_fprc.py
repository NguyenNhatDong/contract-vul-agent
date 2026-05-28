#!/usr/bin/env python3
"""Evaluate False Positive Rate per Contract (FPR-C)."""

import argparse
import csv
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set, Tuple

from evaluate_tlr import PLACEHOLDER_TYPES, normalize_label, read_rows


ContractKey = Tuple[str, str]


def build_ground_truth(gt_csv: Path) -> Tuple[Dict[ContractKey, Set[str]], Dict[str, Set[ContractKey]]]:
    labels_by_contract: Dict[ContractKey, Set[str]] = defaultdict(set)
    contracts_by_label: Dict[str, Set[ContractKey]] = defaultdict(set)

    for row in read_rows(gt_csv):
        label = normalize_label(row.get("vulnerability_type", ""))
        if not label or label in PLACEHOLDER_TYPES:
            continue
        contract = (row.get("folder", ""), row.get("file_name", ""))
        labels_by_contract[contract].add(label)
        contracts_by_label[label].add(contract)

    return dict(labels_by_contract), dict(contracts_by_label)


def build_prediction_rows(model_csv: Path) -> Dict[ContractKey, List[str]]:
    predictions: Dict[ContractKey, List[str]] = defaultdict(list)
    for row in read_rows(model_csv):
        label = normalize_label(row.get("vulnerability_type", ""))
        if not label or label in PLACEHOLDER_TYPES:
            continue
        contract = (row.get("folder", ""), row.get("file_name", ""))
        predictions[contract].append(label)
    return dict(predictions)


def evaluate_false_positives(
    contracts_by_label: Dict[str, Set[ContractKey]],
    predictions_by_contract: Dict[ContractKey, List[str]],
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    detail_rows: List[Dict[str, object]] = []
    false_positive_counts_by_label: Dict[str, int] = defaultdict(int)

    for target_label in sorted(contracts_by_label):
        for contract in sorted(contracts_by_label[target_label]):
            for predicted_label in predictions_by_contract.get(contract, []):
                is_false_positive = predicted_label != target_label
                if is_false_positive:
                    false_positive_counts_by_label[target_label] += 1
                detail_rows.append(
                    {
                        "target_label": target_label,
                        "folder": contract[0],
                        "file_name": contract[1],
                        "predicted_label": predicted_label,
                        "is_false_positive_for_target_label": str(is_false_positive),
                    }
                )

    summary_rows: List[Dict[str, object]] = []
    labels = sorted(contracts_by_label)
    for label in labels:
        numerator = false_positive_counts_by_label[label]
        denominator = len(contracts_by_label[label])
        fprc = numerator / denominator if denominator else 0.0
        summary_rows.append(
            {
                "label": label,
                "sum_FP": numerator,
                "N_contracts_of_label": denominator,
                "FPR_C": f"{fprc:.6f}",
            }
        )

    return summary_rows, detail_rows


def write_by_label(rows: List[Dict[str, object]], path: Path) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["label", "sum_FP", "N_contracts_of_label", "FPR_C"],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_query_details(rows: List[Dict[str, object]], path: Path) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "target_label",
                "folder",
                "file_name",
                "predicted_label",
                "is_false_positive_for_target_label",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)


def write_report(
    rows: List[Dict[str, object]],
    model_csv: Path,
    gt_csv: Path,
    output_path: Path,
) -> None:
    total_fp = sum(int(row["sum_FP"]) for row in rows)
    total_n = sum(int(row["N_contracts_of_label"]) for row in rows)
    overall = total_fp / total_n if total_n else 0.0

    lines: List[str] = []
    lines.append("# FPR-C Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().isoformat()}")
    lines.append("")
    lines.append(f"Model output: `{model_csv}`")
    lines.append("")
    lines.append(f"Ground truth: `{gt_csv}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("- For each ground-truth label `L`, only contracts that belong to `L` in the ground truth are evaluated.")
    lines.append("- `Sum FP(L)` is the number of valid model prediction rows on those contracts where `predicted_label != L`.")
    lines.append("- Prediction rows are counted as rows, so repeated wrong predictions on the same contract still contribute to `Sum FP`.")
    lines.append("- For each label, `N` is the number of unique ground-truth contracts of that label.")
    lines.append("- Formula: `FPR-C(label) = Sum FP(label) / N(label)`.")
    lines.append("- Overall FPR-C uses the sum of per-label false positives divided by the sum of per-label GT contract counts.")
    lines.append("- Placeholder model rows `(none)` and `(error)` are ignored as vulnerability predictions.")
    lines.append("- Label aliases are normalized, e.g. `Front-Running` -> `Front-running_Attacks`, `Reentrancy_Attack` -> `Reentrancy_Attacks`, `other` -> `Other`.")
    lines.append("")
    lines.append("## Overall")
    lines.append("")
    lines.append(f"- Sum FP: {total_fp}")
    lines.append(f"- N contracts of labels: {total_n}")
    lines.append(f"- Overall FPR-C: {overall:.6f}")
    lines.append("")
    lines.append("## FPR-C By Label")
    lines.append("")
    lines.append("| Label | Sum FP | N Contracts Of Label | FPR-C |")
    lines.append("|---|---:|---:|---:|")
    for row in rows:
        lines.append(
            f"| {row['label']} | {row['sum_FP']} | {row['N_contracts_of_label']} | {row['FPR_C']} |"
        )
    lines.append("")
    lines.append("Detailed false-positive contracts are in `fprc_query_details.csv`; machine-readable summary is in `fprc_by_label.csv`.")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def validate(rows: List[Dict[str, object]]) -> None:
    total_n = sum(int(row["N_contracts_of_label"]) for row in rows)
    if total_n != 143:
        raise AssertionError(f"Expected total GT contract-label count 143, got {total_n}")
    for row in rows:
        numerator = int(row["sum_FP"])
        denominator = int(row["N_contracts_of_label"])
        expected = numerator / denominator if denominator else 0.0
        if abs(float(row["FPR_C"]) - expected) > 0.000001:
            raise AssertionError(f"FPR-C mismatch: {row}")


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

    labels_by_contract, contracts_by_label = build_ground_truth(args.gt_csv)
    predictions_by_contract = build_prediction_rows(args.model_csv)
    summary_rows, detail_rows = evaluate_false_positives(
        contracts_by_label,
        predictions_by_contract,
    )
    validate(summary_rows)

    write_by_label(summary_rows, args.output_dir / "fprc_by_label.csv")
    write_query_details(detail_rows, args.output_dir / "fprc_query_details.csv")
    write_report(
        summary_rows,
        args.model_csv,
        args.gt_csv,
        args.output_dir / "fprc_report.md",
    )

    print(f"Wrote {args.output_dir / 'fprc_by_label.csv'}")
    print(f"Wrote {args.output_dir / 'fprc_query_details.csv'}")
    print(f"Wrote {args.output_dir / 'fprc_report.md'}")


if __name__ == "__main__":
    main()
