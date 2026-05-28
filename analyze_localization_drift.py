#!/usr/bin/env python3
"""Generate RQ3 Localization Drift analysis from JSON model outputs."""

import argparse
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from evaluate_tlr import (
    PLACEHOLDER_EVIDENCE,
    build_ground_truth,
    format_lines,
    normalize_label,
)


TOLERANCE = 3
THINKING_EXCERPT_LIMIT = 520


@dataclass
class Prediction:
    label: str
    evidence: str
    lines: Set[int]
    function_name: str
    evidence_snippet: str


@dataclass
class JsonResult:
    path: Path
    folder: str
    file_name: str
    status: str
    vulnerabilities: List[Prediction]
    thinking_process: str
    error: Optional[str]


@dataclass
class DriftCase:
    folder: str
    file_name: str
    label: str
    gt_lines: Set[int]
    predictions: List[Prediction]
    json_result: JsonResult
    min_distance: Optional[int]


def json_result_paths(results_dir: Path) -> List[Path]:
    return sorted(
        path
        for path in results_dir.rglob("*.json")
        if path.name.startswith("result_")
        and path.name not in {"audit_summary.json", "overall_audit_summary.json"}
    )


def safe_load_json(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def result_file_name(path: Path, data: dict) -> str:
    contract_name = str(data.get("contract_name") or "").strip()
    if contract_name:
        return contract_name

    contract_path = str(data.get("contract_path") or "").strip()
    if contract_path:
        return Path(contract_path).name

    stem = path.stem
    if stem.startswith("result_"):
        stem = stem[len("result_") :]
    return f"{stem}.sol"


def read_json_results(results_dir: Path) -> Dict[Tuple[str, str], JsonResult]:
    results: Dict[Tuple[str, str], JsonResult] = {}
    for path in json_result_paths(results_dir):
        data = safe_load_json(path)
        if data is None:
            continue

        folder = path.parent.name
        file_name = result_file_name(path, data)
        predictions: List[Prediction] = []
        for item in data.get("vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            label = normalize_label(str(item.get("vulnerability_type") or ""))
            evidence = str(item.get("evidence") or "").strip()
            predictions.append(
                Prediction(
                    label=label,
                    evidence=evidence,
                    lines=parse_evidence_lines_flexible(evidence),
                    function_name=str(item.get("function_name") or "").strip(),
                    evidence_snippet=str(item.get("evidence_snippet") or "").strip(),
                )
            )

        results[(folder, file_name)] = JsonResult(
            path=path,
            folder=folder,
            file_name=file_name,
            status=str(data.get("status") or "").strip(),
            vulnerabilities=predictions,
            thinking_process=str(data.get("thinking_process") or "").strip(),
            error=data.get("error"),
        )
    return results


def expand_range(start: int, end: int, raw_end: str) -> Tuple[int, int]:
    """Expand ranges, including shorthand such as 522-23 -> 522-523."""
    if end < start and len(raw_end) < len(str(start)):
        prefix = str(start)[: -len(raw_end)]
        candidate = int(prefix + raw_end)
        if candidate >= start:
            end = candidate

    if start > end:
        start, end = end, start
    return start, end


def parse_evidence_lines_flexible(evidence: str) -> Set[int]:
    """Parse model evidence with commas, ranges, prose, and shorthand ranges."""
    raw = (evidence or "").strip()
    if raw.lower() in PLACEHOLDER_EVIDENCE:
        return set()

    lines: Set[int] = set()
    consumed_spans: List[Tuple[int, int]] = []
    for match in re.finditer(r"(\d+)\s*-\s*(\d+)", raw):
        start = int(match.group(1))
        raw_end = match.group(2)
        end = int(raw_end)
        start, end = expand_range(start, end, raw_end)
        lines.update(range(start, end + 1))
        consumed_spans.append(match.span())

    def in_consumed_span(index: int) -> bool:
        return any(start <= index < end for start, end in consumed_spans)

    for match in re.finditer(r"\d+", raw):
        if not in_consumed_span(match.start()):
            lines.add(int(match.group(0)))

    return lines


def has_tolerant_hit(gt_lines: Set[int], predicted_lines: Iterable[int]) -> bool:
    return any(
        abs(predicted_line - gt_line) <= TOLERANCE
        for predicted_line in predicted_lines
        for gt_line in gt_lines
    )


def minimum_distance(gt_lines: Set[int], predicted_lines: Iterable[int]) -> Optional[int]:
    distances = [
        abs(predicted_line - gt_line)
        for predicted_line in predicted_lines
        for gt_line in gt_lines
    ]
    return min(distances) if distances else None


def classify_samples(
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    results_by_contract: Dict[Tuple[str, str], JsonResult],
) -> Tuple[List[DriftCase], Counter, Counter, Counter, Counter]:
    drift_cases: List[DriftCase] = []
    gt_by_label: Counter = Counter()
    correct_label_by_label: Counter = Counter()
    drift_by_label: Counter = Counter()
    invalid_localization_by_label: Counter = Counter()

    for folder, file_name, label in sorted(gt_samples):
        gt_lines = set(gt_samples[(folder, file_name, label)])
        gt_by_label[label] += 1
        result = results_by_contract.get((folder, file_name))
        if not result:
            continue

        matching_predictions = [
            prediction
            for prediction in result.vulnerabilities
            if prediction.label == label
        ]
        if not matching_predictions:
            continue

        correct_label_by_label[label] += 1
        predicted_lines: Set[int] = set()
        for prediction in matching_predictions:
            predicted_lines.update(prediction.lines)

        if not predicted_lines:
            invalid_localization_by_label[label] += 1
            continue

        if has_tolerant_hit(gt_lines, predicted_lines):
            continue

        drift_by_label[label] += 1
        drift_cases.append(
            DriftCase(
                folder=folder,
                file_name=file_name,
                label=label,
                gt_lines=gt_lines,
                predictions=matching_predictions,
                json_result=result,
                min_distance=minimum_distance(gt_lines, predicted_lines),
            )
        )

    return (
        drift_cases,
        gt_by_label,
        correct_label_by_label,
        drift_by_label,
        invalid_localization_by_label,
    )


def read_solidity_lines(dataset_dir: Path, folder: str, file_name: str) -> List[str]:
    path = dataset_dir / folder / file_name
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def merge_ranges(ranges: List[Tuple[int, int]], gap: int = 2) -> List[Tuple[int, int]]:
    if not ranges:
        return []
    merged = [ranges[0]]
    for start, end in ranges[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end + gap:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def snippet_for_lines(lines: List[str], target_lines: Set[int], radius: int = 1) -> str:
    if not lines or not target_lines:
        return "(không có line hợp lệ)"

    ordered_targets = sorted(target_lines)
    ranges = merge_ranges(
        [
            (max(1, line_no - radius), min(len(lines), line_no + radius))
            for line_no in ordered_targets
        ]
    )
    snippet_lines = []
    for idx, (start, end) in enumerate(ranges):
        if idx:
            snippet_lines.append("  ...")
        for line_no in range(start, end + 1):
            marker = ">>" if line_no in target_lines else "  "
            snippet_lines.append(f"{marker} {line_no}: {lines[line_no - 1]}")
    return "\n".join(snippet_lines)


def closest_thinking_excerpt(thinking: str, predictions: List[Prediction]) -> str:
    clean = " ".join((thinking or "").split())
    if not clean:
        return "(thinking_process rỗng hoặc không có)"

    search_terms: List[str] = []
    for prediction in predictions:
        search_terms.extend(
            [
                prediction.function_name,
                prediction.evidence,
                prediction.label,
            ]
        )
    search_terms.extend(["line", "evidence", "vulnerab"])

    lower = clean.lower()
    best_index = -1
    for term in search_terms:
        term = (term or "").strip()
        if not term:
            continue
        best_index = lower.find(term.lower())
        if best_index >= 0:
            break

    if best_index < 0:
        best_index = 0

    start = max(0, best_index - 140)
    end = min(len(clean), start + THINKING_EXCERPT_LIMIT)
    excerpt = clean[start:end]
    if start > 0:
        excerpt = "..." + excerpt
    if end < len(clean):
        excerpt += "..."
    return excerpt


def format_prediction_list(predictions: List[Prediction]) -> str:
    parts = []
    for prediction in predictions:
        lines = format_lines(prediction.lines) if prediction.lines else "none"
        function = prediction.function_name or "unknown"
        snippet = prediction.evidence_snippet.replace("\n", " ").strip()
        if len(snippet) > 180:
            snippet = snippet[:177] + "..."
        parts.append(
            f"`{prediction.label}` evidence `{prediction.evidence}` (lines `{lines}`, function `{function}`), snippet: {snippet or '(none)'}"
        )
    return "<br>".join(parts)


def drift_rate(drift_count: int, correct_label_count: int) -> str:
    if not correct_label_count:
        return "0.00%"
    return f"{drift_count / correct_label_count * 100:.2f}%"


def choose_examples(drift_cases: List[DriftCase], limit: int = 5) -> List[DriftCase]:
    by_label: Dict[str, List[DriftCase]] = defaultdict(list)
    for case in sorted(
        drift_cases,
        key=lambda item: (
            -(item.min_distance or 0),
            item.label,
            item.folder,
            item.file_name,
        ),
    ):
        by_label[case.label].append(case)

    preferred_labels = [
        "Access_Control",
        "Reentrancy_Attacks",
        "Unchecked_External_Calls",
        "Arithmetic",
        "Denial_of_Service_Attacks",
        "Insecure_Randomness",
        "Time_Manipulation",
        "Front-running_Attacks",
    ]
    examples: List[DriftCase] = []
    used_keys: Set[Tuple[str, str, str]] = set()

    for label in preferred_labels:
        if by_label.get(label):
            case = by_label[label][0]
            key = (case.folder, case.file_name, case.label)
            if key not in used_keys:
                examples.append(case)
                used_keys.add(key)
            if len(examples) >= limit:
                return examples

    for case in sorted(
        drift_cases,
        key=lambda item: (
            -(item.min_distance or 0),
            item.label,
            item.folder,
            item.file_name,
        ),
    ):
        key = (case.folder, case.file_name, case.label)
        if key in used_keys:
            continue
        examples.append(case)
        used_keys.add(key)
        if len(examples) >= limit:
            break
    return examples


def write_report(
    output_path: Path,
    results_dir: Path,
    gt_csv: Path,
    dataset_dir: Path,
    drift_cases: List[DriftCase],
    gt_by_label: Counter,
    correct_label_by_label: Counter,
    drift_by_label: Counter,
    invalid_localization_by_label: Counter,
    result_count: int,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    labels = sorted(gt_by_label)
    total_gt = sum(gt_by_label.values())
    total_correct_label = sum(correct_label_by_label.values())
    total_drift = sum(drift_by_label.values())
    total_invalid = sum(invalid_localization_by_label.values())

    lines: List[str] = []
    lines.append("# Localization Drift Analysis - LOGs/my_results_l5")
    lines.append("")
    lines.append("## Mục tiêu và cách đánh giá")
    lines.append("")
    lines.append(f"Nguồn model output JSON: `{results_dir}`")
    lines.append("")
    lines.append(f"Solidity input: `{dataset_dir}`")
    lines.append("")
    lines.append(f"Ground truth: `{gt_csv}`")
    lines.append("")
    lines.append(
        "Một **Localization Drift** được tính khi model dự đoán đúng `vulnerability_type` cho contract, "
        f"nhưng tất cả evidence line của prediction đúng label đều nằm ngoài tolerance `±{TOLERANCE}` so với ground-truth vulnerable line."
    )
    lines.append("")
    lines.append("Các case không dự đoán đúng label được loại khỏi metric này vì thuộc Detection Failure/Misclassification. Các case đúng label nhưng evidence rỗng/placeholder được tách riêng thành `invalid localization`, không dùng làm dẫn chứng highlight sai dòng.")
    lines.append("")
    lines.append("## Tổng quan")
    lines.append("")
    lines.append(f"- Số JSON result được đọc: {result_count}")
    lines.append(f"- Số ground-truth contract-label instances: {total_gt}")
    lines.append(f"- Số instances có correct-label prediction: {total_correct_label}")
    lines.append(f"- Số Localization Drift: {total_drift}")
    lines.append(f"- Số correct-label prediction nhưng evidence không parse được: {total_invalid}")
    lines.append(
        f"- Kết luận: **{'Có' if total_drift else 'Không'}**. "
        "Mô hình có trường hợp chỉ ra đúng loại lỗi nhưng highlight sai dòng mã cụ thể."
    )
    lines.append("")
    lines.append("## Localization Drift theo từng loại lỗ hổng")
    lines.append("")
    lines.append("| Label | GT samples | Correct-label predictions | Drift cases | Drift rate trên correct-label | Invalid localization |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for label in labels:
        correct_count = correct_label_by_label[label]
        drift_count = drift_by_label[label]
        lines.append(
            f"| {label} | {gt_by_label[label]} | {correct_count} | {drift_count} | {drift_rate(drift_count, correct_count)} | {invalid_localization_by_label[label]} |"
        )
    lines.append(
        f"| **Overall** | **{total_gt}** | **{total_correct_label}** | **{total_drift}** | **{drift_rate(total_drift, total_correct_label)}** | **{total_invalid}** |"
    )
    lines.append("")
    lines.append("## Phân tích theo nhóm lỗ hổng")
    lines.append("")
    drift_labels = [label for label in labels if drift_by_label[label] > 0]
    if drift_labels:
        for label in drift_labels:
            cases = [case for case in drift_cases if case.label == label]
            distances = [case.min_distance for case in cases if case.min_distance is not None]
            max_distance = max(distances) if distances else "N/A"
            lines.append(f"### {label}")
            lines.append("")
            lines.append(
                f"- Có {drift_by_label[label]}/{correct_label_by_label[label]} correct-label predictions bị drift."
            )
            lines.append(f"- Khoảng cách line nhỏ nhất lớn nhất trong nhóm drift: `{max_distance}`.")
            lines.append(
                "- Xu hướng: model nhận đúng loại vulnerability nhưng evidence thường trỏ sang function lân cận, đoạn call/transfer phụ, hoặc vùng code giải thích nguyên nhân tổng quát thay vì dòng GT được annotate."
            )
            lines.append("")
    else:
        lines.append("Không tìm thấy Localization Drift theo định nghĩa ±3.")
        lines.append("")

    lines.append("## Dẫn chứng cụ thể")
    lines.append("")
    examples = choose_examples(drift_cases, limit=5)
    for idx, case in enumerate(examples, start=1):
        solidity_lines = read_solidity_lines(dataset_dir, case.folder, case.file_name)
        predicted_lines: Set[int] = set()
        for prediction in case.predictions:
            predicted_lines.update(prediction.lines)

        lines.append(f"### Dẫn chứng {idx} - {case.label} trong `{case.folder}/{case.file_name}`")
        lines.append("")
        lines.append(f"- JSON: `{case.json_result.path}`")
        lines.append(f"- Ground truth: `{case.label}`, evidence `{format_lines(case.gt_lines)}`")
        lines.append(f"- Model output đúng label: {format_prediction_list(case.predictions)}")
        lines.append(f"- Min distance giữa model evidence và GT: `{case.min_distance}` line(s), lớn hơn tolerance `±{TOLERANCE}`.")
        lines.append("")
        lines.append("GT code snippet:")
        lines.append("")
        lines.append("```solidity")
        lines.append(snippet_for_lines(solidity_lines, case.gt_lines))
        lines.append("```")
        lines.append("")
        lines.append("Model-highlighted snippet:")
        lines.append("")
        lines.append("```solidity")
        lines.append(snippet_for_lines(solidity_lines, predicted_lines))
        lines.append("```")
        lines.append("")
        lines.append("Trích/paraphrase từ thinking_process:")
        lines.append("")
        lines.append(f"> {closest_thinking_excerpt(case.json_result.thinking_process, case.predictions)}")
        lines.append("")
        lines.append(
            "Giải thích: model đã chọn đúng vulnerability type nhưng evidence được highlight không nằm trong vùng GT theo tolerance ±3. "
            "Vì vậy đây là lỗi định vị, không phải lỗi phát hiện label."
        )
        lines.append("")

    lines.append("## Kết luận")
    lines.append("")
    lines.append(
        "Có Localization Drift trong output `my_results_l5`: mô hình đôi khi hiểu đúng loại lỗi nhưng đặt evidence ở dòng khác với annotation. "
        "Điều này đặc biệt quan trọng khi dùng model như công cụ hỗ trợ auditor, vì auditor có thể bị dẫn tới vùng code không phải vị trí ground-truth cần kiểm tra."
    )
    lines.append("")
    lines.append(
        f"Với tolerance ±{TOLERANCE}, báo cáo này chỉ tính drift trên các mẫu có correct-label prediction; những lỗi không dự đoán đúng label vẫn nên đọc ở các báo cáo Detection Failure và Misclassification."
    )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=Path("LOGs/my_results_l5"))
    parser.add_argument("--gt-csv", type=Path, default=Path("Description/smartbugs_dataset.csv"))
    parser.add_argument("--dataset-dir", type=Path, default=Path("smartbugs_dataset"))
    parser.add_argument("--output", type=Path, default=Path("RQ3/LocalizationDrift.md"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    gt_samples = build_ground_truth(args.gt_csv)
    results_by_contract = read_json_results(args.results_dir)
    (
        drift_cases,
        gt_by_label,
        correct_label_by_label,
        drift_by_label,
        invalid_localization_by_label,
    ) = classify_samples(gt_samples, results_by_contract)

    write_report(
        output_path=args.output,
        results_dir=args.results_dir,
        gt_csv=args.gt_csv,
        dataset_dir=args.dataset_dir,
        drift_cases=drift_cases,
        gt_by_label=gt_by_label,
        correct_label_by_label=correct_label_by_label,
        drift_by_label=drift_by_label,
        invalid_localization_by_label=invalid_localization_by_label,
        result_count=len(results_by_contract),
    )
    print(f"Wrote {args.output}")
    print(f"JSON results: {len(results_by_contract)}")
    print(f"Localization drift cases: {len(drift_cases)}")


if __name__ == "__main__":
    main()
