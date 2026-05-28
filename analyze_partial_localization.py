#!/usr/bin/env python3
"""Generate RQ3 Partial Localization analysis from JSON model outputs."""

import argparse
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from analyze_localization_drift import (
    JsonResult,
    Prediction,
    closest_thinking_excerpt,
    format_prediction_list,
    has_tolerant_hit,
    minimum_distance,
    read_json_results,
    read_solidity_lines,
    snippet_for_lines,
)
from evaluate_tlr import build_ground_truth, format_lines


TOLERANCE = 3


@dataclass
class FunctionRegion:
    name: str
    start: int
    end: int
    text: str


@dataclass
class PartialCase:
    folder: str
    file_name: str
    label: str
    gt_lines: Set[int]
    predictions: List[Prediction]
    json_result: JsonResult
    hit_gt_lines: Set[int]
    missed_gt_lines: Set[int]
    predicted_lines: Set[int]
    gt_functions: Set[str]
    predicted_functions: Set[str]
    reason: str
    min_distance: Optional[int]


def parse_function_regions(lines: List[str]) -> List[FunctionRegion]:
    regions: List[FunctionRegion] = []
    idx = 0
    while idx < len(lines):
        line = lines[idx]
        if not re.search(r"\b(function|constructor)\b", line):
            idx += 1
            continue

        start = idx + 1
        header_lines = [line]
        open_line = idx
        while "{" not in "\n".join(header_lines) and open_line + 1 < len(lines):
            open_line += 1
            header_lines.append(lines[open_line])

        header = " ".join(header_lines)
        name_match = re.search(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)", header)
        if name_match:
            name = name_match.group(1)
        elif "constructor" in header:
            name = "constructor"
        else:
            name = "fallback"

        brace_depth = 0
        end = open_line + 1
        found_open = False
        for scan_idx in range(idx, len(lines)):
            brace_depth += lines[scan_idx].count("{")
            if lines[scan_idx].count("{"):
                found_open = True
            brace_depth -= lines[scan_idx].count("}")
            end = scan_idx + 1
            if found_open and brace_depth <= 0:
                break

        text = "\n".join(lines[start - 1 : end])
        regions.append(FunctionRegion(name=name, start=start, end=end, text=text))
        idx = max(idx + 1, end)

    return regions


def function_for_line(regions: List[FunctionRegion], line_no: int) -> Optional[str]:
    for region in regions:
        if region.start <= line_no <= region.end:
            return region.name
    return None


def functions_for_lines(regions: List[FunctionRegion], target_lines: Iterable[int]) -> Set[str]:
    names = set()
    for line_no in target_lines:
        name = function_for_line(regions, line_no)
        if name:
            names.add(name)
    return names


def build_call_pairs(regions: List[FunctionRegion]) -> Set[Tuple[str, str]]:
    function_names = {region.name for region in regions}
    pairs: Set[Tuple[str, str]] = set()
    for region in regions:
        for candidate in function_names:
            if candidate == region.name:
                continue
            if re.search(rf"\b{re.escape(candidate)}\s*\(", region.text):
                pairs.add((region.name, candidate))
    return pairs


def hit_gt_lines(gt_lines: Set[int], predicted_lines: Set[int]) -> Set[int]:
    return {
        gt_line
        for gt_line in gt_lines
        if any(abs(predicted_line - gt_line) <= TOLERANCE for predicted_line in predicted_lines)
    }


def is_directly_related_function(
    gt_functions: Set[str],
    predicted_functions: Set[str],
    call_pairs: Set[Tuple[str, str]],
) -> bool:
    if gt_functions & predicted_functions:
        return True
    for gt_function in gt_functions:
        for predicted_function in predicted_functions:
            if (gt_function, predicted_function) in call_pairs or (
                predicted_function,
                gt_function,
            ) in call_pairs:
                return True
    return False


def classify_partial_reason(
    gt_lines: Set[int],
    predicted_lines: Set[int],
    hit_lines: Set[int],
    gt_functions: Set[str],
    predicted_functions: Set[str],
    call_pairs: Set[Tuple[str, str]],
) -> Optional[str]:
    if not predicted_lines:
        return None

    if hit_lines and hit_lines != gt_lines:
        return "Model hit một phần GT lines nhưng bỏ sót phần còn lại của phạm vi lỗi."

    if hit_lines == gt_lines:
        return None

    if gt_functions & predicted_functions:
        shared = ", ".join(sorted(gt_functions & predicted_functions))
        return f"Model đúng function `{shared}` nhưng evidence line không trúng GT trong ±{TOLERANCE}."

    if is_directly_related_function(gt_functions, predicted_functions, call_pairs):
        return "Model highlight function caller/callee trực tiếp của vùng GT, nên đúng một phần luồng thực thi nhưng sai dòng annotate."

    return None


def classify_samples(
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    results_by_contract: Dict[Tuple[str, str], JsonResult],
    dataset_dir: Path,
) -> Tuple[List[PartialCase], Counter, Counter, Counter, Counter]:
    partial_cases: List[PartialCase] = []
    gt_by_label: Counter = Counter()
    correct_label_by_label: Counter = Counter()
    partial_by_label: Counter = Counter()
    complete_by_label: Counter = Counter()

    region_cache: Dict[Tuple[str, str], Tuple[List[str], List[FunctionRegion], Set[Tuple[str, str]]]] = {}

    for folder, file_name, label in sorted(gt_samples):
        gt_lines = set(gt_samples[(folder, file_name, label)])
        gt_by_label[label] += 1
        result = results_by_contract.get((folder, file_name))
        if not result:
            continue

        matching_predictions = [
            prediction for prediction in result.vulnerabilities if prediction.label == label
        ]
        if not matching_predictions:
            continue

        correct_label_by_label[label] += 1
        predicted_lines: Set[int] = set()
        for prediction in matching_predictions:
            predicted_lines.update(prediction.lines)

        if not predicted_lines:
            continue

        cache_key = (folder, file_name)
        if cache_key not in region_cache:
            solidity_lines = read_solidity_lines(dataset_dir, folder, file_name)
            regions = parse_function_regions(solidity_lines)
            region_cache[cache_key] = (solidity_lines, regions, build_call_pairs(regions))
        _, regions, call_pairs = region_cache[cache_key]

        hits = hit_gt_lines(gt_lines, predicted_lines)
        missed = gt_lines - hits
        if hits == gt_lines:
            complete_by_label[label] += 1
            continue

        gt_functions = functions_for_lines(regions, gt_lines)
        predicted_functions = functions_for_lines(regions, predicted_lines)
        reason = classify_partial_reason(
            gt_lines=gt_lines,
            predicted_lines=predicted_lines,
            hit_lines=hits,
            gt_functions=gt_functions,
            predicted_functions=predicted_functions,
            call_pairs=call_pairs,
        )
        if not reason:
            continue

        partial_by_label[label] += 1
        partial_cases.append(
            PartialCase(
                folder=folder,
                file_name=file_name,
                label=label,
                gt_lines=gt_lines,
                predictions=matching_predictions,
                json_result=result,
                hit_gt_lines=hits,
                missed_gt_lines=missed,
                predicted_lines=predicted_lines,
                gt_functions=gt_functions,
                predicted_functions=predicted_functions,
                reason=reason,
                min_distance=minimum_distance(gt_lines, predicted_lines),
            )
        )

    return (
        partial_cases,
        gt_by_label,
        correct_label_by_label,
        partial_by_label,
        complete_by_label,
    )


def partial_rate(partial_count: int, correct_label_count: int) -> str:
    if not correct_label_count:
        return "0.00%"
    return f"{partial_count / correct_label_count * 100:.2f}%"


def choose_examples(cases: List[PartialCase], limit: int = 5) -> List[PartialCase]:
    preferred_labels = [
        "Reentrancy_Attacks",
        "Access_Control",
        "Unchecked_External_Calls",
        "Denial_of_Service_Attacks",
        "Arithmetic",
        "Insecure_Randomness",
        "Time_Manipulation",
    ]
    by_label: Dict[str, List[PartialCase]] = defaultdict(list)
    for case in sorted(
        cases,
        key=lambda item: (
            0 if item.hit_gt_lines else 1,
            item.label,
            item.folder,
            item.file_name,
        ),
    ):
        by_label[case.label].append(case)

    examples: List[PartialCase] = []
    used: Set[Tuple[str, str, str]] = set()
    for label in preferred_labels:
        if by_label.get(label):
            case = by_label[label][0]
            key = (case.folder, case.file_name, case.label)
            if key not in used:
                examples.append(case)
                used.add(key)
            if len(examples) >= limit:
                return examples

    for case in sorted(
        cases,
        key=lambda item: (
            0 if item.hit_gt_lines else 1,
            item.label,
            item.folder,
            item.file_name,
        ),
    ):
        key = (case.folder, case.file_name, case.label)
        if key in used:
            continue
        examples.append(case)
        used.add(key)
        if len(examples) >= limit:
            break
    return examples


def write_report(
    output_path: Path,
    results_dir: Path,
    gt_csv: Path,
    dataset_dir: Path,
    partial_cases: List[PartialCase],
    gt_by_label: Counter,
    correct_label_by_label: Counter,
    partial_by_label: Counter,
    complete_by_label: Counter,
    result_count: int,
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    labels = sorted(gt_by_label)
    total_gt = sum(gt_by_label.values())
    total_correct = sum(correct_label_by_label.values())
    total_partial = sum(partial_by_label.values())
    total_complete = sum(complete_by_label.values())

    lines: List[str] = []
    lines.append("# Partial Localization Analysis - LOGs/my_results_l5")
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
        f"Một **Partial Localization** được tính khi model dự đoán đúng label, nhưng không cover đủ toàn bộ GT evidence trong tolerance `±{TOLERANCE}` và vẫn có tín hiệu định vị liên quan: hit một phần GT, cùng function với GT, hoặc nằm trong quan hệ caller/callee trực tiếp."
    )
    lines.append("")
    lines.append("Các case không có correct-label prediction không được tính ở đây vì thuộc Detection Failure/Misclassification.")
    lines.append("")
    lines.append("## Tổng quan")
    lines.append("")
    lines.append(f"- Số JSON result được đọc: {result_count}")
    lines.append(f"- Số ground-truth contract-label instances: {total_gt}")
    lines.append(f"- Số instances có correct-label prediction: {total_correct}")
    lines.append(f"- Số complete localization trong correct-label predictions: {total_complete}")
    lines.append(f"- Số Partial Localization: {total_partial}")
    lines.append(
        f"- Kết luận: **{'Có' if total_partial else 'Không'}**. Mô hình có trường hợp chỉ xác định đúng một phần phạm vi lỗi, ví dụ đúng luồng/hàm nhưng sai hoặc thiếu dòng cụ thể."
    )
    lines.append("")
    lines.append("## Partial Localization theo từng loại lỗ hổng")
    lines.append("")
    lines.append("| Label | GT samples | Correct-label predictions | Complete localization | Partial localization | Partial rate trên correct-label |")
    lines.append("|---|---:|---:|---:|---:|---:|")
    for label in labels:
        lines.append(
            f"| {label} | {gt_by_label[label]} | {correct_label_by_label[label]} | {complete_by_label[label]} | {partial_by_label[label]} | {partial_rate(partial_by_label[label], correct_label_by_label[label])} |"
        )
    lines.append(
        f"| **Overall** | **{total_gt}** | **{total_correct}** | **{total_complete}** | **{total_partial}** | **{partial_rate(total_partial, total_correct)}** |"
    )
    lines.append("")
    lines.append("## Phân tích theo nhóm lỗ hổng")
    lines.append("")
    partial_labels = [label for label in labels if partial_by_label[label] > 0]
    if partial_labels:
        for label in partial_labels:
            cases = [case for case in partial_cases if case.label == label]
            partial_hit = sum(1 for case in cases if case.hit_gt_lines)
            same_scope = len(cases) - partial_hit
            lines.append(f"### {label}")
            lines.append("")
            lines.append(
                f"- Có {partial_by_label[label]}/{correct_label_by_label[label]} correct-label predictions bị Partial Localization."
            )
            lines.append(f"- {partial_hit} case hit một phần GT lines nhưng bỏ sót GT lines khác.")
            lines.append(f"- {same_scope} case không hit GT line nhưng vẫn nằm trong cùng function hoặc caller/callee trực tiếp.")
            lines.append(
                "- Xu hướng: model thường nhận đúng cơ chế lỗi, nhưng evidence chỉ trỏ vào sink/call phụ hoặc một line đại diện, không bao phủ toàn bộ phạm vi annotation."
            )
            lines.append("")
    else:
        lines.append("Không tìm thấy Partial Localization theo định nghĩa đã nêu.")
        lines.append("")

    lines.append("## Dẫn chứng cụ thể")
    lines.append("")
    examples = choose_examples(partial_cases, limit=5)
    for idx, case in enumerate(examples, start=1):
        solidity_lines = read_solidity_lines(dataset_dir, case.folder, case.file_name)
        lines.append(f"### Dẫn chứng {idx} - {case.label} trong `{case.folder}/{case.file_name}`")
        lines.append("")
        lines.append(f"- JSON: `{case.json_result.path}`")
        lines.append(f"- Ground truth: `{case.label}`, evidence `{format_lines(case.gt_lines)}`")
        lines.append(f"- Model output đúng label: {format_prediction_list(case.predictions)}")
        lines.append(f"- GT lines hit trong ±{TOLERANCE}: `{format_lines(case.hit_gt_lines) or 'none'}`")
        lines.append(f"- GT lines bị miss: `{format_lines(case.missed_gt_lines) or 'none'}`")
        lines.append(f"- GT function(s): `{', '.join(sorted(case.gt_functions)) or 'unknown'}`")
        lines.append(f"- Model-highlighted function(s): `{', '.join(sorted(case.predicted_functions)) or 'unknown'}`")
        if case.min_distance is not None:
            lines.append(f"- Min distance model evidence tới GT: `{case.min_distance}` line(s)")
        lines.append(f"- Lý do Partial Localization: {case.reason}")
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
        lines.append(snippet_for_lines(solidity_lines, case.predicted_lines))
        lines.append("```")
        lines.append("")
        lines.append("Trích/paraphrase từ thinking_process:")
        lines.append("")
        lines.append(f"> {closest_thinking_excerpt(case.json_result.thinking_process, case.predictions)}")
        lines.append("")
        lines.append(
            "Giải thích: model đã phát hiện đúng label và bám vào một phần luồng/phạm vi lỗi, nhưng evidence chưa bao phủ đúng toàn bộ dòng GT. Đây là định vị một phần, không phải phát hiện hoàn chỉnh."
        )
        lines.append("")

    lines.append("## Kết luận")
    lines.append("")
    lines.append(
        "Có Partial Localization trong output `my_results_l5`: model thường hiểu đúng loại lỗi, nhưng evidence line chỉ phản ánh một phần nguyên nhân hoặc một line đại diện. Khi dùng kết quả để audit thủ công, các case này vẫn hữu ích hơn detection failure, nhưng cần mở rộng kiểm tra quanh function/luồng liên quan để không bỏ sót dòng GT."
    )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=Path("LOGs/my_results_l5"))
    parser.add_argument("--gt-csv", type=Path, default=Path("Description/smartbugs_dataset.csv"))
    parser.add_argument("--dataset-dir", type=Path, default=Path("smartbugs_dataset"))
    parser.add_argument("--output", type=Path, default=Path("RQ3/PartialLocalization.md"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    gt_samples = build_ground_truth(args.gt_csv)
    results_by_contract = read_json_results(args.results_dir)
    (
        partial_cases,
        gt_by_label,
        correct_label_by_label,
        partial_by_label,
        complete_by_label,
    ) = classify_samples(gt_samples, results_by_contract, args.dataset_dir)
    write_report(
        output_path=args.output,
        results_dir=args.results_dir,
        gt_csv=args.gt_csv,
        dataset_dir=args.dataset_dir,
        partial_cases=partial_cases,
        gt_by_label=gt_by_label,
        correct_label_by_label=correct_label_by_label,
        partial_by_label=partial_by_label,
        complete_by_label=complete_by_label,
        result_count=len(results_by_contract),
    )
    print(f"Wrote {args.output}")
    print(f"JSON results: {len(results_by_contract)}")
    print(f"Partial localization cases: {len(partial_cases)}")


if __name__ == "__main__":
    main()
