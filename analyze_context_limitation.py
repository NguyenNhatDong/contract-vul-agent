#!/usr/bin/env python3
"""Generate RQ3 Context Limitation analysis for cross-function dependencies."""

import argparse
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Set, Tuple

from analyze_localization_drift import (
    JsonResult,
    format_prediction_list,
    read_json_results,
    read_solidity_lines,
    snippet_for_lines,
)
from analyze_semantic_misunderstanding import excerpt_around_terms
from evaluate_tlr import build_ground_truth, format_lines


@dataclass
class ContextCaseSpec:
    folder: str
    file_name: str
    label: str
    dependency_type: str
    dependency_path: str
    focus_lines: Set[int]
    search_terms: List[str]
    context_limitation: str
    correct_cross_function_reading: str
    impact: str


CONTEXT_CASES: List[ContextCaseSpec] = [
    ContextCaseSpec(
        folder="reentrancy",
        file_name="modifier_reentrancy.sol",
        label="Reentrancy_Attacks",
        dependency_type="Modifier + cross-contract callback",
        dependency_path="attack.call -> ModifierEntrancy.airDrop -> supportsToken modifier -> attack.supportsToken -> ModifierEntrancy.airDrop",
        focus_lines={15, 21, 40, 42, 43},
        search_terms=[
            "airDrop has hasNoBalance and supportsToken",
            "Bank(msg.sender).supportsToken()",
            "attack contract",
            "no vulnerability",
        ],
        context_limitation=(
            "Model phân tích `airDrop`, modifier `supportsToken`, `Bank`, và contract `attack` thành từng mảnh, "
            "nhưng không dựng được call chain quay lại `airDrop` trước khi body cập nhật `tokenBalance`."
        ),
        correct_cross_function_reading=(
            "Lỗ hổng nằm ở tương tác nhiều thành phần: modifier gọi external contract dựa trên `msg.sender`, "
            "contract attacker lợi dụng callback để gọi lại `airDrop` trước khi trạng thái được cập nhật."
        ),
        impact="Model trả `Normal`, bỏ lỡ hoàn toàn reentrancy do phụ thuộc chéo giữa modifier và contract attacker.",
    ),
    ContextCaseSpec(
        folder="reentrancy",
        file_name="reentrancy_bonus.sol",
        label="Reentrancy_Attacks",
        dependency_type="Caller/callee state dependency",
        dependency_path="getFirstWithdrawalBonus -> withdrawReward -> recipient fallback -> getFirstWithdrawalBonus",
        focus_lines={19, 24, 26, 28, 29},
        search_terms=[
            "withdrawReward",
            "getFirstWithdrawalBonus",
            "claimedBonus",
            "Evidence: Line 19",
        ],
        context_limitation=(
            "Model nhận ra external call trong `withdrawReward` nhưng evidence và giải thích tập trung vào callee, "
            "trong khi guard quyết định nằm ở caller `getFirstWithdrawalBonus`."
        ),
        correct_cross_function_reading=(
            "Phải nối hai hàm: `getFirstWithdrawalBonus` kiểm tra `claimedBonus`, gọi `withdrawReward`, "
            "rồi chỉ set `claimedBonus = true` sau external call trong callee."
        ),
        impact="Model đúng label nhưng chỉ định vị một phần, bỏ sót dependency caller/callee tạo ra reentrancy.",
    ),
    ContextCaseSpec(
        folder="access_control",
        file_name="wallet_03_wrong_constructor.sol",
        label="Access_Control",
        dependency_type="Initializer then privileged function",
        dependency_path="attacker -> initWallet -> creator = attacker -> migrateTo",
        focus_lines={19, 20, 36, 37, 38},
        search_terms=[
            "function initWallet() public",
            "creator = msg.sender",
            "migrate",
            "That seems fine",
        ],
        context_limitation=(
            "Model nhìn `migrateTo` có `require(creator == msg.sender)` và coi là an toàn, "
            "nhưng không nối được rằng `creator` có thể bị chiếm trước đó qua initializer public."
        ),
        correct_cross_function_reading=(
            "Access-control bug chỉ hiện ra khi xét lifecycle nhiều bước: gọi `initWallet()` trước để đặt `creator`, "
            "sau đó gọi `migrateTo()` với quyền vừa chiếm."
        ),
        impact="Model bỏ `Access_Control` và chuyển sang `Arithmetic`.",
    ),
    ContextCaseSpec(
        folder="access_control",
        file_name="parity_wallet_bug_2.sol",
        label="Access_Control",
        dependency_type="Library initialization + privileged actions",
        dependency_path="initWallet/initMultiowned -> owner set -> kill/execute/onlymanyowners flow",
        focus_lines={226, 227, 228, 233, 234, 241},
        search_terms=[
            "initWallet",
            "only_uninitialized",
            "kill",
            "execute function",
        ],
        context_limitation=(
            "Model nhận một số hàm nhạy cảm nhưng tập trung sai vào `execute`, "
            "thay vì nối initialization flow với các hàm đặc quyền như `kill`."
        ),
        correct_cross_function_reading=(
            "Bug access control phụ thuộc vào luồng khởi tạo nhiều hàm trong wallet library: khi initialization bị gọi sai/ngữ cảnh proxy-library, "
            "quyền owner/manyowners ảnh hưởng trực tiếp tới `kill` và các hành động đặc quyền."
        ),
        impact="Model dự đoán `Access_Control` nhưng evidence trôi sang `execute`, không nắm đúng dependency init -> privileged action.",
    ),
    ContextCaseSpec(
        folder="front_running",
        file_name="eth_tx_order_dependence_minimal.sol",
        label="Front-running_Attacks",
        dependency_type="Cross-transaction function dependency",
        dependency_path="owner.setReward transaction <-> attacker.claimReward transaction",
        focus_lines={19, 23, 24, 28, 31, 32},
        search_terms=[
            "setReward function",
            "claimReward function",
            "transaction",
            "Reentrancy Attacks",
        ],
        context_limitation=(
            "Model đọc từng hàm như một call stack nội bộ và kéo về reentrancy, "
            "nhưng không mô hình hóa dependency giữa hai giao dịch gọi hai hàm khác nhau."
        ),
        correct_cross_function_reading=(
            "Front-running nằm ở tương tác cross-function/cross-transaction: reward được set trong `setReward`, "
            "và một giao dịch `claimReward` có thể chen thứ tự để nhận reward không đúng kỳ vọng."
        ),
        impact="Model dự đoán `Reentrancy_Attacks`, bỏ nhãn `Front-running_Attacks`.",
    ),
]


def prediction_summary(result: JsonResult) -> str:
    if not result.vulnerabilities:
        return f"`status: {result.status}`, `vulnerabilities_count: 0`"
    return (
        f"`status: {result.status}`, `vulnerabilities_count: {len(result.vulnerabilities)}`; "
        + format_prediction_list(result.vulnerabilities)
    )


def existing_cases(
    specs: List[ContextCaseSpec],
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    results_by_contract: Dict[Tuple[str, str], JsonResult],
) -> List[Tuple[ContextCaseSpec, Set[int], JsonResult]]:
    cases: List[Tuple[ContextCaseSpec, Set[int], JsonResult]] = []
    for spec in specs:
        gt_lines = gt_samples.get((spec.folder, spec.file_name, spec.label), set())
        result = results_by_contract.get((spec.folder, spec.file_name))
        if gt_lines and result:
            cases.append((spec, gt_lines, result))
    return cases


def dependency_by_label(cases: List[Tuple[ContextCaseSpec, Set[int], JsonResult]]) -> Dict[str, str]:
    grouped: Dict[str, List[str]] = {}
    for spec, _, _ in cases:
        grouped.setdefault(spec.label, []).append(spec.dependency_type)
    return {
        label: "; ".join(sorted(set(types)))
        for label, types in grouped.items()
    }


def write_report(
    output_path: Path,
    results_dir: Path,
    gt_csv: Path,
    dataset_dir: Path,
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    result_count: int,
    cases: List[Tuple[ContextCaseSpec, Set[int], JsonResult]],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    gt_by_label = Counter(label for _, _, label in gt_samples)
    context_by_label = Counter(spec.label for spec, _, _ in cases)
    dependencies = dependency_by_label(cases)

    lines: List[str] = []
    lines.append("# Context Limitation Analysis - LOGs/my_results_l5")
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
        "Báo cáo này truy vết **Context Limitation**: các lỗi phát sinh khi vulnerability chỉ rõ nếu nối nhiều hàm, modifier, contract, hoặc nhiều transaction lại với nhau. Trọng tâm là **Cross-function dependency**, không phải lỗi một dòng đơn lẻ."
    )
    lines.append("")
    lines.append(
        "Một case được tính khi `thinking_process`/model output cho thấy model phân tích cục bộ từng hàm hoặc từng sink, nhưng không dựng đủ dependency path giữa các hàm nên bỏ lỡ label, sai label, hoặc định vị sai."
    )
    lines.append("")
    lines.append("## Tổng quan")
    lines.append("")
    lines.append(f"- Số JSON result được đọc: {result_count}")
    lines.append(f"- Số ground-truth contract-label instances: {len(gt_samples)}")
    lines.append(f"- Số Context Limitation cases được truy vết chi tiết: {len(cases)}")
    lines.append("- Kết luận: **Có**. Một phần lỗi phát sinh vì lỗ hổng nằm ở tương tác giữa nhiều hàm/contract/transaction, vượt quá phân tích cục bộ từng dòng.")
    lines.append("")
    lines.append("## Context Limitation theo từng loại lỗ hổng")
    lines.append("")
    lines.append("| Label | GT samples | Traced context-limitation cases | Cross-function dependency nổi bật |")
    lines.append("|---|---:|---:|---|")
    for label in sorted(gt_by_label):
        lines.append(
            f"| {label} | {gt_by_label[label]} | {context_by_label[label]} | {dependencies.get(label, 'Không thấy case cross-function rõ trong 5 dẫn chứng')} |"
        )
    lines.append("")
    lines.append("## Phân tích theo nhóm")
    lines.append("")
    for label in sorted(label for label in context_by_label if context_by_label[label] > 0):
        label_cases = [spec for spec, _, _ in cases if spec.label == label]
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"- Số case truy vết: {len(label_cases)}")
        lines.append(f"- Dạng phụ thuộc: {', '.join(sorted({case.dependency_type for case in label_cases}))}.")
        lines.append(
            "- Nhận xét: model thường thấy một phần tín hiệu trong từng hàm, nhưng không nối đủ dependency path nên kết quả cuối sai hoặc chưa đầy đủ."
        )
        lines.append("")
    lines.append("## Dẫn chứng cụ thể")
    lines.append("")
    for idx, (spec, gt_lines, result) in enumerate(cases[:5], start=1):
        solidity_lines = read_solidity_lines(dataset_dir, spec.folder, spec.file_name)
        lines.append(f"### Dẫn chứng {idx} - {spec.label} trong `{spec.folder}/{spec.file_name}`")
        lines.append("")
        lines.append(f"- JSON: `{result.path}`")
        lines.append(f"- Ground truth: `{spec.label}`, evidence `{format_lines(gt_lines)}`")
        lines.append(f"- Model output: {prediction_summary(result)}")
        lines.append(f"- Dạng context limitation: `{spec.dependency_type}`")
        lines.append(f"- Dependency path cần theo dõi: `{spec.dependency_path}`")
        lines.append("")
        lines.append("Ground-truth snippet:")
        lines.append("")
        lines.append("```solidity")
        lines.append(snippet_for_lines(solidity_lines, gt_lines))
        lines.append("```")
        lines.append("")
        lines.append("Code region thể hiện phụ thuộc chéo hàm:")
        lines.append("")
        lines.append("```solidity")
        lines.append(snippet_for_lines(solidity_lines, spec.focus_lines))
        lines.append("```")
        lines.append("")
        lines.append("Trích/paraphrase từ thinking_process:")
        lines.append("")
        lines.append(f"> {excerpt_around_terms(result.thinking_process, spec.search_terms)}")
        lines.append("")
        lines.append(f"Giới hạn ngữ cảnh của model: {spec.context_limitation}")
        lines.append("")
        lines.append(f"Cách đọc đúng theo cross-function dependency: {spec.correct_cross_function_reading}")
        lines.append("")
        lines.append(f"Hậu quả: {spec.impact}")
        lines.append("")
    lines.append("## Kết luận")
    lines.append("")
    lines.append(
        "Có bằng chứng Context Limitation trong `my_results_l5`: một số lỗi không nằm ở một dòng đơn lẻ mà ở quan hệ giữa modifier, caller/callee, initializer/privileged function, hoặc transaction order. Model có xu hướng phân tích từng hàm riêng lẻ, nên dễ bỏ qua dependency path tạo ra vulnerability."
    )
    lines.append("")
    lines.append(
        "Khi đánh giá các contract có nhiều hàm tương tác, nên bổ sung kiểm tra call graph/lifecycle thủ công hoặc prompt yêu cầu model dựng explicit execution path trước khi kết luận vulnerability."
    )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=Path("LOGs/my_results_l5"))
    parser.add_argument("--gt-csv", type=Path, default=Path("Description/smartbugs_dataset.csv"))
    parser.add_argument("--dataset-dir", type=Path, default=Path("smartbugs_dataset"))
    parser.add_argument("--output", type=Path, default=Path("RQ3/ContextLimitation.md"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    gt_samples = build_ground_truth(args.gt_csv)
    results_by_contract = read_json_results(args.results_dir)
    cases = existing_cases(CONTEXT_CASES, gt_samples, results_by_contract)
    write_report(
        output_path=args.output,
        results_dir=args.results_dir,
        gt_csv=args.gt_csv,
        dataset_dir=args.dataset_dir,
        gt_samples=gt_samples,
        result_count=len(results_by_contract),
        cases=cases,
    )
    print(f"Wrote {args.output}")
    print(f"JSON results: {len(results_by_contract)}")
    print(f"Context limitation cases: {len(cases)}")


if __name__ == "__main__":
    main()
