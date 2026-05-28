#!/usr/bin/env python3
"""Generate RQ3 Semantic Misunderstanding analysis from JSON model outputs."""

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
from evaluate_tlr import build_ground_truth, format_lines


@dataclass
class SemanticCaseSpec:
    folder: str
    file_name: str
    label: str
    issue_type: str
    focus_lines: Set[int]
    search_terms: List[str]
    model_misunderstanding: str
    correct_semantics: str
    impact: str


SEMANTIC_CASES: List[SemanticCaseSpec] = [
    SemanticCaseSpec(
        folder="reentrancy",
        file_name="modifier_reentrancy.sol",
        label="Reentrancy_Attacks",
        issue_type="Modifier/external-call order",
        focus_lines={15, 21, 42, 43},
        search_terms=[
            "airDrop has hasNoBalance and supportsToken",
            "Bank(msg.sender).supportsToken()",
            "attack.supportsToken",
            "there is no vulnerability",
        ],
        model_misunderstanding=(
            "Model thấy `supportsToken` là external call trong modifier nhưng bị rối ở dynamic dispatch "
            "`Bank(msg.sender).supportsToken()`, rồi kết luận không có reentrancy."
        ),
        correct_semantics=(
            "Khi sender là contract `attack`, lời gọi interface tới `supportsToken()` có thể chạy code của attacker "
            "trước khi thân `airDrop` cập nhật `tokenBalance`, nên call order trong modifier là điểm nguy hiểm."
        ),
        impact="Output `Normal`, bỏ lỡ hoàn toàn `Reentrancy_Attacks`.",
    ),
    SemanticCaseSpec(
        folder="reentrancy",
        file_name="reentrancy_bonus.sol",
        label="Reentrancy_Attacks",
        issue_type="Caller/callee state-update order",
        focus_lines={19, 28, 29},
        search_terms=[
            "rewardsForA[recipient] = 0",
            "claimedBonus[recipient] = true",
            "before withdrawReward completes",
            "Evidence: Line 19",
        ],
        model_misunderstanding=(
            "Model nhận đúng reentrancy nhưng gom nhầm thứ tự state update giữa `withdrawReward` và caller "
            "`getFirstWithdrawalBonus`, rồi chỉ highlight sink line 19."
        ),
        correct_semantics=(
            "`rewardsForA` được reset trong callee trước external call, còn guard quan trọng `claimedBonus` "
            "chỉ được set ở caller sau khi `withdrawReward(recipient)` hoàn tất."
        ),
        impact="Model đúng label nhưng định vị/diễn giải chưa đúng phạm vi call order của lỗi.",
    ),
    SemanticCaseSpec(
        folder="access_control",
        file_name="wallet_03_wrong_constructor.sol",
        label="Access_Control",
        issue_type="Initializer/lifecycle order",
        focus_lines={18, 20, 36, 37, 38},
        search_terms=[
            "function initWallet() public",
            "creator = msg.sender",
            "Access control: the migrate function requires creator == msg.sender",
            "That seems fine",
        ],
        model_misunderstanding=(
            "Model xem `require(creator == msg.sender)` trong `migrateTo` như guard an toàn tại thời điểm gọi, "
            "nhưng không nối nó với việc `initWallet()` public có thể được gọi trước để chiếm `creator`."
        ),
        correct_semantics=(
            "Thứ tự thực thi hợp lệ của attacker là gọi initializer public trước, trở thành `creator`, "
            "sau đó gọi hàm privileged `migrateTo`."
        ),
        impact="Model bỏ nhãn `Access_Control` và chuyển sang `Arithmetic`.",
    ),
    SemanticCaseSpec(
        folder="front_running",
        file_name="eth_tx_order_dependence_minimal.sol",
        label="Front-running_Attacks",
        issue_type="Transaction-order vs intra-call order",
        focus_lines={23, 24, 31, 32},
        search_terms=[
            "setReward function",
            "claimReward function",
            "Line 31 transfers before setting claimed",
            "Front-running Attacks",
        ],
        model_misunderstanding=(
            "Model nhìn thấy transfer trước state update và áp dụng khuôn `Reentrancy_Attacks`, "
            "nhưng bỏ qua bản chất transaction-order dependence giữa `setReward` và `claimReward`."
        ),
        correct_semantics=(
            "Ground truth là front-running: kết quả phụ thuộc thứ tự giao dịch owner set reward và user claim reward, "
            "không chỉ thứ tự lệnh trong một call stack."
        ),
        impact="Model dự đoán hai `Reentrancy_Attacks`, không dự đoán `Front-running_Attacks`.",
    ),
    SemanticCaseSpec(
        folder="unchecked_low_level_calls",
        file_name="0x39cfd754c85023648bf003bea2dd498c5612abfa.sol",
        label="Unchecked_External_Calls",
        issue_type="External-call return semantics",
        focus_lines={44, 97, 98},
        search_terms=[
            "WithdrawToken",
            "_addr.call.value(_wei)",
            "send ETH then decrease",
            "Unchecked_External_Calls",
        ],
        model_misunderstanding=(
            "Model hiểu line 97-98 như call-before-state-update reentrancy, nhưng không giữ đúng ngữ nghĩa "
            "`call` trả về bool cần được kiểm tra cho label `Unchecked_External_Calls`."
        ),
        correct_semantics=(
            "`token.call(...)` và `_addr.call.value(_wei)` đều là low-level calls; nếu return value không được kiểm tra, "
            "call failure có thể bị bỏ qua dù control flow vẫn chạy tiếp."
        ),
        impact="Model chỉ output đúng `Unchecked_External_Calls` cho line 44, còn GT line 97 bị kéo sang `Reentrancy_Attacks`.",
    ),
]


def excerpt_around_terms(text: str, terms: List[str], limit: int = 620) -> str:
    clean = " ".join((text or "").split())
    if not clean:
        return "(thinking_process rỗng hoặc không có)"

    lower = clean.lower()
    best_index = -1
    for term in terms:
        term = term.strip()
        if not term:
            continue
        best_index = lower.find(term.lower())
        if best_index >= 0:
            break

    if best_index < 0:
        best_index = 0

    start = max(0, best_index - 160)
    end = min(len(clean), start + limit)
    excerpt = clean[start:end]
    if start > 0:
        excerpt = "..." + excerpt
    if end < len(clean):
        excerpt += "..."
    return excerpt


def prediction_summary(result: JsonResult) -> str:
    if not result.vulnerabilities:
        return f"`status: {result.status}`, `vulnerabilities_count: 0`"
    return (
        f"`status: {result.status}`, `vulnerabilities_count: {len(result.vulnerabilities)}`; "
        + format_prediction_list(result.vulnerabilities)
    )


def existing_cases(
    specs: List[SemanticCaseSpec],
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    results_by_contract: Dict[Tuple[str, str], JsonResult],
) -> List[Tuple[SemanticCaseSpec, Set[int], JsonResult]]:
    cases = []
    for spec in specs:
        gt_lines = gt_samples.get((spec.folder, spec.file_name, spec.label), set())
        result = results_by_contract.get((spec.folder, spec.file_name))
        if not gt_lines or result is None:
            continue
        cases.append((spec, gt_lines, result))
    return cases


def issue_by_label(cases: List[Tuple[SemanticCaseSpec, Set[int], JsonResult]]) -> Dict[str, str]:
    grouped: Dict[str, List[str]] = {}
    for spec, _, _ in cases:
        grouped.setdefault(spec.label, []).append(spec.issue_type)
    return {
        label: "; ".join(sorted(set(issue_types)))
        for label, issue_types in grouped.items()
    }


def write_report(
    output_path: Path,
    results_dir: Path,
    gt_csv: Path,
    dataset_dir: Path,
    gt_samples: Dict[Tuple[str, str, str], Set[int]],
    result_count: int,
    cases: List[Tuple[SemanticCaseSpec, Set[int], JsonResult]],
) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    gt_by_label = Counter(label for _, _, label in gt_samples)
    semantic_by_label = Counter(spec.label for spec, _, _ in cases)
    issues = issue_by_label(cases)

    lines: List[str] = []
    lines.append("# Semantic Misunderstanding Analysis - LOGs/my_results_l5")
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
        "Báo cáo này truy vết **Semantic Misunderstanding**: các case `thinking_process` cho thấy model hiểu sai ngữ nghĩa thực thi, đặc biệt là thứ tự gọi hàm, thứ tự modifier, initializer lifecycle, transaction ordering, hoặc return semantics của low-level call."
    )
    lines.append("")
    lines.append("Khác với Misclassification thuần túy, trọng tâm ở đây là model đọc được một phần tín hiệu code nhưng diễn giải sai luồng thực thi nên kết luận/nhãn/evidence bị sai.")
    lines.append("")
    lines.append("## Tổng quan")
    lines.append("")
    lines.append(f"- Số JSON result được đọc: {result_count}")
    lines.append(f"- Số ground-truth contract-label instances: {len(gt_samples)}")
    lines.append(f"- Số Semantic Misunderstanding cases được truy vết chi tiết: {len(cases)}")
    lines.append("- Kết luận: **Có**. Có bằng chứng model không luôn hiểu đúng thứ tự thực thi/call order của hợp đồng.")
    lines.append("")
    lines.append("## Semantic Misunderstanding theo từng loại lỗ hổng")
    lines.append("")
    lines.append("| Label | GT samples | Traced semantic cases | Dạng hiểu sai nổi bật |")
    lines.append("|---|---:|---:|---|")
    for label in sorted(gt_by_label):
        lines.append(
            f"| {label} | {gt_by_label[label]} | {semantic_by_label[label]} | {issues.get(label, 'Không thấy case call-order rõ trong 5 dẫn chứng')} |"
        )
    lines.append("")
    lines.append("## Phân tích theo nhóm")
    lines.append("")
    for label in sorted(label for label in semantic_by_label if semantic_by_label[label] > 0):
        label_cases = [spec for spec, _, _ in cases if spec.label == label]
        lines.append(f"### {label}")
        lines.append("")
        lines.append(f"- Số case truy vết: {len(label_cases)}")
        lines.append(f"- Dạng lỗi: {', '.join(sorted({case.issue_type for case in label_cases}))}.")
        lines.append(
            "- Nhận xét: model không chỉ sai nhãn/evidence; trong thinking_process có dấu hiệu diễn giải sai thứ tự gọi hoặc lifecycle dẫn tới kết luận sai."
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
        lines.append(f"- Dạng semantic issue: `{spec.issue_type}`")
        lines.append("")
        lines.append("Ground-truth snippet:")
        lines.append("")
        lines.append("```solidity")
        lines.append(snippet_for_lines(solidity_lines, gt_lines))
        lines.append("```")
        lines.append("")
        lines.append("Code region liên quan tới hiểu sai ngữ nghĩa:")
        lines.append("")
        lines.append("```solidity")
        lines.append(snippet_for_lines(solidity_lines, spec.focus_lines))
        lines.append("```")
        lines.append("")
        lines.append("Trích/paraphrase từ thinking_process:")
        lines.append("")
        lines.append(f"> {excerpt_around_terms(result.thinking_process, spec.search_terms)}")
        lines.append("")
        lines.append(f"Model hiểu sai: {spec.model_misunderstanding}")
        lines.append("")
        lines.append(f"Ngữ nghĩa đúng: {spec.correct_semantics}")
        lines.append("")
        lines.append(f"Hậu quả: {spec.impact}")
        lines.append("")
    lines.append("## Kết luận")
    lines.append("")
    lines.append(
        "Có dấu hiệu rõ rằng model đôi khi không hiểu đúng thứ tự thực thi. Các lỗi nổi bật gồm: không theo được external call trong modifier, không nối initializer public với hàm privileged chạy sau đó, nhầm transaction-order dependence thành reentrancy, và nhầm trọng tâm của low-level call giữa return-value checking với reentrancy."
    )
    lines.append("")
    lines.append(
        "Vì vậy, khi dùng model output để audit, các case có nhiều hàm liên kết hoặc modifier/callback nên được kiểm tra thủ công theo call graph, không chỉ theo dòng evidence mà model highlight."
    )

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-dir", type=Path, default=Path("LOGs/my_results_l5"))
    parser.add_argument("--gt-csv", type=Path, default=Path("Description/smartbugs_dataset.csv"))
    parser.add_argument("--dataset-dir", type=Path, default=Path("smartbugs_dataset"))
    parser.add_argument("--output", type=Path, default=Path("RQ3/SemanticMisunderstanding.md"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    gt_samples = build_ground_truth(args.gt_csv)
    results_by_contract = read_json_results(args.results_dir)
    cases = existing_cases(SEMANTIC_CASES, gt_samples, results_by_contract)
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
    print(f"Semantic misunderstanding cases: {len(cases)}")


if __name__ == "__main__":
    main()
