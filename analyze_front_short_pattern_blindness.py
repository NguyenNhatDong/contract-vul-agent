#!/usr/bin/env python3
"""Generate a failure-analysis report for front-running and short-address misses."""

import csv
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from evaluate_tlr import normalize_label, parse_evidence_lines, read_rows


TARGETS = ("Front-running_Attacks", "Short_Addresses")
REPORT_PATH = Path("Failure_analysis/PatternBlindness_FrontRunning_ShortAddresses.md")
GT_CSV = Path("Description/smartbugs_dataset.csv")
MODEL_CSV = Path("LOGs/my_results_l5/vulnerability_report.csv")
MRR_BY_LABEL = Path("1705report/mrr_by_label.csv")
TOPK_BY_LABEL = Path("1705report/topk_accuracy_by_label.csv")
EMT_BY_LABEL = Path("1705report/emt_by_label.csv")
MRR_QUERY_DETAILS = Path("1705report/mrr_query_details.csv")

EVIDENCE_CASES = [
    ("front_running", "ERC20.sol", "Front-running_Attacks"),
    ("front_running", "eth_tx_order_dependence_minimal.sol", "Front-running_Attacks"),
    ("front_running", "FindThisHash.sol", "Front-running_Attacks"),
    ("front_running", "odds_and_evens.sol", "Front-running_Attacks"),
    ("short_addresses", "short_address_example.sol", "Short_Addresses"),
]

CASE_TITLES = {
    "ERC20.sol": "ERC20 allowance race bị hiểu nhầm là token chuẩn không có logic DEX/auction",
    "eth_tx_order_dependence_minimal.sol": "Transaction-order dependence bị thay bằng reentrancy",
    "FindThisHash.sol": "Hash puzzle bị coi là intended functionality",
    "odds_and_evens.sol": "Game hai người bị bỏ qua front-running vì không có blockhash",
    "short_address_example.sol": "Short address bị hiểu sai là vấn đề Solidity fixed-size address",
}


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return [{key: (value or "").strip() for key, value in row.items()} for row in csv.DictReader(f)]


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def compact_words(text: str, max_words: int = 95) -> str:
    words = clean_text(text).split()
    if len(words) <= max_words:
        return " ".join(words)
    return " ".join(words[:max_words]) + " ..."


def format_lines(lines: Iterable[int]) -> str:
    return ", ".join(str(line) for line in sorted(lines)) or "--"


def build_gt() -> Dict[Tuple[str, str, str], List[int]]:
    gt: Dict[Tuple[str, str, str], set[int]] = defaultdict(set)
    for row in read_rows(GT_CSV):
        folder = row.get("folder", "")
        label = normalize_label(row.get("vulnerability_type", ""))
        if label not in TARGETS:
            continue
        key = (folder, row.get("file_name", ""), label)
        gt[key].update(parse_evidence_lines(row.get("evidence", "")))
    return {key: sorted(lines) for key, lines in gt.items()}


def build_model_predictions() -> Dict[Tuple[str, str], List[str]]:
    predictions: Dict[Tuple[str, str], List[str]] = defaultdict(list)
    for row in read_rows(MODEL_CSV):
        label = normalize_label(row.get("vulnerability_type", ""))
        if not label or label in {"(none)", "error"}:
            continue
        key = (row.get("folder", ""), row.get("file_name", ""))
        predictions[key].append(label)
    return dict(predictions)


def read_metric(label: str, rows: Sequence[Dict[str, str]]) -> Dict[str, str]:
    for row in rows:
        if row.get("label") == label:
            return row
    raise ValueError(f"Missing metric for {label}")


def read_query(folder: str, file_name: str, label: str) -> Dict[str, str]:
    for row in read_csv(MRR_QUERY_DETAILS):
        if row.get("folder") == folder and row.get("file_name") == file_name and row.get("label") == label:
            return row
    raise ValueError(f"Missing query detail for {folder}/{file_name}/{label}")


def json_path(folder: str, file_name: str) -> Path:
    return Path("LOGs/my_results_l5") / folder / f"result_{Path(file_name).stem}.json"


def load_json(folder: str, file_name: str) -> Dict[str, object]:
    return json.loads(json_path(folder, file_name).read_text(encoding="utf-8"))


def json_predicted_labels(data: Dict[str, object]) -> List[str]:
    vulnerabilities = data.get("vulnerabilities") or []
    labels: List[str] = []
    if isinstance(vulnerabilities, list):
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                label = normalize_label(str(vuln.get("vulnerability_type", "")).strip())
                if label:
                    labels.append(label)
    return labels


def vulnerability_summary(data: Dict[str, object]) -> str:
    vulnerabilities = data.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list) or not vulnerabilities:
        return "- `(none)` - JSON không có vulnerability object nào."

    lines = []
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        label = normalize_label(str(vuln.get("vulnerability_type", "")).strip())
        evidence = vuln.get("evidence", "--")
        function_name = vuln.get("function_name", "--")
        snippet = clean_text(str(vuln.get("evidence_snippet", "--")))
        lines.append(f"- `{label}` tại `{function_name}`, evidence `{evidence}`: `{snippet}`")
    return "\n".join(lines)


def find_snippet(text: str, patterns: Sequence[str]) -> str:
    normalized = clean_text(text)
    for pattern in patterns:
        match = re.search(pattern, normalized, flags=re.IGNORECASE)
        if match:
            start = max(0, match.start() - 280)
            end = min(len(normalized), match.end() + 760)
            return compact_words(normalized[start:end])

    return compact_words(normalized[:950])


def find_front_quote(file_name: str, thinking: str) -> str:
    if file_name == "ERC20.sol":
        return find_snippet(thinking, [r"Front-running_Attacks:.*?No such logic here", r"approve", r"allowance"])
    if file_name == "eth_tx_order_dependence_minimal.sol":
        return find_snippet(thinking, [r"No transactions that depend on order", r"Front-running Attacks", r"claimReward"])
    if file_name == "FindThisHash.sol":
        return find_snippet(thinking, [r"No obvious front-running", r"intended functionality", r"hash is constant"])
    if file_name == "odds_and_evens.sol":
        return find_snippet(thinking, [r"No obvious issues, like relying on blockhash", r"Front-running_Attacks", r"play function"])
    return find_snippet(thinking, [r"Front-running", r"transaction order"])


def find_short_quote(thinking: str) -> str:
    return find_snippet(
        thinking,
        [
            r"Short_Addresses:.*?not present",
            r"addresses are fixed size",
            r"short addresses",
            r"Short_Addresses",
        ],
    )


def find_substitution_quote(label: str, thinking: str) -> str:
    if label == "Short_Addresses":
        return find_snippet(thinking, [r"Arithmetic", r"Access_Control", r"underflow", r"tx\.origin"])
    return find_snippet(thinking, [r"Reentrancy", r"Unchecked_External_Calls", r"transfer", r"send"])


def metric_table() -> str:
    mrr_rows = read_csv(MRR_BY_LABEL)
    topk_rows = read_csv(TOPK_BY_LABEL)
    emt_rows = read_csv(EMT_BY_LABEL)

    lines = [
        "| Label | N | MRR | TOP-1 | TOP-3 | TOP-max | EMT |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for label in TARGETS:
        mrr = read_metric(label, mrr_rows)
        topk = read_metric(label, topk_rows)
        emt = read_metric(label, emt_rows)
        lines.append(
            f"| `{label}` | {mrr['queries']} | {mrr['mrr']} | {topk['TOP1_accuracy']} | "
            f"{topk['TOP3_accuracy']} | {topk['TOPMAX_accuracy']} | {emt['EMT']} |"
        )
    return "\n".join(lines)


def explain_case(file_name: str, target_label: str, predicted_labels: List[str]) -> str:
    predicted = ", ".join(f"`{label}`" for label in predicted_labels) or "`(none)`"
    if target_label == "Front-running_Attacks":
        if file_name == "ERC20.sol":
            reason = (
                "Model đồng nhất front-running với các ngữ cảnh như DEX/auction nên bỏ qua approve/allowance race trong ERC20. "
                "Quote cho thấy nó thấy `approve` và `allowance`, nhưng kết luận `No such logic here` vì không có logic giao dịch quen thuộc."
            )
        elif file_name == "eth_tx_order_dependence_minimal.sol":
            reason = (
                "Model thấy `transfer` trước cập nhật state và thay thế nhãn bằng reentrancy. Nó không coi `setReward/claimReward` là phụ thuộc thứ tự giao dịch, "
                "dù ground truth chính là transaction-order dependence."
            )
        elif file_name == "FindThisHash.sol":
            reason = (
                "Model xem bài toán hash puzzle là chức năng dự định, không nhận ra lời giải được public trong mempool có thể bị copy và front-run trước khi nhận thưởng."
            )
        else:
            reason = (
                "Model tìm dấu hiệu front-running quá hẹp, như `blockhash`, rồi chuyển sang unchecked send. Nó bỏ qua việc người chơi thứ hai có thể quan sát lựa chọn trước đó và đặt số thắng."
            )
    else:
        reason = (
            "Model hiểu short address như vấn đề kiểu `address` trong Solidity, rồi phủ định vì địa chỉ là fixed-size. "
            "Nó không xét threat model ABI/input-padding ở tầng transaction/client, nên thay nhãn đúng bằng arithmetic/access-control."
        )
    return f"Model prediction là {predicted}. {reason}"


def evidence_sections(gt: Dict[Tuple[str, str, str], List[int]], predictions: Dict[Tuple[str, str], List[str]]) -> str:
    sections: List[str] = []
    for index, (folder, file_name, target_label) in enumerate(EVIDENCE_CASES, start=1):
        data = load_json(folder, file_name)
        thinking = str(data.get("thinking_process") or "")
        query = read_query(folder, file_name, target_label)
        predicted_labels = json_predicted_labels(data)
        if not predicted_labels:
            predicted_labels = predictions.get((folder, file_name), [])
        gt_lines = gt.get((folder, file_name, target_label), [])
        target_quote = find_short_quote(thinking) if target_label == "Short_Addresses" else find_front_quote(file_name, thinking)
        substitution_quote = find_substitution_quote(target_label, thinking)

        sections.append(f"### {index}. `{folder}/{file_name}` - {CASE_TITLES[file_name]}")
        sections.append("")
        sections.append(f"- JSON: `{json_path(folder, file_name).as_posix()}`")
        sections.append(f"- Ground truth: `{target_label}`, evidence `{format_lines(gt_lines)}`")
        sections.append(f"- Metric status: rank `{query['rank']}`, reciprocal rank `{query['reciprocal_rank']}`")
        sections.append(f"- Model predicted labels: `{ ' | '.join(predicted_labels) if predicted_labels else '(none)' }`")
        sections.append("")
        sections.append("Model output liên quan:")
        sections.append("")
        sections.append(vulnerability_summary(data))
        sections.append("")
        sections.append("Quote từ thinking_process về nhãn đúng bị phủ định hoặc hiểu hẹp:")
        sections.append("")
        sections.append(f"> {target_quote}")
        sections.append("")
        sections.append("Quote từ thinking_process về hướng nhãn thay thế:")
        sections.append("")
        sections.append(f"> {substitution_quote}")
        sections.append("")
        sections.append("Giải thích:")
        sections.append("")
        sections.append(explain_case(file_name, target_label, predicted_labels))
        sections.append("")
        sections.append(
            "Vì quote trên cho thấy model tự loại bỏ hoặc định nghĩa quá hẹp nhãn đúng, nên dù có đọc được cấu trúc code, "
            "nó không đưa `Front-running_Attacks`/`Short_Addresses` vào output. Kết quả là rank `not_found` và reciprocal rank `0`."
        )
        sections.append("")
    return "\n".join(sections)


def make_report() -> str:
    gt = build_gt()
    predictions = build_model_predictions()
    return "\n".join(
        [
            "# Pattern Blindness của Front-Running và Short Addresses",
            "",
            "## Kết luận ngắn gọn",
            "",
            (
                "Model thất bại hoàn toàn với hai label này: `Front-running_Attacks` có `4/4` case không được phát hiện, "
                "và `Short_Addresses` có `1/1` case không được phát hiện. Các quote từ `thinking_process` cho thấy lỗi chính "
                "không phải thiếu dữ liệu code, mà là `Pattern Blindness`: model dùng định nghĩa quá hẹp cho front-running và "
                "sai threat model cho short-address attack."
            ),
            "",
            "## Metric tổng quan",
            "",
            metric_table(),
            "",
            "## Dẫn chứng chi tiết",
            "",
            evidence_sections(gt, predictions),
            "## Tổng hợp nguyên nhân",
            "",
            "1. `Narrow Pattern Definition`: model thường chỉ tìm front-running trong các mẫu quen thuộc như DEX, auction, blockhash hoặc logic thị trường rõ ràng.",
            "",
            "2. `Semantic Underfitting`: model không khái quát front-running thành phụ thuộc thứ tự giao dịch, nên bỏ qua approve race, hash puzzle, transaction-order dependence và trò chơi hai người.",
            "",
            "3. `Wrong Threat Model`: với short address, model xét kiểu `address` trong Solidity là fixed-size, thay vì xét lỗi ABI/input-padding ở tầng transaction/client.",
            "",
            "4. `Label Substitution`: khi không nhận ra nhãn đúng, model chuyển sang các nhãn có pattern cú pháp dễ thấy hơn như `Reentrancy_Attacks`, `Unchecked_External_Calls`, `Arithmetic`, hoặc `Access_Control`.",
            "",
        ]
    )


def main() -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(make_report() + "\n", encoding="utf-8")
    print(f"Wrote {REPORT_PATH}")


if __name__ == "__main__":
    main()
