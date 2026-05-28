#!/usr/bin/env python3
"""Generate a failure-analysis report for late Unchecked_External_Calls ranking."""

import csv
import json
import re
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional


TARGET_LABEL = "Unchecked_External_Calls"
REPORT_PATH = Path("Failure_analysis/PriorityInversion_UncheckedLowLevelCalls.md")
MRR_BY_LABEL = Path("1705report/mrr_by_label.csv")
MRR_QUERY_DETAILS = Path("1705report/mrr_query_details.csv")
JSON_DIR = Path("LOGs/my_results_l5/unchecked_low_level_calls")

EVIDENCE_FILES = [
    "0x39cfd754c85023648bf003bea2dd498c5612abfa.sol",
    "0x3a0e9acd953ffc0dd18d63603488846a6b8b2b01.sol",
    "0x5aa88d2901c68fda244f1d0584400368d2c8e739.sol",
    "0x78c2a1e91b52bca4130b6ed9edd9fbcfd4671c37.sol",
    "0x610495793564aed0f9c7fc48dc4c7c9151d34fd6.sol",
]

LABEL_REASON = {
    "Access_Control": "model xem khả năng chiếm quyền/ghi owner là vấn đề trung tâm nên đặt trước lỗi unchecked call.",
    "Reentrancy_Attacks": "model ưu tiên câu chuyện tấn công rút tiền hoặc external call trước state update, nên unchecked call bị đẩy xuống sau.",
    "Arithmetic": "model ưu tiên rủi ro overflow/underflow trong Solidity cũ, dù lỗi ground truth là unchecked low-level call.",
    "Denial_of_Service_Attacks": "model ưu tiên kịch bản làm gián đoạn thực thi hơn việc kiểm tra return value của low-level call.",
}


def read_csv(path: Path) -> List[Dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def parse_labels(raw: str) -> List[str]:
    return [part.strip() for part in raw.split("|") if part.strip()]


def json_path_for(file_name: str) -> Path:
    return JSON_DIR / f"result_{Path(file_name).stem}.json"


def load_json(file_name: str) -> Dict[str, object]:
    path = json_path_for(file_name)
    return json.loads(path.read_text(encoding="utf-8"))


def clean_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def compact_words(text: str, max_words: int = 95) -> str:
    words = clean_text(text).split()
    if len(words) <= max_words:
        return " ".join(words)
    return " ".join(words[:max_words]) + " ..."


def find_snippet(text: str, patterns: Iterable[str], min_start: int = 900) -> str:
    candidates = []
    for pattern in patterns:
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            if match.start() < min_start:
                continue
            candidates.append(match)
    if not candidates:
        for pattern in patterns:
            match = re.search(pattern, text, flags=re.IGNORECASE)
            if match:
                candidates.append(match)
                break
    if not candidates:
        return compact_words(text[:900])

    match = min(candidates, key=lambda item: item.start())
    start = max(0, match.start() - 240)
    end = min(len(text), match.end() + 640)
    return compact_words(text[start:end])


def find_unchecked_snippet(thinking: str) -> str:
    return find_snippet(
        thinking,
        [
            r"doesn'?t check",
            r"no check for success",
            r"return value",
            r"call returns",
            r"without checking",
            r"unchecked external",
            r"unchecked.*call",
            r"Unchecked_External_Calls:",
            r"Unchecked_External Calls:",
            r"\b[a-zA-Z_]+\.call\b",
            r"call\.value",
        ],
    )


def find_priority_snippet(thinking: str, leaders: List[str]) -> str:
    patterns: List[str] = []
    for label in leaders:
        if label == "Access_Control":
            patterns.extend([r"Access_Control", r"owner", r"onlyOwner", r"without restriction"])
        elif label == "Reentrancy_Attacks":
            patterns.extend([r"Reentrancy", r"reenter", r"drain funds", r"before updating state"])
        elif label == "Arithmetic":
            patterns.extend([r"Arithmetic", r"overflow", r"underflow", r"Solidity 0\.4"])
        elif label == "Denial_of_Service_Attacks":
            patterns.extend([r"Denial_of_Service", r"gas", r"block"])
        else:
            patterns.append(re.escape(label))
    if not patterns:
        patterns = [r"vulnerability", r"risk", r"issue"]
    return find_snippet(thinking, patterns)


def get_target_summary(rows: List[Dict[str, str]]) -> Dict[str, str]:
    for row in rows:
        if row["label"] == TARGET_LABEL:
            return row
    raise ValueError(f"Missing {TARGET_LABEL} in {MRR_BY_LABEL}")


def rank_bucket(rank: str) -> str:
    if rank == "not_found":
        return "not_found"
    value = int(rank)
    if value == 1:
        return "rank_1"
    if value == 2:
        return "rank_2"
    if value == 3:
        return "rank_3"
    return "rank_4_plus"


def build_rank_stats(rows: List[Dict[str, str]]) -> Counter:
    stats = Counter()
    for row in rows:
        stats[rank_bucket(row["rank"])] += 1
    return stats


def build_leader_stats(rows: List[Dict[str, str]]) -> Counter:
    stats = Counter()
    for row in rows:
        if row["rank"] in ("1", "not_found"):
            continue
        labels = parse_labels(row["predicted_labels"])
        try:
            target_index = labels.index(TARGET_LABEL)
        except ValueError:
            continue
        for label in labels[:target_index]:
            stats[label] += 1
    return stats


def find_query(rows: List[Dict[str, str]], file_name: str) -> Dict[str, str]:
    for row in rows:
        if row["file_name"] == file_name:
            return row
    raise ValueError(f"Missing query row for {file_name}")


def vulnerability_summary(data: Dict[str, object], labels: List[str]) -> str:
    vulnerabilities = data.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        return "_Không đọc được danh sách vulnerabilities từ JSON._"

    lines = []
    wanted = set(labels + [TARGET_LABEL])
    for vuln in vulnerabilities:
        if not isinstance(vuln, dict):
            continue
        label = str(vuln.get("vulnerability_type", "")).strip()
        if label not in wanted:
            continue
        evidence = vuln.get("evidence", "--")
        function_name = vuln.get("function_name", "--")
        snippet = clean_text(str(vuln.get("evidence_snippet", "--")))
        lines.append(f"- `{label}` tại `{function_name}`, evidence `{evidence}`: `{snippet}`")
    return "\n".join(lines) if lines else "_Không có vulnerability object tương ứng trong JSON._"


def explain_case(rank: str, leaders: List[str]) -> str:
    leader_text = ", ".join(f"`{label}`" for label in leaders) if leaders else "các nhãn khác"
    unique_leaders = list(dict.fromkeys(leaders))
    reasons = [LABEL_REASON.get(label) for label in unique_leaders if label in LABEL_REASON]
    reason_text = " ".join(reasons) if reasons else "model tạo nhiều giả thuyết lỗi trước khi đưa ra nhãn ground truth."
    return (
        f"`{TARGET_LABEL}` chỉ xuất hiện ở rank `{rank}`, sau {leader_text}. "
        f"Điều này làm reciprocal rank của case này giảm còn `1/{rank}`. {reason_text}"
    )


def build_evidence_section(query_rows: List[Dict[str, str]]) -> str:
    sections = []
    for index, file_name in enumerate(EVIDENCE_FILES, start=1):
        query = find_query(query_rows, file_name)
        data = load_json(file_name)
        thinking = str(data.get("thinking_process") or "")
        labels = parse_labels(query["predicted_labels"])
        target_index = labels.index(TARGET_LABEL)
        leaders = labels[:target_index]
        path = json_path_for(file_name).as_posix()

        sections.append(f"### {index}. `{file_name}`")
        sections.append("")
        sections.append(f"- JSON: `{path}`")
        sections.append(f"- Rank của `{TARGET_LABEL}`: `{query['rank']}`")
        sections.append(f"- Reciprocal rank: `{query['reciprocal_rank']}`")
        sections.append(f"- Thứ tự predicted labels: `{query['predicted_labels']}`")
        sections.append(f"- Các nhãn đứng trước: `{', '.join(leaders)}`")
        sections.append("")
        sections.append("Model output liên quan:")
        sections.append("")
        sections.append(vulnerability_summary(data, leaders))
        sections.append("")
        sections.append("Trích đoạn thinking_process về lỗi được ưu tiên trước:")
        sections.append("")
        sections.append(f"> {find_priority_snippet(thinking, leaders)}")
        sections.append("")
        sections.append("Trích đoạn thinking_process về unchecked low-level call:")
        sections.append("")
        sections.append(f"> {find_unchecked_snippet(thinking)}")
        sections.append("")
        sections.append("Giải thích:")
        sections.append("")
        sections.append(explain_case(query["rank"], leaders))
        sections.append("")
        sections.append(
            "Dựa trên hai đoạn thinking trên, model không hoàn toàn mù với low-level call; vấn đề là nó xếp lỗi này sau "
            "các lỗi có mô tả tác động mạnh hơn. Vì MRR chỉ thưởng cao cho nhãn đúng xuất hiện sớm, thứ tự này trực tiếp "
            "kéo điểm của `Unchecked_External_Calls` xuống."
        )
        sections.append("")
    return "\n".join(sections)


def make_markdown() -> str:
    summary = get_target_summary(read_csv(MRR_BY_LABEL))
    all_query_rows = [row for row in read_csv(MRR_QUERY_DETAILS) if row["label"] == TARGET_LABEL]
    stats = build_rank_stats(all_query_rows)
    leader_stats = build_leader_stats(all_query_rows)

    lines = [
        "# Priority Inversion của Unchecked Low-Level Calls",
        "",
        "## Kết luận ngắn gọn",
        "",
        (
            f"`{TARGET_LABEL}` có MRR thấp (`{summary['mrr']}`) vì model thường không đặt nhãn này ở vị trí đầu tiên. "
            "Trong nhiều case, `thinking_process` đã nhận ra low-level call hoặc việc không kiểm tra return value, "
            "nhưng output lại ưu tiên các nhãn có câu chuyện tác động mạnh hơn như `Access_Control`, "
            "`Reentrancy_Attacks`, hoặc `Arithmetic`."
        ),
        "",
        "Nói cách khác, đây không chỉ là lỗi detection failure. Đây là lỗi `Priority Inversion`: model thấy đúng dấu mối, "
        "nhưng xếp nó quá trễ trong danh sách prediction.",
        "",
        "## Metric liên quan",
        "",
        "| Label | Queries | Found | Not found | MRR |",
        "|---|---:|---:|---:|---:|",
        f"| `{TARGET_LABEL}` | {summary['queries']} | {summary['found']} | {summary['not_found']} | {summary['mrr']} |",
        "",
        "Với MRR, rank càng trễ thì điểm càng giảm: rank 2 chỉ còn `1/2`, rank 3 chỉ còn `1/3`, rank 4 chỉ còn `1/4`, "
        "và `not_found` bằng `0`.",
        "",
        "## Phân bố rank",
        "",
        "| Nhóm rank | Số case | Tác động tới MRR |",
        "|---|---:|---|",
        f"| Rank 1 | {stats['rank_1']} | Đóng góp tối đa `1.0` mỗi case |",
        f"| Rank 2 | {stats['rank_2']} | Mỗi case chỉ đóng góp `0.5` |",
        f"| Rank 3 | {stats['rank_3']} | Mỗi case chỉ đóng góp `0.333333` |",
        f"| Rank 4+ | {stats['rank_4_plus']} | Mỗi case đóng góp tối đa `0.25` hoặc thấp hơn |",
        f"| Not found | {stats['not_found']} | Đóng góp `0` |",
        "",
        "## Các nhãn thường đứng trước Unchecked_External_Calls",
        "",
        "| Nhãn đứng trước | Số lần xuất hiện trước nhãn đúng | Ý nghĩa |",
        "|---|---:|---|",
    ]

    for label, count in leader_stats.most_common():
        meaning = LABEL_REASON.get(label, "model uu tien nhan nay truoc unchecked low-level call trong ranked output.")
        lines.append(f"| `{label}` | {count} | {meaning} |")

    lines.extend(
        [
            "",
            "## 5 dẫn chứng chi tiết",
            "",
            build_evidence_section(all_query_rows),
            "## Tổng hợp nguyên nhân",
            "",
            "1. Model hay chuyển trọng tâm sang tác động có vẻ nghiêm trọng hơn.",
            "",
            "Trong `thinking_process`, các lỗi như chiếm owner, reentrancy drain funds, hoặc arithmetic overflow thường được mô tả "
            "bằng ngôn ngữ mạnh hơn: attacker can become owner, drain funds, loss of funds, wrap-around. Trong khi đó, "
            "`Unchecked_External_Calls` thường được mô tả như không check success/return value, nên bị xếp như lỗi phụ.",
            "",
            "2. Low-level call bị gộp vào reasoning của lỗi khác.",
            "",
            "Nhiều đoạn thinking dùng cùng một evidence `call.value` hoặc `token.call` để lập luận cho `Reentrancy_Attacks`, sau đó mới "
            "nhắc đến unchecked return value. Khi output sắp theo thứ tự suy luận này, `Unchecked_External_Calls` bị đẩy xuống rank sau.",
            "",
            "3. MRR phạt nặng ranking trễ.",
            "",
            f"Ngay cả khi model có phát hiện `{TARGET_LABEL}`, nếu nó đứng ở rank 2/3/4 thì điểm tương ứng chỉ là `0.5`, "
            "`0.333333`, hoặc `0.25`. Cộng thêm 23 case `not_found`, MRR của label này bị kéo xuống `0.365385`.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    markdown = make_markdown()
    REPORT_PATH.write_text(markdown + "\n", encoding="utf-8")
    print(f"Wrote {REPORT_PATH}")


if __name__ == "__main__":
    main()
