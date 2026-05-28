# Specification Ambiguity - RQ3

## Mục tiêu

Báo cáo này truy vết **Specification Ambiguity / Mơ hồ về đặc tả** bằng cách đọc prompt tại `prompts/detect_vuln_prompt.txt`, các JSON trong `LOGs/my_results_l5`, đặc biệt là `thinking_process`, và ground truth trong `Description/smartbugs_dataset.csv`.

Câu hỏi chính: nội dung prompt có làm mô hình hiểu nhầm nhiệm vụ cần thực hiện không?

## Kết luận tổng quan

Có. Prompt hiện tại có một số điểm dễ gây hiểu nhầm:

- Prompt yêu cầu **"Identify ALL vulnerabilities"**, nhưng ground truth SmartBugs trong `Description/smartbugs_dataset.csv` thường đánh giá theo nhãn chính của folder/file. Vì vậy mô hình có xu hướng audit toàn diện và thêm nhãn phụ, làm tăng false positive khi đem so với ground truth.
- Tên nhãn trong prompt không hoàn toàn khớp ground truth. Ví dụ prompt dùng `Front-running_Attacks`, trong khi CSV dùng `Front-Running`; prompt có lúc ghi `Unchecked_External Calls`, trong khi CSV dùng `Unchecked_External_Calls`.
- Prompt nói "If none match, use Other" nhưng cũng nói nếu không có vulnerability thì trả về `{"vulnerabilities": []}`. Điều này làm nhãn `Other` mơ hồ: `Other` là một vulnerability type thật trong dataset, hay chỉ là fallback khi không match?
- Prompt yêu cầu evidence phải đến trực tiếp từ `code_with_lines`. Điều này hợp lý với nhiều lỗi line-local, nhưng gây khó cho các lỗi cần ngữ cảnh ngoài code như `Short_Addresses` hoặc `Front-Running`.
- Prompt không định nghĩa rõ từng vulnerability type, không nói thứ tự ưu tiên khi nhiều nhãn có thể áp vào cùng một đoạn code, và không nói cách xử lý khi phát hiện thêm lỗi ngoài nhãn ground truth.

Do đó, một phần lỗi không chỉ đến từ khả năng reasoning của mô hình, mà còn đến từ đặc tả nhiệm vụ chưa khớp với cách evaluation đang được thực hiện.

## Dẫn chứng 1 - Prompt yêu cầu "ALL vulnerabilities" làm model thêm nhãn phụ

- JSON model output: [LOGs/my_results_l5/access_control/result_parity_wallet_bug_2.json](../LOGs/my_results_l5/access_control/result_parity_wallet_bug_2.json)
- Source: `smartbugs_dataset/access_control/parity_wallet_bug_2.sol`
- Ground truth trong CSV: `Access_Control` tại dòng `226`, `233`
- Model prediction: `Access_Control`, `Arithmetic`

Trong `thinking_process`, mô hình nhắc lại rằng nó phải quét các lỗi phổ biến và chọn từ danh sách nhiều loại vulnerability. Nó viết rằng cần "scan the code for common vulnerabilities", sau đó kiểm tra reentrancy, arithmetic, time manipulation, access control, unchecked external calls, v.v.

Kết quả là model tìm đúng `Access_Control`, nhưng đồng thời thêm `Arithmetic` ở hàm `underLimit`:

```text
if (m_spentToday + _value >= m_spentToday && m_spentToday + _value <= m_dailyLimit)
```

Về mặt audit tổng quát, việc kiểm tra arithmetic không vô lý. Nhưng nếu evaluation mong đợi nhãn SmartBugs chính của file là `Access_Control`, thì prompt "Identify ALL vulnerabilities" khiến model sinh thêm nhãn phụ, làm kết quả bị tính là prediction dư.

**Nguồn mơ hồ:** prompt không nói rõ liệu nhiệm vụ là "phát hiện tất cả lỗi có thể có" hay "dự đoán đúng vulnerability label trong ground truth của dataset".

## Dẫn chứng 2 - Nhãn `Unchecked_External_Calls` bị lẫn với reentrancy do thiếu định nghĩa ranh giới

- JSON model output: [LOGs/my_results_l5/unchecked_low_level_calls/result_0xdb1c55f6926e7d847ddf8678905ad871a68199d2.json](../LOGs/my_results_l5/unchecked_low_level_calls/result_0xdb1c55f6926e7d847ddf8678905ad871a68199d2.json)
- Source: `smartbugs_dataset/unchecked_low_level_calls/0xdb1c55f6926e7d847ddf8678905ad871a68199d2.sol`
- Ground truth trong CSV: `Unchecked_External_Calls` tại dòng `39`
- Model prediction: `Reentrancy_Attacks`

Trong `thinking_process`, model nhận ra hàm `Command` có:

```solidity
adr.call.value(msg.value)(data);
```

Nó cũng tự phân tích rằng `call.value()` trả về boolean nhưng code không kiểm tra return value. Đây chính là hướng đúng cho `Unchecked_External_Calls`. Tuy nhiên, do prompt không định nghĩa rõ ranh giới giữa unchecked low-level call và reentrancy, model lại ưu tiên gán `Reentrancy_Attacks`.

Điểm đáng chú ý là prompt có tên nhãn không nhất quán: trong `prompts/detect_vuln_prompt.txt` có dạng `Unchecked_External Calls`, còn ground truth dùng `Unchecked_External_Calls`. Một số `thinking_process` cũng lặp lại biến thể có khoảng trắng này.

**Nguồn mơ hồ:** prompt đưa danh sách nhãn nhưng không giải thích tiêu chí phân biệt `.call.value(...)` khi nào là unchecked external call, khi nào là reentrancy. Tên nhãn cũng không hoàn toàn chuẩn hóa.

## Dẫn chứng 3 - `Short_Addresses` cần ngữ cảnh ngoài code nhưng prompt chỉ cho dùng code-line evidence

- JSON model output: [LOGs/my_results_l5/short_addresses/result_short_address_example.json](../LOGs/my_results_l5/short_addresses/result_short_address_example.json)
- Source: `smartbugs_dataset/short_addresses/short_address_example.sol`
- Ground truth trong CSV: `Short_Addresses` tại dòng `18`
- Model prediction: `Arithmetic`, `Access_Control`

Trong `thinking_process`, model nói rõ rằng nó cần "identify all vulnerabilities that can be directly inferred from this code". Khi xét `Short_Addresses`, nó kết luận rằng short-address attack "not present" hoặc không thấy bằng chứng trực tiếp trong code.

Đây là dấu hiệu của specification ambiguity: short-address vulnerability thường liên quan đến ABI encoding, calldata bị thiếu byte, hoặc client/exchange integration, không phải lúc nào cũng thể hiện rõ bằng một dòng Solidity. Trong khi đó prompt lại yêu cầu mọi evidence phải trực tiếp đến từ `code_with_lines`.

Vì vậy model chuyển sang các lỗi dễ chứng minh bằng dòng code hơn, như:

```text
balances[to] += amount;
balances[tx.origin] = 10000;
```

**Nguồn mơ hồ:** prompt yêu cầu evidence line-local nhưng ground truth chứa một loại lỗi cần ngữ cảnh ABI/transaction input. Điều này làm model né nhãn đúng và chọn nhãn khác có vẻ "có chứng cứ code" hơn.

## Dẫn chứng 4 - `Front-Running` trong CSV không khớp rõ với `Front-running_Attacks` trong prompt

- JSON model output: [LOGs/my_results_l5/front_running/result_odds_and_evens.json](../LOGs/my_results_l5/front_running/result_odds_and_evens.json)
- Source: `smartbugs_dataset/front_running/odds_and_evens.sol`
- Ground truth trong CSV: `Front-Running` tại dòng `25`, `28`
- Model prediction: `Unchecked_External_Calls`, `Unchecked_External_Calls`

Trong `thinking_process`, model liệt kê `Front-running_Attacks` là một loại cần xem xét, nhưng sau đó tập trung vào các dòng `send(...)`:

```solidity
res = players[0].addr.send(1800 finney);
bool res = msg.sender.send(this.balance);
```

Nó chọn `Unchecked_External_Calls` vì return value của `send` được gán vào biến nhưng không được xử lý rõ. Tuy nhiên ground truth lại là `Front-Running`, dựa trên logic game commit/reveal yếu hoặc khả năng quan sát giao dịch trước khi tham gia.

Ở đây prompt không cung cấp định nghĩa front-running, không chỉ ra rằng các bài trong folder `front_running` cần được đánh giá theo transaction-order dependence, và tên nhãn cũng khác format với CSV.

**Nguồn mơ hồ:** thiếu định nghĩa semantic cho `Front-running_Attacks` và không chuẩn hóa tên nhãn `Front-running_Attacks` vs `Front-Running`, khiến model ưu tiên lỗi line-local dễ nhận diện hơn.

## Dẫn chứng 5 - Nhãn `Other` bị nhập nhằng giữa fallback và ground-truth category

- JSON model output: [LOGs/my_results_l5/other/result_name_registrar.json](../LOGs/my_results_l5/other/result_name_registrar.json)
- Source: `smartbugs_dataset/other/name_registrar.sol`
- Ground truth trong CSV: `other` tại dòng `23`
- Model prediction: `Denial_of_Service_Attacks`

Trong prompt, `Other` được mô tả như fallback: nếu không nhãn nào match thì dùng `Other`; nếu không có vulnerability thì trả về mảng rỗng. Nhưng trong CSV, folder `other`/label `other` lại là một category ground truth.

Trong `thinking_process`, model đi qua từng nhãn trong danh sách và cố gắng gán một nhãn cụ thể hơn. Nó thấy `unlocked = false` và `require(unlocked)` trong `register`, rồi suy luận sang `Denial_of_Service_Attacks`, dù ground truth chỉ ghi `other`.

Đây không hẳn là model tự nhiên "không biết". Prompt đã khiến `Other` trở thành lựa chọn cuối cùng sau khi loại trừ mọi nhãn khác, trong khi evaluation lại có thể xem `other` là nhãn đúng độc lập.

**Nguồn mơ hồ:** `Other` trong prompt là fallback operational, còn `other` trong dataset là label/category. Hai ý nghĩa này không được phân biệt.

## Xu hướng lỗi do mơ hồ đặc tả

1. **Audit toàn diện thay vì classification theo ground truth.** Model thêm nhãn phụ như `Arithmetic`, `Access_Control`, `Reentrancy_Attacks` vì prompt yêu cầu tìm tất cả vulnerability.
2. **Ưu tiên lỗi có evidence trực tiếp.** Khi nhãn đúng cần ngữ cảnh ngoài dòng code, model chọn lỗi khác dễ chứng minh bằng snippet.
3. **Tên nhãn không chuẩn hóa.** `Front-Running` vs `Front-running_Attacks`, `Unchecked_External_Calls` vs `Unchecked_External Calls`, `other` vs `Other` làm prediction và evaluation lệch nhau.
4. **Thiếu định nghĩa ranh giới giữa các class.** `.call.value` có thể bị kéo sang reentrancy thay vì unchecked external call; game transaction-order dependence bị bỏ qua để chọn unchecked send.
5. **Không có hướng dẫn xử lý multi-label.** Nếu code có nhiều issue, prompt không nói liệu chỉ lấy nhãn chính, top-1, top-k, hay tất cả nhãn có thể chứng minh.

## Kết luận

Prompt có gây ra sự hiểu lầm về nhiệm vụ. Cụ thể, nó phù hợp với bài toán **open-ended smart contract audit**, nhưng evaluation lại đang đọc kết quả như bài toán **classification/ranking theo nhãn ground truth SmartBugs**. Sự lệch pha này làm xuất hiện các lỗi được tính là misclassification hoặc false positive, dù một phần xuất phát từ cách prompt định nghĩa nhiệm vụ.

Để giảm Specification Ambiguity, prompt nên được sửa theo hướng:

- Chuẩn hóa đúng tên nhãn theo CSV.
- Nói rõ chỉ dự đoán nhãn trong taxonomy evaluation.
- Nói rõ output multi-label hay single-label/top-k.
- Định nghĩa từng vulnerability type bằng tiêu chí ngắn.
- Tách `Other` fallback khỏi label `other` của dataset.
- Với `Short_Addresses` và `Front-Running`, cho phép dùng ngữ cảnh vulnerability pattern của dataset, không chỉ evidence line-local.
