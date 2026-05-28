# Phân tích vì sao EMT của Reentrancy thấp hơn TOP-k

Thời điểm tạo báo cáo: 2026-05-27T15:24:57.657581

## Chênh lệch chỉ số

| Chỉ số | Số hit | N | Điểm |
|---|---:|---:|---:|
| EMT | 10 | 31 | 0.322581 |
| TOP-1 Accuracy | 28 | 31 | 0.903226 |
| TOP-3 Accuracy | 28 | 31 | 0.903226 |
| TOP-max Accuracy | 28 | 31 | 0.903226 |

## Câu trả lời chính

`Reentrancy_Attacks` có TOP-k Accuracy cao vì model thường đặt nhãn reentrancy đúng ở vị trí đầu tiên. Tuy nhiên, EMT thấp hơn nhiều vì EMT yêu cầu output phải có **chính xác một prediction** và prediction đó phải đúng. Trong query details, có 18 contract reentrancy có TOP-1 đúng nhưng EMT vẫn fail vì model sinh nhiều nhãn cùng lúc.

Nói ngắn gọn: TOP-k chỉ hỏi “model có đặt nhãn đúng đủ cao không?”, còn EMT hỏi “model có trả đúng duy nhất một nhãn không?”. Vì model hay over-predict thêm `Arithmetic`, `Access_Control`, `Denial_of_Service_Attacks`, `Time_Manipulation`, v.v., nên TOP-k vẫn cao nhưng EMT giảm mạnh.

## Phân loại nguyên nhân EMT fail

| Nhóm lỗi | Số lượng |
|---|---:|
| TOP-1 đúng nhưng EMT fail vì model sinh thêm prediction phụ | 18 |
| Không có prediction hợp lệ/status Normal hoặc Error | 2 |
| TOP-max fail vì không có `Reentrancy_Attacks` | 1 |

## Dẫn chứng từ JSON và thinking_process

### Ví dụ 1: `0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.sol`

- JSON: `LOGs\my_results_l5\reentrancy\result_0x01f8c4e3fa3edeb29e514cba738d87ce8c091d3f.json`
- Nhãn model dự đoán trong query details: `Reentrancy_Attacks | Arithmetic | Access_Control`
- EMT exact_match: `0`
- TOP-k: top1=`1`, top3=`1`, topmax=`1`
- JSON status: `Vulnerable`, vulnerabilities_count: `4`
- Vulnerabilities trong model output: `Reentrancy_Attacks` evidence `54` function `Collect`<br>`Arithmetic` evidence `43` function `Deposit`<br>`Time_Manipulation` evidence `91` function `AddMessage`<br>`Denial_of_Service_Attacks` evidence `83` function `AddMessage`

Đoạn thinking_process cho thấy model nhận ra reentrancy:

> ...if(msg.sender.call.value(_am)()) { // This is an external call balances[msg.sender] -= _am; Log.AddMessage(msg.sender, _am, "Collect"); } } This is a classic reentrancy vulnerability because the external call (msg.sender.call) could be to a contract that re-enters this Collect function before the balance is deducted. In Solidity, when you do a call with value, if the recipient is a contract, it can call back. Here, msg.sender could be a malicious contract that, upon receiving the ether, calls Collect again, drainin...

Đoạn thinking_process cho thấy model mở rộng sang nhãn phụ:

> ...ate is after the call, so if the call re-enters, it can use the old balance. Yes, this is a clear reentrancy issue. Next, Arithmetic vulnerabilities: Overflow/underflow. - Deposit: balances[msg.sender] += msg.value; This could overflow if the balance is too high, but in Solidity 0.4.19, there are no checks for overflow by default, so it could be a risk. In Solidity 0.4.19, integer overflows don't revert by default, so this could lead to overflow without error. Evidence: Line 43. But is this directly inferable? Yes,...

Giải thích dựa trên thinking_process:

TOP-k tính case này là đúng vì `Reentrancy_Attacks` xuất hiện ở rank 1. Nhưng EMT đánh fail vì cùng output còn có thêm các nhãn phụ như `Arithmetic`, `Access_Control` trong query details, và JSON thực tế còn có thêm `Time_Manipulation`, `Denial_of_Service_Attacks`. Thinking_process cho thấy model đã nhận ra reentrancy, nhưng sau đó tiếp tục scan các nhóm lỗi khác và thêm prediction phụ. Vì vậy một dự đoán top-1 đúng bị biến thành output multi-label, không còn là exact match.

### Ví dụ 2: `0x4e73b32ed6c35f570686b89848e5f39f20ecc106.sol`

- JSON: `LOGs\my_results_l5\reentrancy\result_0x4e73b32ed6c35f570686b89848e5f39f20ecc106.json`
- Nhãn model dự đoán trong query details: `Reentrancy_Attacks | Arithmetic | Access_Control | Short_Addresses`
- EMT exact_match: `0`
- TOP-k: top1=`1`, top3=`1`, topmax=`1`
- JSON status: `Vulnerable`, vulnerabilities_count: `2`
- Vulnerabilities trong model output: `Reentrancy_Attacks` evidence `54-58` function `Collect`<br>`Arithmetic` evidence `43` function `Deposit`

Đoạn thinking_process cho thấy model nhận ra reentrancy:

> ...kay because History stores a copy. No vulnerability there. Now, I need to output only if vulnerabilities can be directly inferred. - Reentrancy: Yes, classic reentrancy vulnerability. - Arithmetic overflow: Yes, in Solidity, uint256 can overflow, leading to loss of funds. - Access_Control: Not clearly a vulnerability; it's more of a design aspect. - Other types don't seem to apply. So, I should include Reentrancy_Attack and Arithmetic. Now, for the JSON output. First, vulnerabilities array. For each, specify: - vul...

Đoạn thinking_process cho thấy model mở rộng sang nhãn phụ:

> ...+= msg.value; could overflow if the balance is high. - Evidence: line 43 - Function: Deposit - Execution: trigger is the += operation, state_issue is potential overflow, exploitable_behavior is calling Deposit with large values. - Causality: state is the balance variable, guard is None (no check for overflow), transition is the addition, capability is to cause overflow and wrap around, outcome is incorrect balance and potential loss of funds. 3. **Access_Control Flaw**: After initialization, anyone can call functio...

Giải thích dựa trên thinking_process:

Ở ví dụ này, model tự ghi rõ `Reentrancy: Yes, classic reentrancy vulnerability`, nên TOP-1 đúng. Nhưng ngay trong cùng reasoning, model tiếp tục kết luận `Arithmetic overflow: Yes` và thậm chí cân nhắc `Access_Control`. Điều này tạo output có nhiều nhãn. EMT vì vậy fail, dù model đã đặt đúng nhãn reentrancy ở đầu.

### Ví dụ 3: `0x561eac93c92360949ab1f1403323e6db345cbf31.sol`

- JSON: `LOGs\my_results_l5\reentrancy\result_0x561eac93c92360949ab1f1403323e6db345cbf31.json`
- Nhãn model dự đoán trong query details: `Reentrancy_Attacks | Arithmetic | Denial_of_Service_Attacks`
- EMT exact_match: `0`
- TOP-k: top1=`1`, top3=`1`, topmax=`1`
- JSON status: `Vulnerable`, vulnerabilities_count: `3`
- Vulnerabilities trong model output: `Reentrancy_Attacks` evidence `54` function `Collect`<br>`Unchecked_External_Calls` evidence `44` function `Deposit`<br>`Arithmetic` evidence `43` function `Deposit`

Đoạn thinking_process cho thấy model nhận ra reentrancy:

> ...ed. Reentrancy typically involves a function that sends Ether and then updates state. Here, Collect sends Ether first, then updates state. That's the classic reentrancy pattern where the call can re-enter before the state update. Evidence: Line 54: if(msg.sender.call.value(_am)()) { ... decreases balance } So, evidence_snippet could be line 54. Function_name: Collect Now, for Reentrancy_Attacks, I need to check if there's a guard. In standard reentrancy, the guard is missing or misplaced. Here, after the call, it d...

Đoạn thinking_process cho thấy model mở rộng sang nhãn phụ:

> ...Message is not sending Ether, so probably not reentrant. But in Collect, it's a potential issue. Next, Arithmetic vulnerabilities: Look for unchecked overflows/underflows. In Deposit: balances[msg.sender] += msg.value; This could overflow if balances[msg.sender] is too high, but in Solidity 0.4.19, addition might not revert on overflow by default, but it could be handled. In this version, unchecked arithmetic might be a issue, but I'm not sure. In Solidity 0.4.19, integer overflows do not revert transactions by def...

Giải thích dựa trên thinking_process:

Model xác định đúng pattern reentrancy: gửi Ether trước rồi cập nhật state sau. Nhưng sau khi đã nhận ra lỗi chính, model tiếp tục phân tích `Arithmetic vulnerabilities` ở `Deposit`. Vì thế output không còn là một prediction duy nhất. TOP-k vẫn tính đúng vì reentrancy đứng đầu, còn EMT fail vì có thêm nhãn phụ.

### Ví dụ 4: `etherbank.sol`

- JSON: `LOGs\my_results_l5\reentrancy\result_etherbank.json`
- Nhãn model dự đoán trong query details: `Reentrancy_Attacks | Access_Control`
- EMT exact_match: `0`
- TOP-k: top1=`1`, top3=`1`, topmax=`1`
- JSON status: `Vulnerable`, vulnerabilities_count: `3`
- Vulnerabilities trong model output: `Reentrancy_Attacks` evidence `21` function `withdrawBalance`<br>`Access_Control` evidence `14-16, 18-23` function `addToBalance, withdrawBalance`<br>`Arithmetic` evidence `15` function `addToBalance`

Đoạn thinking_process cho thấy model nhận ra reentrancy:

> ...if it has a reentrant function - capability: Attacker can withdraw funds multiple times - outcome: Funds are drained multiple times This seems like a classic reentrancy vulnerability. Now, other vulnerabilities: Arithmetic: Check for overflow/underflow. In addToBalance, userBalances[msg.sender] += msg.value; If msg.value is large, it might overflow the uint. But uint in Solidity has no upper limit in 0.4.0, it's fixed-point, but overflow can still happen if exceeding 2^256-1, but practically, it's rare. However, in...

Đoạn thinking_process cho thấy model mở rộng sang nhãn phụ:

> ...here's no restriction. For example, addToBalance doesn't check if msg.sender is authorized. Similarly for withdraw. But the contract doesn't have any access control mechanisms. However, the vulnerability types include Access_Control, which might refer to unauthorized access. Evidence: Functions are public by default, no modifiers or checks. Function_name: addToBalance or withdrawBalance Evidence_snippet: For example, "function addToBalance() {" no access control. But is this a vulnerability? In smart contracts, lac...

Giải thích dựa trên thinking_process:

Thinking_process cho thấy model đã phát hiện đúng “classic reentrancy vulnerability”. Tuy nhiên, sau đó model tiếp tục mở rộng sang `Arithmetic` và `Access_Control`, dựa trên việc các hàm public không có modifier/check. Đây là biểu hiện over-prediction: model không dừng ở lỗi reentrancy chính mà thêm các nhãn phụ. Do đó TOP-k đúng nhưng EMT fail.

### Ví dụ 5: `reentrancy_simple.sol`

- JSON: `LOGs\my_results_l5\reentrancy\result_reentrancy_simple.json`
- Nhãn model dự đoán trong query details: `Reentrancy_Attacks | Arithmetic`
- EMT exact_match: `0`
- TOP-k: top1=`1`, top3=`1`, topmax=`1`
- JSON status: `Vulnerable`, vulnerabilities_count: `1`
- Vulnerabilities trong model output: `Reentrancy_Attacks` evidence `24` function `withdrawBalance`

Đoạn thinking_process cho thấy model nhận ra reentrancy:

> ...llback function in msg.sender. If msg.sender has a function that can call back into withdrawBalance, it could re-enter and drain the funds. This is a classic reentrancy vulnerability. Let me confirm the code. In withdrawBalance: - It sends Ether to msg.sender. - Then sets balance to 0. But before setting to 0, the Ether is sent, and if the recipient has a reentrant contract, it can call withdrawBalance again, but withdrawBalance requires a balance to withdraw, so perhaps not directly. Standard reentrancy: in the wi...

Đoạn thinking_process cho thấy model mở rộng sang nhãn phụ:

> ...s calling withdrawBalance. Also, the contract name is Reentrance, which might be a hint. Now, are there other vulnerabilities? Arithmetic: no obvious overflow/underflow, since userBalance is uint, and += might overflow, but in Solidity 0.4.15, there are no checks for overflow, so it could overflow, but that's not directly in the code snippet, and the vulnerability type is Arithmetic, which might include unchecked arithmetic operations. But in this case, addToBalance uses +=, which in Solidity 0.4.15 doesn't check f...

Giải thích dựa trên thinking_process:

Model nhận ra đúng reentrancy, nhưng thinking_process tiếp tục tự hỏi “are there other vulnerabilities?” rồi xét thêm `Arithmetic`. Vì query details ghi nhận thêm `Arithmetic`, EMT không thể pass. Đây là một ví dụ rất rõ: TOP-k đúng vì reentrancy ở rank 1, còn EMT fail vì output không còn là exact single-label.

## Kết luận

Khoảng cách giữa EMT và TOP-k của `Reentrancy_Attacks` chủ yếu không phải vì model không biết phát hiện reentrancy. Ngược lại, trong phần lớn trường hợp, model nhận ra đúng reentrancy và đặt nó ở vị trí đầu. Vấn đề là model thường tiếp tục mở rộng reasoning sang các loại lỗi khác, rồi sinh thêm prediction phụ.

Vì vậy:

- TOP-k cao vì chỉ cần `Reentrancy_Attacks` xuất hiện ở top prediction.
- EMT thấp vì yêu cầu output chỉ có đúng một prediction và prediction đó phải là `Reentrancy_Attacks`.
- Thinking_process cho thấy nguyên nhân chính là **over-prediction/multi-label output**: model nhận đúng lỗi chính, nhưng không kiểm soát tốt việc thêm nhãn phụ.
