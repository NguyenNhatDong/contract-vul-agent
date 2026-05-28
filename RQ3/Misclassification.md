# Misclassification Analysis - LOGs/my_results_l5

## Mục tiêu và cách đánh giá

Nguồn model output: `LOGs/my_results_l5`

Ground truth: `Description/smartbugs_dataset.csv`

Một **Misclassification** được tính khi:

1. Ground truth của contract có label lỗ hổng `L`.
2. Model có ít nhất một prediction trong `vulnerabilities`.
3. Không prediction nào có label `L`.
4. Tức là model không im lặng hoàn toàn, nhưng đã **gán sai loại lỗ hổng**.

Các case `status: Normal` không có prediction hoặc `status: Error` không có JSON hợp lệ được xem là Detection Failure, không phải trọng tâm của báo cáo này. Các label được chuẩn hóa khi đối chiếu, ví dụ `Front-Running` -> `Front-running_Attacks`, `Reentrancy_Attack` -> `Reentrancy_Attacks`.

## Tổng quan

- Số ground-truth contract-label instances: 156
- Số misclassification instances: 34
- Nhóm bị nhầm nhiều nhất theo số lượng:
  - `Unchecked_External_Calls`: 12 case
  - `Access_Control`: 6 case
  - `Denial_of_Service_Attacks`: 3 case
  - `Time_Manipulation`: 3 case
  - `Other`: 3 case

## Xu hướng nhầm lẫn theo từng loại lỗ hổng

| Ground-truth label | Số contract ground truth | Số case phân loại sai | Xu hướng nhầm chính |
|---|---:|---:|---|
| Access_Control | 22 | 6 | Hay bị gán thành `Reentrancy_Attacks`, sau đó là `Arithmetic`, `Short_Addresses`, `Time_Manipulation`, `Unchecked_External_Calls` |
| Arithmetic | 18 | 2 | Bị gán thành `Access_Control` hoặc `Reentrancy_Attacks` |
| Delegatecall | 1 | 0 | Không có misclassification có prediction; case này thuộc nhóm không phát hiện |
| Denial_of_Service_Attacks | 6 | 3 | Chủ yếu bị gán thành `Reentrancy_Attacks`; đôi khi kèm `Time_Manipulation`, `Unchecked_External_Calls` |
| Front-running_Attacks | 4 | 2 | Bị gán thành `Reentrancy_Attacks` hoặc `Unchecked_External_Calls` |
| Insecure_Randomness | 9 | 1 | Bị gán thành `Reentrancy_Attacks` |
| Logic_Error | 4 | 0 | Không có misclassification có prediction; các case thuộc nhóm không phát hiện |
| Other | 3 | 3 | Bị gán thành các nhãn cụ thể như `Reentrancy_Attacks`, `Insecure_Randomness`, `Time_Manipulation`, `Denial_of_Service_Attacks` |
| Reentrancy_Attacks | 31 | 1 | Bị gán thành `Access_Control` và `Arithmetic` trong cùng một file |
| Short_Addresses | 1 | 1 | Bị gán thành `Access_Control` và `Arithmetic` |
| Time_Manipulation | 5 | 3 | Hay bị gán thành `Reentrancy_Attacks`; cũng bị gán thành `Insecure_Randomness`, `Denial_of_Service_Attacks` |
| Unchecked_External_Calls | 52 | 12 | Rất hay bị gán thành `Reentrancy_Attacks`; ngoài ra còn bị gán thành `Arithmetic`, `Access_Control`, `Front-running_Attacks`, `Insecure_Randomness` |

## Phân tích theo nhóm lỗ hổng

### 1. Access_Control

`Access_Control` có 6 case bị phân loại sai. Xu hướng nổi bật là model thấy một hành vi nguy hiểm nhưng không quy về quyền truy cập sai:

- Nếu có external call hoặc transfer, model dễ chuyển sang `Reentrancy_Attacks`.
- Nếu có constructor/init sai hoặc thay đổi trạng thái, model đôi khi chuyển sang `Arithmetic`.
- Với pattern `tx.origin`, model có thể nhắc tới access control trong thinking nhưng lại loại bỏ nó và chọn nhãn khác.

### 2. Reentrancy_Attacks

`Reentrancy_Attacks` chỉ có 1 case phân loại sai trong nhóm có prediction. Điều này cho thấy model khá nhạy với reentrancy, nhưng vẫn có thể miss khi luồng reentrancy không nằm ở pattern withdraw/call đơn giản.

Xu hướng ngược lại lại rất mạnh: nhiều label khác bị model gán nhầm thành `Reentrancy_Attacks`. Đây là dấu hiệu model đang over-predict reentrancy khi thấy external call hoặc transfer.

### 3. Unchecked_External_Calls

`Unchecked_External_Calls` là nhóm bị phân loại sai nhiều nhất: 12 case. Xu hướng chính là nhầm sang `Reentrancy_Attacks`.

Nguyên nhân quan sát từ `thinking_process`: model nhận diện external call như `.call`, `.call.value`, hoặc transfer logic, nhưng tập trung vào khả năng reentry thay vì việc return value không được kiểm tra hoặc low-level call không được xử lý đúng.

### 4. Front-running_Attacks và Time_Manipulation

`Front-running_Attacks` bị nhầm thành `Reentrancy_Attacks` hoặc `Unchecked_External_Calls`. Model thường không nhận diện đúng yếu tố transaction ordering/approve race.

`Time_Manipulation` bị nhầm sang `Insecure_Randomness`, `Reentrancy_Attacks`, hoặc `Denial_of_Service_Attacks`. Với các contract lottery, model thường coi việc dùng block data là randomness yếu thay vì timestamp/time manipulation.

## Dẫn chứng cụ thể

### Dẫn chứng 1 - Access_Control bị gán nhầm thành Short_Addresses

- JSON: [LOGs/my_results_l5/access_control/result_phishable.json](../LOGs/my_results_l5/access_control/result_phishable.json)
- Ground truth: `Access_Control`, evidence `20`
- Model prediction: `Short_Addresses`
- Status: `Vulnerable`

Trích từ `thinking_process`:

> "Perhaps Access_Control is not fully implemented, but it's based on tx.origin... However, no direct vulnerability in access control here."

Nhận xét: model đã nhìn thấy `tx.origin` trong logic kiểm soát quyền, nhưng lại kết luận không phải access-control vulnerability và chuyển sang nhãn `Short_Addresses`. Đây là phân loại sai rõ ràng.

### Dẫn chứng 2 - Access_Control bị gán nhầm thành Arithmetic

- JSON: [LOGs/my_results_l5/access_control/result_wallet_03_wrong_constructor.json](../LOGs/my_results_l5/access_control/result_wallet_03_wrong_constructor.json)
- Ground truth: `Access_Control`, evidence `19`
- Model prediction: `Arithmetic`
- Status: `Vulnerable`

Trích từ `thinking_process`:

> "Access control: the migrate function requires creator == msg.sender, so only creator can migrate. That seems fine. Now, back to deposit: potential overflow."

Nhận xét: vulnerability đúng nằm ở constructor/init sai làm sai quyền sở hữu, nhưng model bỏ qua hướng access control và tập trung vào overflow trong `deposit`, dẫn tới nhãn `Arithmetic`.

### Dẫn chứng 3 - Denial_of_Service_Attacks bị gán nhầm thành Reentrancy/Time/Unchecked

- JSON: [LOGs/my_results_l5/denial_of_service/result_list_dos.json](../LOGs/my_results_l5/denial_of_service/result_list_dos.json)
- Ground truth: `Denial_of_Service_Attacks`, evidence `46`, `48`
- Model predictions: `Reentrancy_Attacks`, `Time_Manipulation`, `Unchecked_External_Calls`
- Status: `Vulnerable`

Trích từ `thinking_process`:

> "This function handles lending money... if 12 hours have passed... it sends money back to the sender and creditor, and resets some state."

Nhận xét: model chú ý tới external transfers và timestamp nên gán sang reentrancy/time/unchecked call. Nó không nhận ra bản chất DoS của danh sách/vòng xử lý hoặc trạng thái có thể làm contract bị kẹt.

### Dẫn chứng 4 - Front-running_Attacks bị gán nhầm thành Reentrancy_Attacks

- JSON: [LOGs/my_results_l5/front_running/result_eth_tx_order_dependence_minimal.json](../LOGs/my_results_l5/front_running/result_eth_tx_order_dependence_minimal.json)
- Ground truth: `Front-running_Attacks`, evidence `23`, `31`
- Model predictions: `Reentrancy_Attacks`, `Reentrancy_Attacks`
- Status: `Vulnerable`

Trích từ `thinking_process`:

> "claimReward: Line 31 transfers before setting claimed to true."

Nhận xét: model tập trung vào thứ tự transfer/state update và gọi đây là reentrancy. Ground truth lại là transaction-order dependence/front-running, nên đây là nhầm loại vulnerability.

### Dẫn chứng 5 - Unchecked_External_Calls bị gán nhầm thành Reentrancy_Attacks

- JSON: [LOGs/my_results_l5/unchecked_low_level_calls/result_0xdb1c55f6926e7d847ddf8678905ad871a68199d2.json](../LOGs/my_results_l5/unchecked_low_level_calls/result_0xdb1c55f6926e7d847ddf8678905ad871a68199d2.json)
- Ground truth: `Unchecked_External_Calls`, evidence `39`
- Model prediction: `Reentrancy_Attacks`
- Status: `Vulnerable`

Trích từ `thinking_process`:

> "Line 13: function() public payable{}... This is a fallback function that accepts ETH... GetFreebie... Owner.transfer(this.balance) and msg.sender.transfer(this.balance). This looks suspicious."

Nhận xét: model phát hiện luồng chuyển tiền và external interaction nhưng quy nó về reentrancy. Nó không gắn đúng với nhãn ground truth là unchecked external call tại evidence `39`.

## Kết luận

Mô hình **có gán sai nhãn loại lỗ hổng** trong nhiều trường hợp.

Xu hướng nổi bật:

1. **Over-predict `Reentrancy_Attacks`**: nhiều `Unchecked_External_Calls`, `Denial_of_Service_Attacks`, `Time_Manipulation`, `Front-running_Attacks`, và `Other` bị kéo về reentrancy khi model thấy external call/transfer.
2. **Under-recognize `Access_Control`**: model thường nhắc tới quyền truy cập trong reasoning nhưng tự loại bỏ nó, rồi chọn nhãn khác.
3. **Nhầm `Time_Manipulation` với `Insecure_Randomness`**: đặc biệt trong lottery/randomness contract dùng timestamp hoặc block data.
4. **Không nắm chắc các pattern đặc thù** như front-running/transaction ordering, short address, delegatecall, logic error; nếu có dự đoán, model thường gán sang nhãn phổ biến hơn.

Tóm lại, misclassification chủ yếu không phải do parser, mà do model ưu tiên các pattern quen thuộc như reentrancy/arithmetic hơn các nhãn tinh tế hơn như access control, front-running, unchecked external calls, time manipulation, và các lỗi logic đặc thù.
