# Detection Failure Analysis - LOGs/my_results_l5

## Mục tiêu và cách đánh giá

Nguồn model output: `LOGs/my_results_l5`

Ground truth: `Description/smartbugs_dataset.csv`

Một **Detection Failure** được tính khi ground truth của một contract có label lỗ hổng `L`, nhưng trong file JSON kết quả tương ứng, model **không dự đoán label `L` ở bất kỳ vị trí nào**. Điều này bao gồm các trường hợp:

- Model trả `status: Normal` dù ground truth có lỗ hổng.
- Model trả `status: Vulnerable` nhưng chỉ dự đoán sai loại lỗ hổng.
- Model trả `status: Error`, nên không có prediction hợp lệ trong `vulnerabilities`.

Các label được chuẩn hóa khi đối chiếu, ví dụ `Front-Running` -> `Front-running_Attacks`, `Reentrancy_Attack` -> `Reentrancy_Attacks`.

## Tổng quan

- Số JSON result trong `LOGs/my_results_l5`: 143
- Số ground-truth contract-label instances được đánh giá: 156
- Số Detection Failure hoàn toàn: 57
- Kết luận: **Có. Mô hình đã hoàn toàn bỏ lỡ nhiều lỗ hổng**, đặc biệt ở `Access_Control`, `Front-running_Attacks`, `Time_Manipulation`, `Unchecked_External_Calls`, và một số label hiếm như `Delegatecall`, `Logic_Error`, `Short_Addresses`.

## Detection Failure theo từng loại lỗ hổng

| Label | Số contract ground truth | Số bị bỏ lỡ hoàn toàn | Tỷ lệ miss |
|---|---:|---:|---:|
| Access_Control | 22 | 12 | 54.55% |
| Arithmetic | 18 | 5 | 27.78% |
| Delegatecall | 1 | 1 | 100.00% |
| Denial_of_Service_Attacks | 6 | 3 | 50.00% |
| Front-running_Attacks | 4 | 4 | 100.00% |
| Insecure_Randomness | 9 | 2 | 22.22% |
| Logic_Error | 4 | 4 | 100.00% |
| Other | 3 | 3 | 100.00% |
| Reentrancy_Attacks | 31 | 2 | 6.45% |
| Short_Addresses | 1 | 1 | 100.00% |
| Time_Manipulation | 5 | 4 | 80.00% |
| Unchecked_External_Calls | 52 | 16 | 30.77% |

## Phân tích chính

### 1. Access_Control

`Access_Control` là nhóm bị bỏ lỡ nhiều nhất theo số lượng tuyệt đối: 12/22 contract bị miss hoàn toàn.

Các dạng lỗi phổ biến:

- Model kết luận `Normal` dù contract có hàm public nguy hiểm hoặc delegatecall không kiểm soát.
- Model nhận thấy yếu tố access-control trong reasoning nhưng lại kết luận không phải vulnerability.
- Model dự đoán sang nhãn khác như `Short_Addresses`, `Reentrancy_Attacks`, hoặc `Arithmetic`, làm mất nhãn đúng.

### 2. Reentrancy_Attacks

`Reentrancy_Attacks` có tỷ lệ miss thấp hơn nhiều: 2/31 contract bị bỏ lỡ hoàn toàn. Tuy nhiên vẫn có case quan trọng model trả `Normal` dù thinking đã nhắc tới external call/reentrancy pattern.

Điều này cho thấy model thường nhạy với reentrancy, nhưng vẫn có thể bỏ sót khi vulnerability nằm trong modifier hoặc luồng gọi gián tiếp.

### 3. Front-running_Attacks và Time_Manipulation

`Front-running_Attacks` bị bỏ lỡ 4/4 contract, tức miss hoàn toàn toàn bộ label này trong tập `my_results_l5`.

`Time_Manipulation` bị bỏ lỡ 4/5 contract. Model thường chuyển các case này sang `Insecure_Randomness`, `Reentrancy_Attacks`, hoặc kết luận `Normal`.

### 4. Unchecked_External_Calls

`Unchecked_External_Calls` có 16/52 miss. Đây là nhóm có nhiều contract nhất, nên dù tỷ lệ thấp hơn `Access_Control`, số lượng lỗi vẫn đáng kể.

Một số case là lỗi phân loại: model thấy external call nhưng gọi là `Reentrancy_Attacks`. Một số case khác là lỗi output: thinking có nhắc đúng `Unchecked_External_Calls`, nhưng final JSON không parse được nên kết quả lưu thành `Error`.

## Dẫn chứng cụ thể

### Dẫn chứng 1 - Access_Control bị kết luận Normal

- JSON: [LOGs/my_results_l5/access_control/result_proxy.json](../LOGs/my_results_l5/access_control/result_proxy.json)
- Ground truth: `Access_Control`, evidence `19`
- Model output: `status: Normal`, `vulnerabilities_count: 0`
- Detection Failure: model không dự đoán bất kỳ vulnerability nào.

Trích từ `thinking_process`:

> "There's an owner variable, but no functions that check access control... The `forward` function is public, so anyone can call it. No vulnerability here directly."

Nhận xét: model nhìn thấy `forward` là public nhưng lại coi đây không phải vulnerability, dẫn tới bỏ lỡ hoàn toàn `Access_Control`.

### Dẫn chứng 2 - Access_Control bị phân loại sai thành Short_Addresses

- JSON: [LOGs/my_results_l5/access_control/result_phishable.json](../LOGs/my_results_l5/access_control/result_phishable.json)
- Ground truth: `Access_Control`, evidence `20`
- Model output: `status: Vulnerable`, prediction duy nhất là `Short_Addresses`
- Detection Failure: model phát hiện có vulnerability nhưng không phát hiện đúng loại `Access_Control`.

Trích từ `thinking_process`:

> "Perhaps Access_Control is not fully implemented, but it's based on tx.origin... However, no direct vulnerability in access control here."

Nhận xét: đây là pattern access-control dựa trên `tx.origin`, nhưng model tự loại bỏ nhãn `Access_Control` và chuyển sang nhãn sai.

### Dẫn chứng 3 - Reentrancy_Attacks bị kết luận Normal

- JSON: [LOGs/my_results_l5/reentrancy/result_modifier_reentrancy.json](../LOGs/my_results_l5/reentrancy/result_modifier_reentrancy.json)
- Ground truth: `Reentrancy_Attacks`, evidence `15`
- Model output: `status: Normal`, `vulnerabilities_count: 0`
- Detection Failure: model bỏ lỡ hoàn toàn reentrancy.

Trích từ `thinking_process`:

> "Perhaps there's no vulnerability... In ModifierEntrancy.airDrop(), it calls Bank(msg.sender).supportsToken(), which is an external call... but that's not necessarily a vulnerability."

Nhận xét: model nhận ra external call trong luồng modifier/airDrop nhưng không liên kết nó với reentrancy pattern trong ground truth.

### Dẫn chứng 4 - Front-running_Attacks bị kết luận Normal

- JSON: [LOGs/my_results_l5/front_running/result_ERC20.json](../LOGs/my_results_l5/front_running/result_ERC20.json)
- Ground truth: `Front-running_Attacks`, evidence `110`, `113`
- Model output: `status: Normal`, `vulnerabilities_count: 0`
- Detection Failure: model bỏ lỡ hoàn toàn front-running.

Trích từ `thinking_process`:

> "But perhaps there's no vulnerability here... Functions like transfer, approve, transferFrom are public, which might be fine for ERC20..."

Nhận xét: model không nhận ra vấn đề front-running/race-condition quen thuộc quanh ERC20 `approve`, nên trả về Normal.

### Dẫn chứng 5 - Unchecked_External_Calls được nghĩ tới nhưng output Error

- JSON: [LOGs/my_results_l5/unchecked_low_level_calls/result_0x89c1b3807d4c67df034fffb62f3509561218d30b.json](../LOGs/my_results_l5/unchecked_low_level_calls/result_0x89c1b3807d4c67df034fffb62f3509561218d30b.json)
- Ground truth: `Unchecked_External_Calls`, evidence `162`, `175`, `180`, `192`
- Model output: `status: Error`
- Error: `Model response could not be parsed as valid analysis JSON: No JSON found (attempt 3)`
- Detection Failure: không có prediction hợp lệ trong `vulnerabilities`.

Trích từ `thinking_process`:

> "Now, for the JSON, I need to output vulnerabilities. First vulnerability: Unchecked_External_Calls. Evidence: line 180 in deliver function."

Nhận xét: đây là lỗi output-format/parsing nghiêm trọng. Model đã nghĩ tới đúng nhãn `Unchecked_External_Calls`, nhưng không sinh JSON hợp lệ nên hệ thống lưu `status: Error`; kết quả cuối cùng vẫn là detection failure.

## Kết luận

Mô hình **có hoàn toàn bỏ lỡ** nhiều lỗ hổng trong `LOGs/my_results_l5`.

Các nguyên nhân chính quan sát được từ model response và `thinking_process`:

1. **Kết luận Normal sai**: model thấy một số dấu hiệu nguy hiểm nhưng cho rằng không đủ trực tiếp để báo cáo.
2. **Sai loại lỗ hổng**: model phát hiện có vấn đề nhưng map sang nhãn khác, ví dụ `Access_Control` -> `Short_Addresses` hoặc `Unchecked_External_Calls` -> `Reentrancy_Attacks`.
3. **Lỗi sinh JSON**: model reasoning đúng một phần nhưng không tạo JSON hợp lệ, dẫn tới `status: Error`.
4. **Không nhận ra pattern đặc thù**: đặc biệt rõ ở `Front-running_Attacks`, `Time_Manipulation`, `Logic_Error`, `Delegatecall`, và `Short_Addresses`.

Nhìn chung, failure không chỉ là lỗi parser; phần lớn là lỗi nhận diện/ phân loại vulnerability trong reasoning của model. Tuy nhiên, một số case như `result_0x89c1...json` cho thấy lỗi format output cũng có thể biến một phân tích đúng trong thinking thành một detection failure ở kết quả cuối.
