# Hallucinated Reasoning - RQ3

## Mục tiêu

Báo cáo này truy vết **Hallucinated Reasoning / Suy luận ảo giác** trong các file JSON tại `LOGs/my_results_l5`, đặc biệt ở trường `thinking_process`, bằng cách đối chiếu với source Solidity tương ứng và ground truth trong `Description/smartbugs_dataset.csv`.

Trong báo cáo này, một trường hợp được xem là hallucinated reasoning khi mô hình:

- Gán thêm biến, trạng thái, vai trò hoặc cơ chế tấn công không xuất hiện trong code.
- Suy luận về trạng thái của contract ngoài dù source chỉ cung cấp một địa chỉ hoặc low-level call, không có code của contract ngoài.
- Khẳng định thiếu guard hoặc thiếu trạng thái bảo vệ trong khi source có biến/logic guard tương ứng.
- Dùng giả định ngoài code để củng cố nhãn vulnerability.

## Kết luận tổng quan

Có. Mô hình có đưa ra các giả định không được hỗ trợ trực tiếp bởi code. Xu hướng rõ nhất là: khi thấy `call`, `transfer`, hoặc callback, mô hình thường mở rộng suy luận sang reentrancy, malicious contract, drain funds, attacker-controlled state, hoặc admin role dù các trạng thái đó không tồn tại trong contract đang phân tích.

Điều này đặc biệt dễ xảy ra với nhóm `unchecked_low_level_calls`: mô hình phát hiện đúng dấu hiệu low-level call chưa check return value, nhưng phần `thinking_process` và đôi khi cả `causality` lại thêm các hệ quả như "drain funds", "unauthorized fund transfers", "payable function", hoặc "external contract state" mà source không chứng minh.

## Dẫn chứng 1 - `wallet_02_refund_nosub.sol`

- JSON model output: [LOGs/my_results_l5/access_control/result_wallet_02_refund_nosub.json](../LOGs/my_results_l5/access_control/result_wallet_02_refund_nosub.json)
- Source: `smartbugs_dataset/access_control/wallet_02_refund_nosub.sol`
- Ground truth label: `access_control`

Trong source, contract chỉ có các state chính: `creator` và `balances`. Hàm `withdraw` kiểm tra `amount <= balances[msg.sender]`, gọi `msg.sender.transfer(amount)`, rồi trừ balance. Hàm `refund` gọi `msg.sender.transfer(balances[msg.sender])` nhưng không cập nhật `balances[msg.sender]`.

Phần `thinking_process` lại suy luận: attacker có thể dùng "self-destructing contract" để gọi `withdraw` nhiều lần, và mô tả state là "balance mapping and total balance". Đây là suy luận vượt quá code:

- Không có contract attacker hoặc cơ chế `selfdestruct` trong source.
- Không có biến `total balance` riêng; chỉ có mapping `balances` và Ether balance mặc định của contract.
- Vấn đề rõ nhất của `refund` là không trừ balance sau khi refund, nhưng mô hình trộn thêm cơ chế reentrancy/self-destruct không có bằng chứng trực tiếp.

Đánh giá: hallucination ở mức cơ chế khai thác. Mô hình nhận ra một lỗi thật, nhưng giải thích bằng một kịch bản attacker không tồn tại trong code.

## Dẫn chứng 2 - `0xd5967fed03e85d1cce44cab284695b41bc675b5c.sol`

- JSON model output: [LOGs/my_results_l5/unchecked_low_level_calls/result_0xd5967fed03e85d1cce44cab284695b41bc675b5c.json](../LOGs/my_results_l5/unchecked_low_level_calls/result_0xd5967fed03e85d1cce44cab284695b41bc675b5c.json)
- Source: `smartbugs_dataset/unchecked_low_level_calls/0xd5967fed03e85d1cce44cab284695b41bc675b5c.sol`
- Ground truth label: `unchecked_low_level_calls`

Source chỉ có hàm `transfer(address from,address caddress,address[] _tos,uint v)` lặp qua `_tos` và gọi:

```solidity
caddress.call(id,from,_tos[i],v);
```

Đây là unchecked low-level call hợp lệ để đánh dấu. Tuy nhiên, `thinking_process` và `causality` mở rộng thành: attacker có thể set `caddress` thành reentrant contract để "drain funds", gây "unauthorized fund transfers", hoặc manipulate state.

Những giả định này không được source hỗ trợ:

- Contract `demo` không có Ether balance logic, không có mapping balance, không có withdraw/deposit.
- Source không chứa code của `caddress`, nên không thể kết luận contract ngoài có reentrant behavior.
- `caddress.call(...)` gọi selector `transferFrom(address,address,uint256)`, nhưng bản thân source không chứng minh có fund drain từ contract này.

Đánh giá: hallucination ở mức hậu quả khai thác. Nhãn `Unchecked_External_Calls` có căn cứ, nhưng phần reasoning thêm "drain funds" và "state manipulation" không có trong code.

## Dẫn chứng 3 - `0xf2570186500a46986f3139f65afedc2afe4f445d.sol`

- JSON model output: [LOGs/my_results_l5/unchecked_low_level_calls/result_0xf2570186500a46986f3139f65afedc2afe4f445d.json](../LOGs/my_results_l5/unchecked_low_level_calls/result_0xf2570186500a46986f3139f65afedc2afe4f445d.json)
- Source: `smartbugs_dataset/unchecked_low_level_calls/0xf2570186500a46986f3139f65afedc2afe4f445d.sol`
- Ground truth label: `unchecked_low_level_calls`

Source chỉ định nghĩa một địa chỉ hard-coded:

```solidity
address fuck = 0xc63e7b1DEcE63A77eD7E4Aeef5efb3b05C81438D;
```

và gọi:

```solidity
fuck.call(bytes4(sha3("giveBlockReward()")));
```

Trong `thinking_process`, mô hình nói `giveBlockReward()` "might be a payable function", có thể "send Ether", "reenter back to this contract", hoặc nếu `fuck` bị attacker control thì có thể exploit. Đây là các giả định không được chứng minh:

- `fuck` là địa chỉ hard-coded, không phải input người dùng trong source này.
- Source không cung cấp code của contract tại địa chỉ `fuck`.
- Contract hiện tại không có state tài chính hoặc hàm withdraw/deposit để reentry có thể drain.
- Việc `giveBlockReward()` payable hay gửi Ether là phỏng đoán bên ngoài code.

Đánh giá: hallucination ở mức external-state speculation. Mô hình đúng khi thấy unchecked `call`, nhưng tự thêm tính chất của contract ngoài.

## Dẫn chứng 4 - `0x89c1b3807d4c67df034fffb62f3509561218d30b.sol`

- JSON model output: [LOGs/my_results_l5/unchecked_low_level_calls/result_0x89c1b3807d4c67df034fffb62f3509561218d30b.json](../LOGs/my_results_l5/unchecked_low_level_calls/result_0x89c1b3807d4c67df034fffb62f3509561218d30b.json)
- Source: `smartbugs_dataset/unchecked_low_level_calls/0x89c1b3807d4c67df034fffb62f3509561218d30b.sol`
- Ground truth label: `unchecked_low_level_calls`

Trong source `TownCrier`, contract có biến guard rõ ràng:

```solidity
bool public externalCallFlag;
```

Nhiều đoạn kiểm tra và set/reset guard này, ví dụ:

```solidity
if (externalCallFlag) { throw; }
externalCallFlag = true;
...
externalCallFlag = false;
```

Tuy nhiên, trong `thinking_process`, mô hình lại viết rằng "Standard reentrancy guard is missing in many places". Đây là nhận định mâu thuẫn với code, vì source thật sự có cơ chế guard `externalCallFlag`.

Ngoài ra, mô hình dùng cách gọi "admin" cho các check dựa trên `requests[0].requester`. Source không có biến `admin`; vai trò này là suy diễn từ `requests[0].requester`.

Đánh giá: hallucination ở mức bỏ qua state/guard tồn tại. Mô hình không chỉ thêm vai trò "admin" không có biến tương ứng, mà còn nói thiếu guard trong khi code có guard.

## Dẫn chứng 5 - `phishable.sol`

- JSON model output: [LOGs/my_results_l5/access_control/result_phishable.json](../LOGs/my_results_l5/access_control/result_phishable.json)
- Source: `smartbugs_dataset/access_control/phishable.sol`
- Ground truth label: `access_control`

Source có `owner`, fallback payable rỗng, và:

```solidity
require(tx.origin == owner);
_recipient.transfer(this.balance);
```

`thinking_process` nhiều lần nói `tx.origin` có thể bị "changed by proxies" hoặc bị "manipulated". Đây là cách diễn giải sai cơ chế:

- `tx.origin` là EOA khởi tạo transaction, không bị proxy contract "đổi" thành giá trị khác.
- Lỗi thật của pattern này là phishing: owner có thể bị dụ gọi một malicious contract, malicious contract gọi tiếp `withdrawAll`, khi đó `tx.origin` vẫn là owner còn `msg.sender` là malicious contract.
- Source không có biến/trạng thái "proxy" nào.

Mô hình sau đó còn suy luận sang Short_Addresses dựa trên `owner = _owner;`, nói attacker có thể đưa short address string khi deploy. Đây là hallucination rõ hơn:

- `_owner` là kiểu `address`, không phải string trong source.
- Không có xử lý calldata thủ công hoặc logic kiểm tra độ dài địa chỉ trong contract.
- Không có evidence trực tiếp cho Short_Addresses từ dòng `owner = _owner;`.

Đánh giá: hallucination ở cả cơ chế `tx.origin` và loại lỗi Short_Addresses. Model có nhắc đúng bề mặt access-control liên quan `tx.origin`, nhưng giải thích sai cách nó bị khai thác và thêm một nhãn không có cơ sở trong code.

## Mẫu lỗi lặp lại

1. **External call bị phóng đại thành drain funds**: Các contract chỉ có `call(...)` thường bị mô hình mô tả thêm "drain funds", dù không có balance/withdraw state.
2. **Contract ngoài bị gán tính chất không có trong source**: Mô hình giả định contract ngoài payable, reentrant, malicious hoặc attacker-controlled dù chỉ thấy một address/call selector.
3. **Role hallucination**: Các role như `admin` được mô hình đặt tên từ suy đoán, trong khi source dùng biến khác như `requests[0].requester`.
4. **Bỏ qua guard tồn tại**: Với `TownCrier`, mô hình nói thiếu reentrancy guard trong khi source có `externalCallFlag`.
5. **Cơ chế blockchain bị diễn giải sai**: Với `tx.origin`, mô hình nói có thể bị proxy thay đổi, trong khi lỗi thật là phishing qua call chain.

## Nhận xét cuối

Hallucinated reasoning không phải lúc nào cũng làm sai hoàn toàn nhãn dự đoán. Một số case vẫn phát hiện đúng dấu hiệu như unchecked low-level call. Tuy nhiên, phần `thinking_process` thường tự bù thêm bối cảnh tấn công thiếu bằng chứng, làm cho giải thích trở nên không đáng tin khi dùng để phân tích nguyên nhân hoặc viết báo cáo bảo mật.
