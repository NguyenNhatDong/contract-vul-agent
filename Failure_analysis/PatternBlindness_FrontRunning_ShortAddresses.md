# Pattern Blindness của Front-Running và Short Addresses

## Kết luận ngắn gọn

Model thất bại hoàn toàn với hai label này: `Front-running_Attacks` có `4/4` case không được phát hiện, và `Short_Addresses` có `1/1` case không được phát hiện. Các quote từ `thinking_process` cho thấy lỗi chính không phải thiếu dữ liệu code, mà là `Pattern Blindness`: model dùng định nghĩa quá hẹp cho front-running và sai threat model cho short-address attack.

## Metric tổng quan

| Label | N | MRR | TOP-1 | TOP-3 | TOP-max | EMT |
|---|---:|---:|---:|---:|---:|---:|
| `Front-running_Attacks` | 4 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.000000 |
| `Short_Addresses` | 1 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.000000 |

## Dẫn chứng chi tiết

### 1. `front_running/ERC20.sol` - ERC20 allowance race bị hiểu nhầm là token chuẩn không có logic DEX/auction

- JSON: `LOGs/my_results_l5/front_running/result_ERC20.json`
- Ground truth: `Front-running_Attacks`, evidence `110, 113`
- Metric status: rank `not_found`, reciprocal rank `0.000000`
- Model predicted labels: `(none)`

Model output liên quan:

- `(none)` - JSON không có vulnerability object nào.

Quote từ thinking_process về nhãn đúng bị phủ định hoặc hiểu hẹp:

> nsfer, approve, transferFrom are public, which might be fine for ERC20, but in a real scenario, you might want restricted access, but according to ERC20 standard, these are public. The constructor is public by default, but it's fine. No vulnerabilities in access control here. 5. Front-running_Attacks: This is about transactions being front-runned, often in decentralized exchanges or auctions. No such logic here. 6. Denial_of_Service_Attacks: Could be if functions can be called excessively, but no such thing here. 7. Short_Addresses: This is about not checking address lengths, e.g., not using address payable or checking for zero ...

Quote từ thinking_process về hướng nhãn thay thế:

> First, I am considering the code provided. It's a Solidity smart contract with a SafeMath library and an ERC20 token contract. I need to analyze it for vulnerabilities based on the specified types: Reentrancy_Attacks, Arithmetic, Time_Manipulation, Access_Control, Front-running_Attacks, Denial_of_Service_Attacks, Short_Addresses, Insecure_Randomness, Unchecked_External_Calls, or "Other" if none match. I must use ONLY the provided code_with_lines as evidence, not invent line numbers. Evidence must come directly from the code. If a vulnerability can't be supported by explicit code, I shouldn't output it. The vulnerability types are fixed, so I need to map any issues to these categories. ...

Giải thích:

Model prediction là `(none)`. Model đồng nhất front-running với các ngữ cảnh như DEX/auction nên bỏ qua approve/allowance race trong ERC20. Quote cho thấy nó thấy `approve` và `allowance`, nhưng kết luận `No such logic here` vì không có logic giao dịch quen thuộc.

Vì quote trên cho thấy model tự loại bỏ hoặc định nghĩa quá hẹp nhãn đúng, nên dù có đọc được cấu trúc code, nó không đưa `Front-running_Attacks`/`Short_Addresses` vào output. Kết quả là rank `not_found` và reciprocal rank `0`.

### 2. `front_running/eth_tx_order_dependence_minimal.sol` - Transaction-order dependence bị thay bằng reentrancy

- JSON: `LOGs/my_results_l5/front_running/result_eth_tx_order_dependence_minimal.json`
- Ground truth: `Front-running_Attacks`, evidence `23, 31`
- Metric status: rank `not_found`, reciprocal rank `0.000000`
- Model predicted labels: `Reentrancy_Attacks | Reentrancy_Attacks`

Model output liên quan:

- `Reentrancy_Attacks` tại `setReward`, evidence `23`: `owner.transfer(reward);`
- `Reentrancy_Attacks` tại `claimReward`, evidence `31`: `msg.sender.transfer(reward);`

Quote từ thinking_process về nhãn đúng bị phủ định hoặc hiểu hẹp:

> Attacks covers this. 4. **Arithmetic**: No obvious arithmetic overflows or underflows. Rewards are uint, but no operations like addition or subtraction that could cause issues. 5. **Time Manipulation**: No timestamps or blocks used, so probably not. 6. **Front-running Attacks**: No transactions that depend on order, like in a lottery or something. 7. **Denial_of_Service_Attacks**: Not clear, no functions that could be spammed with high gas or something. 8. **Short_Addresses**: No address handling that could be affected by short addresses (e.g., 0x vs. shortened addresses). 9. **Insecure_Randomness**: No randomness used. 10. **Other**: If none, but I think ...

Quote từ thinking_process về hướng nhãn thay thế:

> d I need to analyze the given Solidity code for vulnerabilities. The code is provided with line numbers, but I must use only the provided code and not invent line numbers. I have to base my findings solely on the code_with_lines. The vulnerability types I must choose from are: - Reentrancy_Attacks - Arithmetic - Time_Manipulation - Access_Control - Front-running_Attacks - Denial_of_Service_Attacks - Short_Addresses - Insecure_Randomness - Unchecked_External Calls - If none, use "Other" I need to identify all vulnerabilities that can be directly inferred from the code. If no vulnerabilities, return an empty array. Now, ...

Giải thích:

Model prediction là `Reentrancy_Attacks`, `Reentrancy_Attacks`. Model thấy `transfer` trước cập nhật state và thay thế nhãn bằng reentrancy. Nó không coi `setReward/claimReward` là phụ thuộc thứ tự giao dịch, dù ground truth chính là transaction-order dependence.

Vì quote trên cho thấy model tự loại bỏ hoặc định nghĩa quá hẹp nhãn đúng, nên dù có đọc được cấu trúc code, nó không đưa `Front-running_Attacks`/`Short_Addresses` vào output. Kết quả là rank `not_found` và reciprocal rank `0`.

### 3. `front_running/FindThisHash.sol` - Hash puzzle bị coi là intended functionality

- JSON: `LOGs/my_results_l5/front_running/result_FindThisHash.json`
- Ground truth: `Front-running_Attacks`, evidence `17`
- Metric status: rank `not_found`, reciprocal rank `0.000000`
- Model predicted labels: `(none)`

Model output liên quan:

- `(none)` - JSON không có vulnerability object nào.

Quote từ thinking_process về nhãn đúng bị phủ định hoặc hiểu hẹp:

> rong, but that's not a vulnerability; it's intentional. No access control issues apparent. Front-running_Attacks: This could be if there's a public function that can be front-run, but here, the solve function requires a specific input, so it's not like a simple payable function. No obvious front-running. Denial_of_Service_Attacks: Not clear, no functions that could be spammed or something. Short_Addresses: In Solidity, addresses can be shortened if they start with 0x, but this code doesn't handle addresses; it's using msg.sender for transfer, which is standard. No vulnerability here. Insecure_Randomness: No randomness in this code. Unchecked_External_Calls: The transfer ...

Quote từ thinking_process về hướng nhãn thay thế:

> ontract security expert, and I need to analyze the given Solidity code for vulnerabilities. The code is provided with line numbers, and I must use only that code as evidence. I can't invent line numbers or add anything not in the code. The vulnerability types to choose from are: Reentrancy_Attacks, Arithmetic, Time_Manipulation, Access_Control, Front-running_Attacks, Denial_of_Service_Attacks, Short_Addresses, Insecure_Randomness, Unchecked_External_Calls. If none, use "Other". The code is: 7: pragma solidity ^0.4.22; 8: 9: contract FindThisHash { 10: bytes32 constant public hash = 0xb5b5b97fafd9855eec9b41f74dfb6c38f5951141f9a3ecd7f44d5479b630ee0a; 11: 12: constructor() public payable {} 13: 14: function solve(string solution) public { 15: ...

Giải thích:

Model prediction là `(none)`. Model xem bài toán hash puzzle là chức năng dự định, không nhận ra lời giải được public trong mempool có thể bị copy và front-run trước khi nhận thưởng.

Vì quote trên cho thấy model tự loại bỏ hoặc định nghĩa quá hẹp nhãn đúng, nên dù có đọc được cấu trúc code, nó không đưa `Front-running_Attacks`/`Short_Addresses` vào output. Kết quả là rank `not_found` và reciprocal rank `0`.

### 4. `front_running/odds_and_evens.sol` - Game hai người bị bỏ qua front-running vì không có blockhash

- JSON: `LOGs/my_results_l5/front_running/result_odds_and_evens.json`
- Ground truth: `Front-running_Attacks`, evidence `25, 28`
- Metric status: rank `not_found`, reciprocal rank `0.000000`
- Model predicted labels: `Unchecked_External_Calls | Unchecked_External_Calls`

Model output liên quan:

- `Unchecked_External_Calls` tại `andTheWinnerIs`, evidence `38-42`: `res = players[0].addr.send(1800 finney);`
- `Unchecked_External_Calls` tại `getProfit`, evidence `50`: `bool res = msg.sender.send(this.balance);`

Quote từ thinking_process về nhãn đúng bị phủ định hoặc hiểu hẹp:

> k. But the contract itself doesn't call any external functions that could re-enter. - In andTheWinnerIs, it's sending to external addresses, but no function calls, so no reentrancy. 6. **Time_Manipulation**: No time-dependent logic in this contract. 7. **Front-running_Attacks**: No obvious issues, like relying on blockhash or anything. 8. **Denial_of_Service_Attacks**: Could be if someone spam calls play, but each call requires 1 ether, so it's pay-per-play, might not be denial of service. 9. **Short_Addresses**: Addresses are used as is, no check for short addresses or checksums. - In Solidity, addresses are 20 bytes, and the code ...

Quote từ thinking_process về hướng nhãn thay thế:

> First, I am considering the code provided. It's a Solidity smart contract named OddsAndEvens. I need to analyze it for vulnerabilities based on the specified types: Reentrancy_Attacks, Arithmetic, Time_Manipulation, Access_Control, Front-running_Attacks, Denial_of_Service_Attacks, Short_Addresses, Insecure_Randomness, Unchecked_External Calls, or "Other" if none match. The code has a struct Player with address and uint, an array of two players, a counter tot, an owner address, and functions: constructor, play, andTheWinnerIs (private), and getProfit. I must use only the provided code_with_lines as evidence, not invent line numbers. Evidence must be direct from the code. Vulnerability types to consider: - ...

Giải thích:

Model prediction là `Unchecked_External_Calls`, `Unchecked_External_Calls`. Model tìm dấu hiệu front-running quá hẹp, như `blockhash`, rồi chuyển sang unchecked send. Nó bỏ qua việc người chơi thứ hai có thể quan sát lựa chọn trước đó và đặt số thắng.

Vì quote trên cho thấy model tự loại bỏ hoặc định nghĩa quá hẹp nhãn đúng, nên dù có đọc được cấu trúc code, nó không đưa `Front-running_Attacks`/`Short_Addresses` vào output. Kết quả là rank `not_found` và reciprocal rank `0`.

### 5. `short_addresses/short_address_example.sol` - Short address bị hiểu sai là vấn đề Solidity fixed-size address

- JSON: `LOGs/my_results_l5/short_addresses/result_short_address_example.json`
- Ground truth: `Short_Addresses`, evidence `18`
- Metric status: rank `not_found`, reciprocal rank `0.000000`
- Model predicted labels: `Arithmetic | Access_Control`

Model output liên quan:

- `Arithmetic` tại `sendCoin`, evidence `21`: `balances[to] += amount;`
- `Access_Control` tại `MyToken`, evidence `15`: `balances[tx.origin] = 10000;`

Quote từ thinking_process về nhãn đúng bị phủ định hoặc hiểu hẹp:

> ess_Control" might cover it. The constructor allows anyone to deploy and get tokens, so it's an access control issue. Also, the sendCoin function has no restrictions, so anyone can transfer tokens. But the constructor is specific. Now, is there a Denial_of_Service? Probably not. Short_Addresses: Not present. Insecure_Randomness: No. Unchecked_External_Calls: No external calls. Reentrancy: No. Front-running: No. Time_Manipulation: No. So, likely two vulnerabilities: Arithmetic and Access_Control. But Arithmetic is underflow/overflow, and Access_Control is for the constructor. In the code, the balances mapping is used, and no initial supply control. Also, the constructor sets tx.origin, which might ...

Quote từ thinking_process về hướng nhãn thay thế:

> er, to, amount); 23: return true; 24: } 25: 26: function getBalance(address addr) constant returns(uint) { 27: return balances[addr]; 28: } 29: } I need to identify all vulnerabilities that can be directly inferred from this code. The vulnerability types are: Reentrancy_Attacks, Arithmetic, Time_Manipulation, Access_Control, Front-running_Attacks, Denial_of_Service_Attacks, Short_Addresses, Insecure_Randomness, Unchecked_External_Calls. If none, use "Other". Let me review the code step by step. - Line 7: pragma solidity ^0.4.11; This specifies the Solidity version. Version 0.4.11 is old and has known vulnerabilities, but I need to focus on the code itself. - Line 9-29: Contract definition ...

Giải thích:

Model prediction là `Arithmetic`, `Access_Control`. Model hiểu short address như vấn đề kiểu `address` trong Solidity, rồi phủ định vì địa chỉ là fixed-size. Nó không xét threat model ABI/input-padding ở tầng transaction/client, nên thay nhãn đúng bằng arithmetic/access-control.

Vì quote trên cho thấy model tự loại bỏ hoặc định nghĩa quá hẹp nhãn đúng, nên dù có đọc được cấu trúc code, nó không đưa `Front-running_Attacks`/`Short_Addresses` vào output. Kết quả là rank `not_found` và reciprocal rank `0`.

## Tổng hợp nguyên nhân

1. `Narrow Pattern Definition`: model thường chỉ tìm front-running trong các mẫu quen thuộc như DEX, auction, blockhash hoặc logic thị trường rõ ràng.

2. `Semantic Underfitting`: model không khái quát front-running thành phụ thuộc thứ tự giao dịch, nên bỏ qua approve race, hash puzzle, transaction-order dependence và trò chơi hai người.

3. `Wrong Threat Model`: với short address, model xét kiểu `address` trong Solidity là fixed-size, thay vì xét lỗi ABI/input-padding ở tầng transaction/client.

4. `Label Substitution`: khi không nhận ra nhãn đúng, model chuyển sang các nhãn có pattern cú pháp dễ thấy hơn như `Reentrancy_Attacks`, `Unchecked_External_Calls`, `Arithmetic`, hoặc `Access_Control`.

