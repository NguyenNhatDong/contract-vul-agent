# Priority Inversion của Unchecked Low-Level Calls

## Kết luận ngắn gọn

`Unchecked_External_Calls` có MRR thấp (`0.365385`) vì model thường không đặt nhãn này ở vị trí đầu tiên. Trong nhiều case, `thinking_process` đã nhận ra low-level call hoặc việc không kiểm tra return value, nhưng output lại ưu tiên các nhãn có câu chuyện tác động mạnh hơn như `Access_Control`, `Reentrancy_Attacks`, hoặc `Arithmetic`.

Nói cách khác, đây không chỉ là lỗi detection failure. Đây là lỗi `Priority Inversion`: model thấy đúng dấu mối, nhưng xếp nó quá trễ trong danh sách prediction.

## Metric liên quan

| Label | Queries | Found | Not found | MRR |
|---|---:|---:|---:|---:|
| `Unchecked_External_Calls` | 52 | 29 | 23 | 0.365385 |

Với MRR, rank càng trễ thì điểm càng giảm: rank 2 chỉ còn `1/2`, rank 3 chỉ còn `1/3`, rank 4 chỉ còn `1/4`, và `not_found` bằng `0`.

## Phân bố rank

| Nhóm rank | Số case | Tác động tới MRR |
|---|---:|---|
| Rank 1 | 12 | Đóng góp tối đa `1.0` mỗi case |
| Rank 2 | 9 | Mỗi case chỉ đóng góp `0.5` |
| Rank 3 | 6 | Mỗi case chỉ đóng góp `0.333333` |
| Rank 4+ | 2 | Mỗi case đóng góp tối đa `0.25` hoặc thấp hơn |
| Not found | 23 | Đóng góp `0` |

## Các nhãn thường đứng trước Unchecked_External_Calls

| Nhãn đứng trước | Số lần xuất hiện trước nhãn đúng | Ý nghĩa |
|---|---:|---|
| `Access_Control` | 13 | model xem khả năng chiếm quyền/ghi owner là vấn đề trung tâm nên đặt trước lỗi unchecked call. |
| `Reentrancy_Attacks` | 10 | model ưu tiên câu chuyện tấn công rút tiền hoặc external call trước state update, nên unchecked call bị đẩy xuống sau. |
| `Arithmetic` | 4 | model ưu tiên rủi ro overflow/underflow trong Solidity cũ, dù lỗi ground truth là unchecked low-level call. |

## 5 dẫn chứng chi tiết

### 1. `0x39cfd754c85023648bf003bea2dd498c5612abfa.sol`

- JSON: `LOGs/my_results_l5/unchecked_low_level_calls/result_0x39cfd754c85023648bf003bea2dd498c5612abfa.json`
- Rank của `Unchecked_External_Calls`: `4`
- Reciprocal rank: `0.250000`
- Thứ tự predicted labels: `Access_Control | Access_Control | Access_Control | Unchecked_External_Calls | Unchecked_External_Calls | Reentrancy_Attacks | Arithmetic`
- Các nhãn đứng trước: `Access_Control, Access_Control, Access_Control`

Model output liên quan:

- `Access_Control` tại `initTokenBank`, evidence `57`: `owner = msg.sender;`
- `Unchecked_External_Calls` tại `WithdrawToken`, evidence `44`: `token.call(bytes4(sha3("transfer(address,uint256)")),to,amount);`

Trích đoạn thinking_process về lỗi được ưu tiên trước:

> and confirmOwner to finalize the change. There's a modifier onlyOwner. - Contract Token: Inherits from Ownable. Has a function WithdrawToken to call transfer on a token. - Contract TokenBank: Inherits from Token. Has initTokenBank to set owner and MinDeposit. Has a fallback function for deposits, Deposit function to handle deposits, and functions to withdraw tokens or wei to holders. Now, I need to identify vulnerabilities. Start with Access_Control: This is common in smart contracts. Look for issues like uncontrolled access. In Ownable contract: - changeOwner sets newOwner but doesn't confirm it immediately. confirmOwner sets owner ...

Trích đoạn thinking_process về unchecked low-level call:

> sender]. No reentrancy guard. But Deposit is called by the fallback function, which is payable and calls Deposit. Then, WithdrawToHolder (line 87-101): payable, onlyOwner, and it sends ETH to _addr if Holders[_addr] >= _wei. In line 97: _addr.call.value(_wei)(); This is a low-level call to send ETH. If _addr is a malicious contract, it could reenter. Also, in WithdrawTokenToHolder (line 76-85): calls WithdrawToken, which makes an external call to a token's transfer function. WithdrawToken (line 39-45): calls token.transfer with sha3, which is a way to call the transfer function. But transfer in ERC223 or similar might ...

Giải thích:

`Unchecked_External_Calls` chỉ xuất hiện ở rank `4`, sau `Access_Control`, `Access_Control`, `Access_Control`. Điều này làm reciprocal rank của case này giảm còn `1/4`. model xem khả năng chiếm quyền/ghi owner là vấn đề trung tâm nên đặt trước lỗi unchecked call.

Dựa trên hai đoạn thinking trên, model không hoàn toàn mù với low-level call; vấn đề là nó xếp lỗi này sau các lỗi có mô tả tác động mạnh hơn. Vì MRR chỉ thưởng cao cho nhãn đúng xuất hiện sớm, thứ tự này trực tiếp kéo điểm của `Unchecked_External_Calls` xuống.

### 2. `0x3a0e9acd953ffc0dd18d63603488846a6b8b2b01.sol`

- JSON: `LOGs/my_results_l5/unchecked_low_level_calls/result_0x3a0e9acd953ffc0dd18d63603488846a6b8b2b01.json`
- Rank của `Unchecked_External_Calls`: `2`
- Reciprocal rank: `0.500000`
- Thứ tự predicted labels: `Access_Control | Unchecked_External_Calls | Unchecked_External_Calls | Reentrancy_Attacks | Arithmetic | Arithmetic`
- Các nhãn đứng trước: `Access_Control`

Model output liên quan:

- `Access_Control` tại `initTokenBank`, evidence `57`: `owner = msg.sender;`
- `Unchecked_External_Calls` tại `WithdrawToken`, evidence `44`: `token.call(bytes4(sha3("transfer(address,uint256)")),to,amount);`

Trích đoạn thinking_process về lỗi được ưu tiên trước:

> nsfer tokens. - Lines 48-104: TokenBank contract, which inherits from Token. It has deposit and withdrawal functions. I need to identify vulnerabilities. Let's go through each part. Starting with Ownable contract: - Line 11: address newOwner; - Line 12: address owner = msg.sender; // This sets the initial owner to the deployer. - Function changeOwner sets newOwner. - Function confirmOwner allows the newOwner to confirm and become the owner. - Modifier onlyOwner checks if msg.sender is owner. Potential issues: In Ownable, the owner is set to msg.sender at deployment, but there's no constructor or way ...

Trích đoạn thinking_process về unchecked low-level call:

> used in other functions, like WithdrawToHolder. Another function: WithdrawToHolder, line 87-101: function WithdrawToHolder(address _addr, uint _wei) public onlyOwner payable { if(Holders[msg.sender] > 0) { if(Holders[_addr] >= _wei) { _addr.call.value(_wei); Holders[_addr] -= _wei; } } } This allows the owner to withdraw wei from Holders to another address. But Holders[msg.sender] > 0 is checked, and then Holders[_addr] >= _wei. Potential reentrancy: Since it's using call to send ether, and if the _addr is a contract, it might reenter. Look at the call: _addr.call.value(_wei)(); This sends ether and if the call returns false, it might still deduct ...

Giải thích:

`Unchecked_External_Calls` chỉ xuất hiện ở rank `2`, sau `Access_Control`. Điều này làm reciprocal rank của case này giảm còn `1/2`. model xem khả năng chiếm quyền/ghi owner là vấn đề trung tâm nên đặt trước lỗi unchecked call.

Dựa trên hai đoạn thinking trên, model không hoàn toàn mù với low-level call; vấn đề là nó xếp lỗi này sau các lỗi có mô tả tác động mạnh hơn. Vì MRR chỉ thưởng cao cho nhãn đúng xuất hiện sớm, thứ tự này trực tiếp kéo điểm của `Unchecked_External_Calls` xuống.

### 3. `0x5aa88d2901c68fda244f1d0584400368d2c8e739.sol`

- JSON: `LOGs/my_results_l5/unchecked_low_level_calls/result_0x5aa88d2901c68fda244f1d0584400368d2c8e739.json`
- Rank của `Unchecked_External_Calls`: `2`
- Reciprocal rank: `0.500000`
- Thứ tự predicted labels: `Arithmetic | Unchecked_External_Calls`
- Các nhãn đứng trước: `Arithmetic`

Model output liên quan:

- `Arithmetic` tại `multiplicate`, evidence `36-39`: `if(msg.value>=this.balance) { adr.transfer(this.balance+msg.value); }`
- `Unchecked_External_Calls` tại `Command`, evidence `29`: `adr.call.value(msg.value)(data);`

Trích đoạn thinking_process về lỗi được ưu tiên trước:

> y: - state: The contract's balance before and after the call. - guard: None, or minimal guard. - transition: The call might execute arbitrary code. - capability: Attacker can drain funds. - outcome: Funds are lost or duplicated. Now, Arithmetic vulnerabilities: Look for unchecked overflows/underflows. In multiplicate, there's an if condition: if(msg.value >= this.balance) Then it transfers this.balance + msg.value. In Solidity 0.4.18, there might be no automatic checks for overflow, so this.balance + msg.value could overflow if the sum is too big. But this.balance is the contract's balance, which could be large, but in ...

Trích đoạn thinking_process về unchecked low-level call:

> ); 20: Owner.transfer(this.balance); 21: } 22: 23: function Command(address adr,bytes data) 24: payable 25: public 26: { 27: require(msg.sender == Owner); 28: 29: adr.call.value(msg.value)(data); 30: } 31: 32: function multiplicate(address adr) 33: public 34: payable 35: { 36: if(msg.value>=this.balance) 37: { 38: adr.transfer(this.balance+msg.value); 39: } 40: } 41: } I need to look for common vulnerabilities in Solidity. Start with Access_Control: The contract has an Owner set to msg.sender at deployment. Functions like withdraw, Command, and multiplicate have require statements checking if msg.sender == Owner. But in multiplicate, there's no require check for the caller. ...

Giải thích:

`Unchecked_External_Calls` chỉ xuất hiện ở rank `2`, sau `Arithmetic`. Điều này làm reciprocal rank của case này giảm còn `1/2`. model ưu tiên rủi ro overflow/underflow trong Solidity cũ, dù lỗi ground truth là unchecked low-level call.

Dựa trên hai đoạn thinking trên, model không hoàn toàn mù với low-level call; vấn đề là nó xếp lỗi này sau các lỗi có mô tả tác động mạnh hơn. Vì MRR chỉ thưởng cao cho nhãn đúng xuất hiện sớm, thứ tự này trực tiếp kéo điểm của `Unchecked_External_Calls` xuống.

### 4. `0x78c2a1e91b52bca4130b6ed9edd9fbcfd4671c37.sol`

- JSON: `LOGs/my_results_l5/unchecked_low_level_calls/result_0x78c2a1e91b52bca4130b6ed9edd9fbcfd4671c37.json`
- Rank của `Unchecked_External_Calls`: `3`
- Reciprocal rank: `0.333333`
- Thứ tự predicted labels: `Reentrancy_Attacks | Reentrancy_Attacks | Unchecked_External_Calls | Access_Control`
- Các nhãn đứng trước: `Reentrancy_Attacks, Reentrancy_Attacks`

Model output liên quan:

- `Unchecked_External_Calls` tại `Command`, evidence `45`: `adr.call.value(msg.value)(data);`

Trích đoạn thinking_process về lỗi được ưu tiên trước:

> w function, payable, requires msg.sender == Owner, then transfers. - Line 39-46: Command function, payable, requires msg.sender == Owner, then calls adr.call.value(msg.value)(data). Now, I need to identify vulnerabilities. Starting with Reentrancy_Attacks: This happens when a function calls out to an external contract and re-entrancy can occur. Look for functions that transfer ether and then call other functions. In redeem function (line 21-28), it has: - if(msg.value >= minEligibility) { Owner.transfer(this.balance); msg.sender.transfer(this.balance); } Owner.transfer and msg.sender.transfer are both using .transfer which has a gas limit and might not be reliable, but more importantly, if these calls ...

Trích đoạn thinking_process về unchecked low-level call:

> sg.value >= minEligibility, then transfers to Owner and msg.sender. - Line 31-36: withdraw function, payable, requires msg.sender == Owner, then transfers. - Line 39-46: Command function, payable, requires msg.sender == Owner, then calls adr.call.value(msg.value)(data). Now, I need to identify vulnerabilities. Starting with Reentrancy_Attacks: This happens when a function calls out to an external contract and re-entrancy can occur. Look for functions that transfer ether and then call other functions. In redeem function (line 21-28), it has: - if(msg.value >= minEligibility) { Owner.transfer(this.balance); msg.sender.transfer(this.balance); } Owner.transfer and msg.sender.transfer are both using .transfer which has a gas ...

Giải thích:

`Unchecked_External_Calls` chỉ xuất hiện ở rank `3`, sau `Reentrancy_Attacks`, `Reentrancy_Attacks`. Điều này làm reciprocal rank của case này giảm còn `1/3`. model ưu tiên câu chuyện tấn công rút tiền hoặc external call trước state update, nên unchecked call bị đẩy xuống sau.

Dựa trên hai đoạn thinking trên, model không hoàn toàn mù với low-level call; vấn đề là nó xếp lỗi này sau các lỗi có mô tả tác động mạnh hơn. Vì MRR chỉ thưởng cao cho nhãn đúng xuất hiện sớm, thứ tự này trực tiếp kéo điểm của `Unchecked_External_Calls` xuống.

### 5. `0x610495793564aed0f9c7fc48dc4c7c9151d34fd6.sol`

- JSON: `LOGs/my_results_l5/unchecked_low_level_calls/result_0x610495793564aed0f9c7fc48dc4c7c9151d34fd6.json`
- Rank của `Unchecked_External_Calls`: `2`
- Reciprocal rank: `0.500000`
- Thứ tự predicted labels: `Arithmetic | Unchecked_External_Calls`
- Các nhãn đứng trước: `Arithmetic`

Model output liên quan:

- `Arithmetic` tại `N/A`, evidence `12-20`: `uint public depositsCount; depositsCount++;`
- `Unchecked_External_Calls` tại `sendMoney`, evidence `31-34`: `function sendMoney(address _target, uint _value, bytes _data) public onlyOwner { _target.call.value(_value)(_data); }`

Trích đoạn thinking_process về lỗi được ưu tiên trước:

> sendMoney, call is used, which doesn't revert on failure. Evidence for sendMoney: line 31-34. Evidence_snippet: "function sendMoney(address _target, uint _value, bytes _data) public onlyOwner { _target.call.value(_value)(_data); }" Now, Arithmetic: There's depositsCount, which is incremented in fallback. No overflow or underflow mentioned, but in Solidity 0.4.24, there might be no built-in checks for uint overflow, which could lead to overflow if many deposits. But depositsCount is just a counter, and if there are many deposits, it might overflow, but that's not a critical vulnerability unless specified. In this context, it might not be exploitable easily, but ...

Trích đoạn thinking_process về unchecked low-level call:

> ic onlyOwner { withdraw(address(this).balance); } - Line 27-29: function withdraw(uint _value) public onlyOwner { msg.sender.transfer(_value); } - Line 31-34: function sendMoney(address _target, uint _value, bytes _data) public onlyOwner { _target.call.value(_value)(_data); } I need to analyze for vulnerabilities. Starting with Access_Control: The owner is set to msg.sender at deployment. There's a modifier onlyOwner that checks if msg.sender == owner. But in the fallback function, anyone can deposit by calling the payable function, and depositsCount increments, but there's no check on who deposits. However, the owner is fixed, so only the owner can call withdrawAll, withdraw, and ...

Giải thích:

`Unchecked_External_Calls` chỉ xuất hiện ở rank `2`, sau `Arithmetic`. Điều này làm reciprocal rank của case này giảm còn `1/2`. model ưu tiên rủi ro overflow/underflow trong Solidity cũ, dù lỗi ground truth là unchecked low-level call.

Dựa trên hai đoạn thinking trên, model không hoàn toàn mù với low-level call; vấn đề là nó xếp lỗi này sau các lỗi có mô tả tác động mạnh hơn. Vì MRR chỉ thưởng cao cho nhãn đúng xuất hiện sớm, thứ tự này trực tiếp kéo điểm của `Unchecked_External_Calls` xuống.

## Tổng hợp nguyên nhân

1. Model hay chuyển trọng tâm sang tác động có vẻ nghiêm trọng hơn.

Trong `thinking_process`, các lỗi như chiếm owner, reentrancy drain funds, hoặc arithmetic overflow thường được mô tả bằng ngôn ngữ mạnh hơn: attacker can become owner, drain funds, loss of funds, wrap-around. Trong khi đó, `Unchecked_External_Calls` thường được mô tả như không check success/return value, nên bị xếp như lỗi phụ.

2. Low-level call bị gộp vào reasoning của lỗi khác.

Nhiều đoạn thinking dùng cùng một evidence `call.value` hoặc `token.call` để lập luận cho `Reentrancy_Attacks`, sau đó mới nhắc đến unchecked return value. Khi output sắp theo thứ tự suy luận này, `Unchecked_External_Calls` bị đẩy xuống rank sau.

3. MRR phạt nặng ranking trễ.

Ngay cả khi model có phát hiện `Unchecked_External_Calls`, nếu nó đứng ở rank 2/3/4 thì điểm tương ứng chỉ là `0.5`, `0.333333`, hoặc `0.25`. Cộng thêm 23 case `not_found`, MRR của label này bị kéo xuống `0.365385`.

