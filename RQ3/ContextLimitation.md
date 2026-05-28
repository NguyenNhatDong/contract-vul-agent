# Context Limitation Analysis - LOGs/my_results_l5

## Mục tiêu và cách đánh giá

Nguồn model output JSON: `LOGs\my_results_l5`

Solidity input: `smartbugs_dataset`

Ground truth: `Description\smartbugs_dataset.csv`

Báo cáo này truy vết **Context Limitation**: các lỗi phát sinh khi vulnerability chỉ rõ nếu nối nhiều hàm, modifier, contract, hoặc nhiều transaction lại với nhau. Trọng tâm là **Cross-function dependency**, không phải lỗi một dòng đơn lẻ.

Một case được tính khi `thinking_process`/model output cho thấy model phân tích cục bộ từng hàm hoặc từng sink, nhưng không dựng đủ dependency path giữa các hàm nên bỏ lỡ label, sai label, hoặc định vị sai.

## Tổng quan

- Số JSON result được đọc: 143
- Số ground-truth contract-label instances: 143
- Số Context Limitation cases được truy vết chi tiết: 5
- Kết luận: **Có**. Một phần lỗi phát sinh vì lỗ hổng nằm ở tương tác giữa nhiều hàm/contract/transaction, vượt quá phân tích cục bộ từng dòng.

## Context Limitation theo từng loại lỗ hổng

| Label | GT samples | Traced context-limitation cases | Cross-function dependency nổi bật |
|---|---:|---:|---|
| Access_Control | 18 | 2 | Initializer then privileged function; Library initialization + privileged actions |
| Arithmetic | 15 | 0 | Không thấy case cross-function rõ trong 5 dẫn chứng |
| Denial_of_Service_Attacks | 6 | 0 | Không thấy case cross-function rõ trong 5 dẫn chứng |
| Front-running_Attacks | 4 | 1 | Cross-transaction function dependency |
| Insecure_Randomness | 8 | 0 | Không thấy case cross-function rõ trong 5 dẫn chứng |
| Other | 3 | 0 | Không thấy case cross-function rõ trong 5 dẫn chứng |
| Reentrancy_Attacks | 31 | 2 | Caller/callee state dependency; Modifier + cross-contract callback |
| Short_Addresses | 1 | 0 | Không thấy case cross-function rõ trong 5 dẫn chứng |
| Time_Manipulation | 5 | 0 | Không thấy case cross-function rõ trong 5 dẫn chứng |
| Unchecked_External_Calls | 52 | 0 | Không thấy case cross-function rõ trong 5 dẫn chứng |

## Phân tích theo nhóm

### Access_Control

- Số case truy vết: 2
- Dạng phụ thuộc: Initializer then privileged function, Library initialization + privileged actions.
- Nhận xét: model thường thấy một phần tín hiệu trong từng hàm, nhưng không nối đủ dependency path nên kết quả cuối sai hoặc chưa đầy đủ.

### Front-running_Attacks

- Số case truy vết: 1
- Dạng phụ thuộc: Cross-transaction function dependency.
- Nhận xét: model thường thấy một phần tín hiệu trong từng hàm, nhưng không nối đủ dependency path nên kết quả cuối sai hoặc chưa đầy đủ.

### Reentrancy_Attacks

- Số case truy vết: 2
- Dạng phụ thuộc: Caller/callee state dependency, Modifier + cross-contract callback.
- Nhận xét: model thường thấy một phần tín hiệu trong từng hàm, nhưng không nối đủ dependency path nên kết quả cuối sai hoặc chưa đầy đủ.

## Dẫn chứng cụ thể

### Dẫn chứng 1 - Reentrancy_Attacks trong `reentrancy/modifier_reentrancy.sol`

- JSON: [LOGs/my_results_l5/reentrancy/result_modifier_reentrancy.json](../LOGs/my_results_l5/reentrancy/result_modifier_reentrancy.json)
- Ground truth: `Reentrancy_Attacks`, evidence `15`
- Model output: `status: Normal`, `vulnerabilities_count: 0`
- Dạng context limitation: `Modifier + cross-contract callback`
- Dependency path cần theo dõi: `attack.call -> ModifierEntrancy.airDrop -> supportsToken modifier -> attack.supportsToken -> ModifierEntrancy.airDrop`

Ground-truth snippet:

```solidity
   14:                               
>> 15:   function airDrop() hasNoBalance supportsToken  public{
   16:     tokenBalance[msg.sender] += 20;
```

Code region thể hiện phụ thuộc chéo hàm:

```solidity
   14:                               
>> 15:   function airDrop() hasNoBalance supportsToken  public{
   16:     tokenBalance[msg.sender] += 20;
  ...
   20:   modifier supportsToken() {
>> 21:     require(keccak256(abi.encodePacked("Nu Token")) == Bank(msg.sender).supportsToken());
   22:     _;
  ...
   39:     function supportsToken() external returns(bytes32){
>> 40:         if(!hasBeenCalled){
   41:             hasBeenCalled = true;
>> 42:             ModifierEntrancy(msg.sender).airDrop();
>> 43:         }
   44:         return(keccak256(abi.encodePacked("Nu Token")));
```

Trích/paraphrase từ thinking_process:

> ...sNoBalance supportsToken public { tokenBalance[msg.sender] += 20; } - Line 19-23: modifier supportsToken() { require(keccak256(abi.encodePacked("Nu Token")) == Bank(msg.sender).supportsToken()); _; } - Line 24-28: modifier hasNoBalance { require(tokenBalance[msg.sender] == 0); _; } - Line 31-35: contract Bank - Line 32-34: function supportsToken() external pure returns(bytes32) { return(keccak256(abi.encodePacked("Nu Token"))); } - Line 37-49: contract attack - Line 38: bool hasBeenCalled; - Line 39-45: function supportsToken() external returns(bytes32) { if(!hasBeenCalled){ hasBeenCalled = true; ModifierEntrancy...

Giới hạn ngữ cảnh của model: Model phân tích `airDrop`, modifier `supportsToken`, `Bank`, và contract `attack` thành từng mảnh, nhưng không dựng được call chain quay lại `airDrop` trước khi body cập nhật `tokenBalance`.

Cách đọc đúng theo cross-function dependency: Lỗ hổng nằm ở tương tác nhiều thành phần: modifier gọi external contract dựa trên `msg.sender`, contract attacker lợi dụng callback để gọi lại `airDrop` trước khi trạng thái được cập nhật.

Hậu quả: Model trả `Normal`, bỏ lỡ hoàn toàn reentrancy do phụ thuộc chéo giữa modifier và contract attacker.

### Dẫn chứng 2 - Reentrancy_Attacks trong `reentrancy/reentrancy_bonus.sol`

- JSON: [LOGs/my_results_l5/reentrancy/result_reentrancy_bonus.json](../LOGs/my_results_l5/reentrancy/result_reentrancy_bonus.json)
- Ground truth: `Reentrancy_Attacks`, evidence `28`
- Model output: `status: Vulnerable`, `vulnerabilities_count: 1`; `Reentrancy_Attacks` evidence `19` (lines `19`, function `getFirstWithdrawalBonus`), snippet: (bool success, ) = recipient.call.value(amountToWithdraw)""";
- Dạng context limitation: `Caller/callee state dependency`
- Dependency path cần theo dõi: `getFirstWithdrawalBonus -> withdrawReward -> recipient fallback -> getFirstWithdrawalBonus`

Ground-truth snippet:

```solidity
   27:                                     
>> 28:         withdrawReward(recipient);                                                                                    
   29:         claimedBonus[recipient] = true;
```

Code region thể hiện phụ thuộc chéo hàm:

```solidity
   18:         rewardsForA[recipient] = 0;
>> 19:         (bool success, ) = recipient.call.value(amountToWithdraw)("");
   20:         require(success);
  ...
   23:     function getFirstWithdrawalBonus(address recipient) public {
>> 24:         require(!claimedBonus[recipient]);                                                              
   25: 
>> 26:         rewardsForA[recipient] += 100;
   27:                                     
>> 28:         withdrawReward(recipient);                                                                                    
>> 29:         claimedBonus[recipient] = true;
   30:     }
```

Trích/paraphrase từ thinking_process:

> ...=> uint) private userBalances; - Line 13: mapping (address => bool) claimedBonus; - Line 14: mapping (address => uint) private rewardsForA; - Line 16: function withdrawReward(address recipient) public { - Line 17: uint amountToWithdraw = rewardsForA[recipient]; - Line 18: rewardsForA[recipient] = 0; - Line 19: (bool success, ) = recipient.call.value(amountToWithdraw)(""); - Line 20: require(success); - Line 23: function getFirstWithdrawalBonus(address recipient) public { - Line 24: require(!claimedBonus[recipient]); - Line 26: rewardsForA[recipient] += 100; - Line 28: withdrawReward(recipient); - Line 29: claimed...

Giới hạn ngữ cảnh của model: Model nhận ra external call trong `withdrawReward` nhưng evidence và giải thích tập trung vào callee, trong khi guard quyết định nằm ở caller `getFirstWithdrawalBonus`.

Cách đọc đúng theo cross-function dependency: Phải nối hai hàm: `getFirstWithdrawalBonus` kiểm tra `claimedBonus`, gọi `withdrawReward`, rồi chỉ set `claimedBonus = true` sau external call trong callee.

Hậu quả: Model đúng label nhưng chỉ định vị một phần, bỏ sót dependency caller/callee tạo ra reentrancy.

### Dẫn chứng 3 - Access_Control trong `access_control/wallet_03_wrong_constructor.sol`

- JSON: [LOGs/my_results_l5/access_control/result_wallet_03_wrong_constructor.json](../LOGs/my_results_l5/access_control/result_wallet_03_wrong_constructor.json)
- Ground truth: `Access_Control`, evidence `19;20`
- Model output: `status: Vulnerable`, `vulnerabilities_count: 1`; `Arithmetic` evidence `24` (lines `24`, function `deposit`), snippet: assert(balances[msg.sender] + msg.value > balances[msg.sender]);
- Dạng context limitation: `Initializer then privileged function`
- Dependency path cần theo dõi: `attacker -> initWallet -> creator = attacker -> migrateTo`

Ground-truth snippet:

```solidity
   18:                                      
>> 19:      function initWallet() public {
>> 20:          creator = msg.sender;
   21:      }
```

Code region thể hiện phụ thuộc chéo hàm:

```solidity
   18:                                      
>> 19:      function initWallet() public {
>> 20:          creator = msg.sender;
   21:      }
  ...
   35: 
>> 36:      function migrateTo(address to) public {
>> 37:          require(creator == msg.sender);
>> 38:          to.transfer(this.balance);
   39:      }
```

Trích/paraphrase từ thinking_process:

> ... – Contract definition. - Line 14: `address creator;` – Public variable. - Line 16: `mapping(address => uint256) balances;` – Mapping for balances. - Line 18: `function initWallet() public {` – Initializes creator. - Line 19: `function deposit() public payable {` – Allows depositing ETH. - Line 20: `creator = msg.sender;` – Sets creator on init. - Line 23: `function deposit() public payable {` – Deposit function. - Line 24: `assert(balances[msg.sender] + msg.value > balances[msg.sender]);` – This assert seems redundant because `balances[msg.sender] + msg.value` will always be greater than `balances[msg.sender]` u...

Giới hạn ngữ cảnh của model: Model nhìn `migrateTo` có `require(creator == msg.sender)` và coi là an toàn, nhưng không nối được rằng `creator` có thể bị chiếm trước đó qua initializer public.

Cách đọc đúng theo cross-function dependency: Access-control bug chỉ hiện ra khi xét lifecycle nhiều bước: gọi `initWallet()` trước để đặt `creator`, sau đó gọi `migrateTo()` với quyền vừa chiếm.

Hậu quả: Model bỏ `Access_Control` và chuyển sang `Arithmetic`.

### Dẫn chứng 4 - Access_Control trong `access_control/parity_wallet_bug_2.sol`

- JSON: [LOGs/my_results_l5/access_control/result_parity_wallet_bug_2.json](../LOGs/my_results_l5/access_control/result_parity_wallet_bug_2.json)
- Ground truth: `Access_Control`, evidence `226;233`
- Model output: `status: Vulnerable`, `vulnerabilities_count: 2`; `Access_Control` evidence `241` (lines `241`, function `execute`), snippet: function execute(address _to, uint _value, bytes _data) public {<br>`Arithmetic` evidence `359` (lines `359`, function `underLimit`), snippet: if (m_spentToday + _value >= m_spentToday && m_spentToday + _value <= m_dailyLimit)
- Dạng context limitation: `Library initialization + privileged actions`
- Dependency path cần theo dõi: `initWallet/initMultiowned -> owner set -> kill/execute/onlymanyowners flow`

Ground-truth snippet:

```solidity
   225:                                   
>> 226:   function initWallet(address[] _owners, uint _required, uint _daylimit) only_uninitialized {
   227:     initDaylimit(_daylimit);
  ...
   232:                                   
>> 233:   function kill(address _to) onlymanyowners(sha3(msg.data)) external {
   234:     suicide(_to);
```

Code region thể hiện phụ thuộc chéo hàm:

```solidity
   225:                                   
>> 226:   function initWallet(address[] _owners, uint _required, uint _daylimit) only_uninitialized {
>> 227:     initDaylimit(_daylimit);
>> 228:     initMultiowned(_owners, _required);
   229:   }
  ...
   232:                                   
>> 233:   function kill(address _to) onlymanyowners(sha3(msg.data)) external {
>> 234:     suicide(_to);
   235:   }
  ...
   240:                                                                                          
>> 241:   function execute(address _to, uint _value, bytes _data) external onlyowner returns (bytes32 o_hash) {
   242:                                                                              
```

Trích/paraphrase từ thinking_process:

> ...it can be manipulated. Access Control: Look at the only_uninitialized modifier. Line 221: modifier only_uninitialized { if (m_numOwners > 0) throw; _; } But in initWallet, line 226-229: function initWallet(address[] _owners, uint _required, uint _daylimit) only_uninitialized { initDaylimit(_ daylimit); initMultiowned(_owners, _required); } initMultiowned itself has only_uninitialized? No, initMultiowned is called from initWallet, which has only_uninitialized. But initMultiowned doesn't have a modifier; it's public or something? Line 113: function initMultiowned(address[] _owners, uint _required) only_uninitialize...

Giới hạn ngữ cảnh của model: Model nhận một số hàm nhạy cảm nhưng tập trung sai vào `execute`, thay vì nối initialization flow với các hàm đặc quyền như `kill`.

Cách đọc đúng theo cross-function dependency: Bug access control phụ thuộc vào luồng khởi tạo nhiều hàm trong wallet library: khi initialization bị gọi sai/ngữ cảnh proxy-library, quyền owner/manyowners ảnh hưởng trực tiếp tới `kill` và các hành động đặc quyền.

Hậu quả: Model dự đoán `Access_Control` nhưng evidence trôi sang `execute`, không nắm đúng dependency init -> privileged action.

### Dẫn chứng 5 - Front-running_Attacks trong `front_running/eth_tx_order_dependence_minimal.sol`

- JSON: [LOGs/my_results_l5/front_running/result_eth_tx_order_dependence_minimal.json](../LOGs/my_results_l5/front_running/result_eth_tx_order_dependence_minimal.json)
- Ground truth: `Front-running_Attacks`, evidence `23;31`
- Model output: `status: Vulnerable`, `vulnerabilities_count: 2`; `Reentrancy_Attacks` evidence `23` (lines `23`, function `setReward`), snippet: owner.transfer(reward);<br>`Reentrancy_Attacks` evidence `31` (lines `31`, function `claimReward`), snippet: msg.sender.transfer(reward);
- Dạng context limitation: `Cross-transaction function dependency`
- Dependency path cần theo dõi: `owner.setReward transaction <-> attacker.claimReward transaction`

Ground-truth snippet:

```solidity
   22:                                        
>> 23:         owner.transfer(reward);
   24:         reward = msg.value;
  ...
   30:                                        
>> 31:         msg.sender.transfer(reward);
   32:         claimed = true;
```

Code region thể hiện phụ thuộc chéo hàm:

```solidity
   18:     function setReward() public payable {
>> 19:         require (!claimed);
   20: 
   21:         require(msg.sender == owner);
   22:                                        
>> 23:         owner.transfer(reward);
>> 24:         reward = msg.value;
   25:     }
   26: 
   27:     function claimReward(uint256 submission) {
>> 28:         require (!claimed);
   29:         require(submission < 10);
   30:                                        
>> 31:         msg.sender.transfer(reward);
>> 32:         claimed = true;
   33:     }
```

Trích/paraphrase từ thinking_process:

> ...ne 32: claimed = true; - Line 34: } I need to analyze this for common vulnerabilities. Let me break down the contract: - It has an owner set on construction. - setReward function: only owner can call it, requires not claimed, transfers reward to owner, then sets reward to msg.value. - claimReward function: requires not claimed, submission < 10, transfers reward to msg.sender, sets claimed to true. Now, potential vulnerabilities: 1. **Reentrancy Attacks**: This is common in payable functions where external calls are made before state changes. In setReward, it calls owner.transfer(reward), which is an external call...

Giới hạn ngữ cảnh của model: Model đọc từng hàm như một call stack nội bộ và kéo về reentrancy, nhưng không mô hình hóa dependency giữa hai giao dịch gọi hai hàm khác nhau.

Cách đọc đúng theo cross-function dependency: Front-running nằm ở tương tác cross-function/cross-transaction: reward được set trong `setReward`, và một giao dịch `claimReward` có thể chen thứ tự để nhận reward không đúng kỳ vọng.

Hậu quả: Model dự đoán `Reentrancy_Attacks`, bỏ nhãn `Front-running_Attacks`.

## Kết luận

Có bằng chứng Context Limitation trong `my_results_l5`: một số lỗi không nằm ở một dòng đơn lẻ mà ở quan hệ giữa modifier, caller/callee, initializer/privileged function, hoặc transaction order. Model có xu hướng phân tích từng hàm riêng lẻ, nên dễ bỏ qua dependency path tạo ra vulnerability.

Khi đánh giá các contract có nhiều hàm tương tác, nên bổ sung kiểm tra call graph/lifecycle thủ công hoặc prompt yêu cầu model dựng explicit execution path trước khi kết luận vulnerability.
