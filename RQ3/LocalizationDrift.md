# Localization Drift Analysis - LOGs/my_results_l5

## Mục tiêu và cách đánh giá

Nguồn model output JSON: `LOGs\my_results_l5`

Solidity input: `smartbugs_dataset`

Ground truth: `Description\smartbugs_dataset.csv`

Một **Localization Drift** được tính khi model dự đoán đúng `vulnerability_type` cho contract, nhưng tất cả evidence line của prediction đúng label đều nằm ngoài tolerance `±3` so với ground-truth vulnerable line.

Các case không dự đoán đúng label được loại khỏi metric này vì thuộc Detection Failure/Misclassification. Các case đúng label nhưng evidence rỗng/placeholder được tách riêng thành `invalid localization`, không dùng làm dẫn chứng highlight sai dòng.

## Tổng quan

- Số JSON result được đọc: 143
- Số ground-truth contract-label instances: 143
- Số instances có correct-label prediction: 99
- Số Localization Drift: 5
- Số correct-label prediction nhưng evidence không parse được: 0
- Kết luận: **Có**. Mô hình có trường hợp chỉ ra đúng loại lỗi nhưng highlight sai dòng mã cụ thể.

## Localization Drift theo từng loại lỗ hổng

| Label | GT samples | Correct-label predictions | Drift cases | Drift rate trên correct-label | Invalid localization |
|---|---:|---:|---:|---:|---:|
| Access_Control | 18 | 10 | 3 | 30.00% | 0 |
| Arithmetic | 15 | 13 | 0 | 0.00% | 0 |
| Denial_of_Service_Attacks | 6 | 3 | 1 | 33.33% | 0 |
| Front-running_Attacks | 4 | 0 | 0 | 0.00% | 0 |
| Insecure_Randomness | 8 | 7 | 0 | 0.00% | 0 |
| Other | 3 | 0 | 0 | 0.00% | 0 |
| Reentrancy_Attacks | 31 | 29 | 1 | 3.45% | 0 |
| Short_Addresses | 1 | 0 | 0 | 0.00% | 0 |
| Time_Manipulation | 5 | 1 | 0 | 0.00% | 0 |
| Unchecked_External_Calls | 52 | 36 | 0 | 0.00% | 0 |
| **Overall** | **143** | **99** | **5** | **5.05%** | **0** |

## Phân tích theo nhóm lỗ hổng

### Access_Control

- Có 3/10 correct-label predictions bị drift.
- Khoảng cách line nhỏ nhất lớn nhất trong nhóm drift: `11`.
- Xu hướng: model nhận đúng loại vulnerability nhưng evidence thường trỏ sang function lân cận, đoạn call/transfer phụ, hoặc vùng code giải thích nguyên nhân tổng quát thay vì dòng GT được annotate.

### Denial_of_Service_Attacks

- Có 1/3 correct-label predictions bị drift.
- Khoảng cách line nhỏ nhất lớn nhất trong nhóm drift: `4`.
- Xu hướng: model nhận đúng loại vulnerability nhưng evidence thường trỏ sang function lân cận, đoạn call/transfer phụ, hoặc vùng code giải thích nguyên nhân tổng quát thay vì dòng GT được annotate.

### Reentrancy_Attacks

- Có 1/29 correct-label predictions bị drift.
- Khoảng cách line nhỏ nhất lớn nhất trong nhóm drift: `9`.
- Xu hướng: model nhận đúng loại vulnerability nhưng evidence thường trỏ sang function lân cận, đoạn call/transfer phụ, hoặc vùng code giải thích nguyên nhân tổng quát thay vì dòng GT được annotate.

## Dẫn chứng cụ thể

### Dẫn chứng 1 - Access_Control trong `access_control/FibonacciBalance.sol`

- JSON: [LOGs/my_results_l5/access_control/result_FibonacciBalance.json](../LOGs/my_results_l5/access_control/result_FibonacciBalance.json)
- Ground truth: `Access_Control`, evidence `31;38`
- Model output đúng label: `Access_Control` evidence `49-55` (lines `49;50;51;52;53;54;55`, function `setStart and setFibonacci`), snippet: function setStart(uint _start) public; function setFibonacci(uint n) public;
- Min distance giữa model evidence và GT: `11` line(s), lớn hơn tolerance `±3`.

GT code snippet:

```solidity
   30:                                         
>> 31:         require(fibonacciLibrary.delegatecall(fibSig, withdrawalCounter));
   32:         msg.sender.transfer(calculatedFibNumber * 1 ether);
  ...
   37:                                         
>> 38:         require(fibonacciLibrary.delegatecall(msg.data));
   39:     }
```

Model-highlighted snippet:

```solidity
   48:                                                
>> 49:     function setStart(uint _start) public {
>> 50:         start = _start;
>> 51:     }
>> 52: 
>> 53:     function setFibonacci(uint n) public {
>> 54:         calculatedFibNumber = fibonacci(n);
>> 55:     }
   56: 
```

Trích/paraphrase từ thinking_process:

> ...ight include overflows. - Also, Time_Manipulation: not apparent, no timestamps or block timestamps used. - Access_Control: in FibonacciLib, setStart and setFibonacci are public, so anyone can call them, which might not be intended if the library should be controlled by the main contract. - In FibonacciBalance, fibonacciLibrary is set in constructor, but the library functions are public, so no access control. - But the main contract doesn't control the library's functions. - Front-running_Attacks: not obvious, no tr...

Giải thích: model đã chọn đúng vulnerability type nhưng evidence được highlight không nằm trong vùng GT theo tolerance ±3. Vì vậy đây là lỗi định vị, không phải lỗi phát hiện label.

### Dẫn chứng 2 - Reentrancy_Attacks trong `reentrancy/reentrancy_bonus.sol`

- JSON: [LOGs/my_results_l5/reentrancy/result_reentrancy_bonus.json](../LOGs/my_results_l5/reentrancy/result_reentrancy_bonus.json)
- Ground truth: `Reentrancy_Attacks`, evidence `28`
- Model output đúng label: `Reentrancy_Attacks` evidence `19` (lines `19`, function `getFirstWithdrawalBonus`), snippet: (bool success, ) = recipient.call.value(amountToWithdraw)""";
- Min distance giữa model evidence và GT: `9` line(s), lớn hơn tolerance `±3`.

GT code snippet:

```solidity
   27:                                     
>> 28:         withdrawReward(recipient);                                                                                    
   29:         claimedBonus[recipient] = true;
```

Model-highlighted snippet:

```solidity
   18:         rewardsForA[recipient] = 0;
>> 19:         (bool success, ) = recipient.call.value(amountToWithdraw)("");
   20:         require(success);
```

Trích/paraphrase từ thinking_process:

> ...[recipient] = 0; - Line 19: (bool success, ) = recipient.call.value(amountToWithdraw)(""); - Line 20: require(success); - Line 23: function getFirstWithdrawalBonus(address recipient) public { - Line 24: require(!claimedBonus[recipient]); - Line 26: rewardsForA[recipient] += 100; - Line 28: withdrawReward(recipient); - Line 29: claimedBonus[recipient] = true; - Line 30: } The contract is named Reentrancy_bonus, which might hint at a reentrancy vulnerability. I need to check for common vulnerabilities: 1. **Reentranc...

Giải thích: model đã chọn đúng vulnerability type nhưng evidence được highlight không nằm trong vùng GT theo tolerance ±3. Vì vậy đây là lỗi định vị, không phải lỗi phát hiện label.

### Dẫn chứng 3 - Denial_of_Service_Attacks trong `denial_of_service/dos_address.sol`

- JSON: [LOGs/my_results_l5/denial_of_service/result_dos_address.json](../LOGs/my_results_l5/denial_of_service/result_dos_address.json)
- Ground truth: `Denial_of_Service_Attacks`, evidence `16;17;18`
- Model output đúng label: `Denial_of_Service_Attacks` evidence `22-26` (lines `22;23;24;25;26`, function `addCreditors`), snippet: for(uint i=0;i<350;i++) { creditorAddresses.push(msg.sender); }
- Min distance giữa model evidence và GT: `4` line(s), lớn hơn tolerance `±3`.

GT code snippet:

```solidity
   15:                                            
>> 16:         if(creditorAddresses.length>1500) {
>> 17:             creditorAddresses = new address[](0);
>> 18:             win = true;
   19:         }
```

Model-highlighted snippet:

```solidity
   21: 
>> 22:     function addCreditors() public returns (bool) {
>> 23:         for(uint i=0;i<350;i++) {
>> 24:           creditorAddresses.push(msg.sender);
>> 25:         }
>> 26:         return true;
   27:     }
```

Trích/paraphrase từ thinking_process:

> ...I need to analyze the given Solidity code for vulnerabilities. The code is for a contract named DosGas, with functions like emptyCreditors, addCreditors, iWin, and numberCreditors. The vulnerability types I must consider are from the set: Reentrancy_Attacks, Arithmetic, Time_Manipulation, Access_Control, Front-running_Attacks, Denial_of_Service_Attacks, Short_Addresses, Insecure_Randomness, Unchecked_External_Calls. If none, use "Other". I need to look at the code and identify all vulnerabilities that can be direct...

Giải thích: model đã chọn đúng vulnerability type nhưng evidence được highlight không nằm trong vùng GT theo tolerance ±3. Vì vậy đây là lỗi định vị, không phải lỗi phát hiện label.

### Dẫn chứng 4 - Access_Control trong `access_control/mapping_write.sol`

- JSON: [LOGs/my_results_l5/access_control/result_mapping_write.json](../LOGs/my_results_l5/access_control/result_mapping_write.json)
- Ground truth: `Access_Control`, evidence `20`
- Model output đúng label: `Access_Control` evidence `12` (lines `12`, function `N/A`), snippet: address public owner;
- Min distance giữa model evidence và GT: `8` line(s), lớn hơn tolerance `±3`.

GT code snippet:

```solidity
   19:                                         
>> 20:          map[key] = value;
   21:      }
```

Model-highlighted snippet:

```solidity
   11:  contract Map {
>> 12:      address public owner;
   13:      uint256[] map;
```

Trích/paraphrase từ thinking_process:

> ...st, evidence must come directly from code. For Access_Control: - Evidence: line 12, owner is declared but not initialized. - Function_name: N/A, it's a state variable. - But vulnerability_type is Access_Control. For Arithmetic: - Evidence: line 17, map.length = key + 1; where key is uint256, could overflow. - Function_name: set Now, is there any other? The withdraw function: msg.sender.transfer(address(this).balance). In Solidity ^0.4.24, transfer is used, which is safe against call failures, but can be reentrant. ...

Giải thích: model đã chọn đúng vulnerability type nhưng evidence được highlight không nằm trong vùng GT theo tolerance ±3. Vì vậy đây là lỗi định vị, không phải lỗi phát hiện label.

### Dẫn chứng 5 - Access_Control trong `access_control/parity_wallet_bug_2.sol`

- JSON: [LOGs/my_results_l5/access_control/result_parity_wallet_bug_2.json](../LOGs/my_results_l5/access_control/result_parity_wallet_bug_2.json)
- Ground truth: `Access_Control`, evidence `226;233`
- Model output đúng label: `Access_Control` evidence `241` (lines `241`, function `execute`), snippet: function execute(address _to, uint _value, bytes _data) public {
- Min distance giữa model evidence và GT: `8` line(s), lớn hơn tolerance `±3`.

GT code snippet:

```solidity
   225:                                   
>> 226:   function initWallet(address[] _owners, uint _required, uint _daylimit) only_uninitialized {
   227:     initDaylimit(_daylimit);
  ...
   232:                                   
>> 233:   function kill(address _to) onlymanyowners(sha3(msg.data)) external {
   234:     suicide(_to);
```

Model-highlighted snippet:

```solidity
   240:                                                                                          
>> 241:   function execute(address _to, uint _value, bytes _data) external onlyowner returns (bytes32 o_hash) {
   242:                                                                              
```

Trích/paraphrase từ thinking_process:

> ...(line 104-109): function() payable { if (msg.value > 0) Deposit(msg.sender, msg.value); } This is simple, no external calls, probably safe. execute function (line 241-266): This has a call to _to.call.value(_value)(_data), which could be reentrant if the contract has a fallback that calls back. But in this case, the call is to _to, which might be an external contract. If _to has a payable fallback, it could reenter. Specifically, line 249: if (!_to.call.value(_value)(_data)) throw; This is a call to an external con...

Giải thích: model đã chọn đúng vulnerability type nhưng evidence được highlight không nằm trong vùng GT theo tolerance ±3. Vì vậy đây là lỗi định vị, không phải lỗi phát hiện label.

## Kết luận

Có Localization Drift trong output `my_results_l5`: mô hình đôi khi hiểu đúng loại lỗi nhưng đặt evidence ở dòng khác với annotation. Điều này đặc biệt quan trọng khi dùng model như công cụ hỗ trợ auditor, vì auditor có thể bị dẫn tới vùng code không phải vị trí ground-truth cần kiểm tra.

Với tolerance ±3, báo cáo này chỉ tính drift trên các mẫu có correct-label prediction; những lỗi không dự đoán đúng label vẫn nên đọc ở các báo cáo Detection Failure và Misclassification.
