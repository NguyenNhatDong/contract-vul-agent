# Partial Localization Analysis - LOGs/my_results_l5

## Mục tiêu và cách đánh giá

Nguồn model output JSON: `LOGs\my_results_l5`

Solidity input: `smartbugs_dataset`

Ground truth: `Description\smartbugs_dataset.csv`

Một **Partial Localization** được tính khi model dự đoán đúng label, nhưng không cover đủ toàn bộ GT evidence trong tolerance `±3` và vẫn có tín hiệu định vị liên quan: hit một phần GT, cùng function với GT, hoặc nằm trong quan hệ caller/callee trực tiếp.

Các case không có correct-label prediction không được tính ở đây vì thuộc Detection Failure/Misclassification.

## Tổng quan

- Số JSON result được đọc: 143
- Số ground-truth contract-label instances: 143
- Số instances có correct-label prediction: 99
- Số complete localization trong correct-label predictions: 83
- Số Partial Localization: 12
- Kết luận: **Có**. Mô hình có trường hợp chỉ xác định đúng một phần phạm vi lỗi, ví dụ đúng luồng/hàm nhưng sai hoặc thiếu dòng cụ thể.

## Partial Localization theo từng loại lỗ hổng

| Label | GT samples | Correct-label predictions | Complete localization | Partial localization | Partial rate trên correct-label |
|---|---:|---:|---:|---:|---:|
| Access_Control | 18 | 10 | 7 | 0 | 0.00% |
| Arithmetic | 15 | 13 | 12 | 1 | 7.69% |
| Denial_of_Service_Attacks | 6 | 3 | 2 | 0 | 0.00% |
| Front-running_Attacks | 4 | 0 | 0 | 0 | 0.00% |
| Insecure_Randomness | 8 | 7 | 3 | 4 | 57.14% |
| Other | 3 | 0 | 0 | 0 | 0.00% |
| Reentrancy_Attacks | 31 | 29 | 28 | 1 | 3.45% |
| Short_Addresses | 1 | 0 | 0 | 0 | 0.00% |
| Time_Manipulation | 5 | 1 | 0 | 1 | 100.00% |
| Unchecked_External_Calls | 52 | 36 | 31 | 5 | 13.89% |
| **Overall** | **143** | **99** | **83** | **12** | **12.12%** |

## Phân tích theo nhóm lỗ hổng

### Arithmetic

- Có 1/13 correct-label predictions bị Partial Localization.
- 1 case hit một phần GT lines nhưng bỏ sót GT lines khác.
- 0 case không hit GT line nhưng vẫn nằm trong cùng function hoặc caller/callee trực tiếp.
- Xu hướng: model thường nhận đúng cơ chế lỗi, nhưng evidence chỉ trỏ vào sink/call phụ hoặc một line đại diện, không bao phủ toàn bộ phạm vi annotation.

### Insecure_Randomness

- Có 4/7 correct-label predictions bị Partial Localization.
- 4 case hit một phần GT lines nhưng bỏ sót GT lines khác.
- 0 case không hit GT line nhưng vẫn nằm trong cùng function hoặc caller/callee trực tiếp.
- Xu hướng: model thường nhận đúng cơ chế lỗi, nhưng evidence chỉ trỏ vào sink/call phụ hoặc một line đại diện, không bao phủ toàn bộ phạm vi annotation.

### Reentrancy_Attacks

- Có 1/29 correct-label predictions bị Partial Localization.
- 0 case hit một phần GT lines nhưng bỏ sót GT lines khác.
- 1 case không hit GT line nhưng vẫn nằm trong cùng function hoặc caller/callee trực tiếp.
- Xu hướng: model thường nhận đúng cơ chế lỗi, nhưng evidence chỉ trỏ vào sink/call phụ hoặc một line đại diện, không bao phủ toàn bộ phạm vi annotation.

### Time_Manipulation

- Có 1/1 correct-label predictions bị Partial Localization.
- 1 case hit một phần GT lines nhưng bỏ sót GT lines khác.
- 0 case không hit GT line nhưng vẫn nằm trong cùng function hoặc caller/callee trực tiếp.
- Xu hướng: model thường nhận đúng cơ chế lỗi, nhưng evidence chỉ trỏ vào sink/call phụ hoặc một line đại diện, không bao phủ toàn bộ phạm vi annotation.

### Unchecked_External_Calls

- Có 5/36 correct-label predictions bị Partial Localization.
- 5 case hit một phần GT lines nhưng bỏ sót GT lines khác.
- 0 case không hit GT line nhưng vẫn nằm trong cùng function hoặc caller/callee trực tiếp.
- Xu hướng: model thường nhận đúng cơ chế lỗi, nhưng evidence chỉ trỏ vào sink/call phụ hoặc một line đại diện, không bao phủ toàn bộ phạm vi annotation.

## Dẫn chứng cụ thể

### Dẫn chứng 1 - Reentrancy_Attacks trong `reentrancy/reentrancy_bonus.sol`

- JSON: [LOGs/my_results_l5/reentrancy/result_reentrancy_bonus.json](../LOGs/my_results_l5/reentrancy/result_reentrancy_bonus.json)
- Ground truth: `Reentrancy_Attacks`, evidence `28`
- Model output đúng label: `Reentrancy_Attacks` evidence `19` (lines `19`, function `getFirstWithdrawalBonus`), snippet: (bool success, ) = recipient.call.value(amountToWithdraw)""";
- GT lines hit trong ±3: `none`
- GT lines bị miss: `28`
- GT function(s): `getFirstWithdrawalBonus`
- Model-highlighted function(s): `withdrawReward`
- Min distance model evidence tới GT: `9` line(s)
- Lý do Partial Localization: Model highlight function caller/callee trực tiếp của vùng GT, nên đúng một phần luồng thực thi nhưng sai dòng annotate.

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

Giải thích: model đã phát hiện đúng label và bám vào một phần luồng/phạm vi lỗi, nhưng evidence chưa bao phủ đúng toàn bộ dòng GT. Đây là định vị một phần, không phải phát hiện hoàn chỉnh.

### Dẫn chứng 2 - Unchecked_External_Calls trong `unchecked_low_level_calls/0x39cfd754c85023648bf003bea2dd498c5612abfa.sol`

- JSON: [LOGs/my_results_l5/unchecked_low_level_calls/result_0x39cfd754c85023648bf003bea2dd498c5612abfa.json](../LOGs/my_results_l5/unchecked_low_level_calls/result_0x39cfd754c85023648bf003bea2dd498c5612abfa.json)
- Ground truth: `Unchecked_External_Calls`, evidence `44;97`
- Model output đúng label: `Unchecked_External_Calls` evidence `44` (lines `44`, function `WithdrawToken`), snippet: token.call(bytes4(sha3("transfer(address,uint256)")),to,amount);
- GT lines hit trong ±3: `44`
- GT lines bị miss: `97`
- GT function(s): `WithdrawToHolder, WithdrawToken`
- Model-highlighted function(s): `WithdrawToken`
- Min distance model evidence tới GT: `0` line(s)
- Lý do Partial Localization: Model hit một phần GT lines nhưng bỏ sót phần còn lại của phạm vi lỗi.

GT code snippet:

```solidity
   43:                                             
>> 44:         token.call(bytes4(sha3("transfer(address,uint256)")),to,amount); 
   45:     }
  ...
   96:                                                     
>> 97:                 _addr.call.value(_wei);
   98:                 Holders[_addr]-=_wei;
```

Model-highlighted snippet:

```solidity
   43:                                             
>> 44:         token.call(bytes4(sha3("transfer(address,uint256)")),to,amount); 
   45:     }
```

Trích/paraphrase từ thinking_process:

> ...changeOwner, and confirmOwner to finalize the change. There's a modifier onlyOwner. - Contract Token: Inherits from Ownable. Has a function WithdrawToken to call transfer on a token. - Contract TokenBank: Inherits from Token. Has initTokenBank to set owner and MinDeposit. Has a fallback function for deposits, Deposit function to handle deposits, and functions to withdraw tokens or wei to holders. Now, I need to identify vulnerabilities. Start with Access_Control: This is common in smart contracts. Look for issues l...

Giải thích: model đã phát hiện đúng label và bám vào một phần luồng/phạm vi lỗi, nhưng evidence chưa bao phủ đúng toàn bộ dòng GT. Đây là định vị một phần, không phải phát hiện hoàn chỉnh.

### Dẫn chứng 3 - Arithmetic trong `arithmetic/overflow_single_tx.sol`

- JSON: [LOGs/my_results_l5/arithmetic/result_overflow_single_tx.json](../LOGs/my_results_l5/arithmetic/result_overflow_single_tx.json)
- Ground truth: `Arithmetic`, evidence `18;24;30;36;42;48`
- Model output đúng label: `Arithmetic` evidence `18` (lines `18`, function `overflowaddtostate`), snippet: count += input;<br>`Arithmetic` evidence `24` (lines `24`, function `overflowmultostate`), snippet: count *= input;<br>`Arithmetic` evidence `30` (lines `30`, function `underflowtostate`), snippet: count -= input;
- GT lines hit trong ±3: `18;24;30`
- GT lines bị miss: `36;42;48`
- GT function(s): `overflowaddtostate, overflowlocalonly, overflowmulocalonly, overflowmultostate, underflowlocalonly, underflowtostate`
- Model-highlighted function(s): `overflowaddtostate, overflowmultostate, underflowtostate`
- Min distance model evidence tới GT: `0` line(s)
- Lý do Partial Localization: Model hit một phần GT lines nhưng bỏ sót phần còn lại của phạm vi lỗi.

GT code snippet:

```solidity
   17:                                     
>> 18:         count += input;
   19:     }
  ...
   23:                                     
>> 24:         count *= input;
   25:     }
  ...
   29:                                     
>> 30:         count -= input;
   31:     }
  ...
   35:                                     
>> 36:         uint res = count + input;
   37:     }
  ...
   41:                                     
>> 42:         uint res = count * input;
   43:     }
  ...
   47:                                     
>> 48:        	uint res = count - input;
   49:     }
```

Model-highlighted snippet:

```solidity
   17:                                     
>> 18:         count += input;
   19:     }
  ...
   23:                                     
>> 24:         count *= input;
   25:     }
  ...
   29:                                     
>> 30:         count -= input;
   31:     }
```

Trích/paraphrase từ thinking_process:

> ...rithmetic operations: addition, multiplication, subtraction, all with potential for overflow or underflow. Let me list out the functions: - overflowaddtostate: Adds input to count. - overflowmultostate: Multiplies count by input. - underflowtostate: Subtracts input from count. - overflowlocalonly: Adds input to count locally, doesn't change state. - overflowmulocalonly: Multiplies input locally, doesn't change state. - underflowlocalonly: Subtracts input locally, doesn't change state. Now, I need to identify vulner...

Giải thích: model đã phát hiện đúng label và bám vào một phần luồng/phạm vi lỗi, nhưng evidence chưa bao phủ đúng toàn bộ dòng GT. Đây là định vị một phần, không phải phát hiện hoàn chỉnh.

### Dẫn chứng 4 - Insecure_Randomness trong `bad_randomness/blackjack.sol`

- JSON: [LOGs/my_results_l5/bad_randomness/result_blackjack.json](../LOGs/my_results_l5/bad_randomness/result_blackjack.json)
- Ground truth: `Insecure_Randomness`, evidence `17;19;21`
- Model output đúng label: `Insecure_Randomness` evidence `21` (lines `21`, function `deal`), snippet: return uint8(uint256(keccak256(block.blockhash(b), player, cardNumber, timestamp)) % 52;
- GT lines hit trong ±3: `19;21`
- GT lines bị miss: `17`
- GT function(s): `deal`
- Model-highlighted function(s): `deal`
- Min distance model evidence tới GT: `0` line(s)
- Lý do Partial Localization: Model hit một phần GT lines nhưng bỏ sót phần còn lại của phạm vi lỗi.

GT code snippet:

```solidity
   16: 		                                
>> 17: 		uint b = block.number;
   18: 		                                
>> 19: 		uint timestamp = block.timestamp;
   20: 		                                
>> 21: 		return uint8(uint256(keccak256(block.blockhash(b), player, cardNumber, timestamp)) % 52);
   22: 	}
```

Model-highlighted snippet:

```solidity
   20: 		                                
>> 21: 		return uint8(uint256(keccak256(block.blockhash(b), player, cardNumber, timestamp)) % 52);
   22: 	}
```

Trích/paraphrase từ thinking_process:

> ...w, I'll analyze the code step by step to find potential vulnerabilities. The code is a BlackJack game contract with a Deck library for card dealing. Key parts: - Deck library: has functions to deal cards using blockhash and timestamp for randomness, and helper functions for card values. - BlackJack contract: handles game logic, states, betting, and events. Vulnerability types to check: 1. **Reentrancy_Attacks**: This happens when a contract calls out to an external contract before updating its state. Look for payab...

Giải thích: model đã phát hiện đúng label và bám vào một phần luồng/phạm vi lỗi, nhưng evidence chưa bao phủ đúng toàn bộ dòng GT. Đây là định vị một phần, không phải phát hiện hoàn chỉnh.

### Dẫn chứng 5 - Time_Manipulation trong `time_manipulation/lottopollo.sol`

- JSON: [LOGs/my_results_l5/time_manipulation/result_lottopollo.json](../LOGs/my_results_l5/time_manipulation/result_lottopollo.json)
- Ground truth: `Time_Manipulation`, evidence `13;27`
- Model output đúng label: `Time_Manipulation` evidence `13-19` (lines `13;14;15;16;17;18;19`, function `payOut`), snippet: if ( rand > 0 && now - rand > 24 hours ) {
- GT lines hit trong ±3: `13`
- GT lines bị miss: `27`
- GT function(s): `payOut, randomGen`
- Model-highlighted function(s): `payOut`
- Min distance model evidence tới GT: `0` line(s)
- Lý do Partial Localization: Model hit một phần GT lines nhưng bỏ sót phần còn lại của phạm vi lỗi.

GT code snippet:

```solidity
   12:                                        
>> 13:     if ( rand> 0 && now - rand > 24 hours ) {
   14:       msg.sender.send( msg.value );
  ...
   26:                                          
>> 27:       return block.timestamp;   
   28:     }
```

Model-highlighted snippet:

```solidity
   12:                                        
>> 13:     if ( rand> 0 && now - rand > 24 hours ) {
>> 14:       msg.sender.send( msg.value );
>> 15: 
>> 16:       if ( this.balance > 0 ) {
>> 17:         leader.send( this.balance );
>> 18:       }
>> 19:     }
   20:     else if ( msg.value >= 1 ether ) {
```

Trích/paraphrase từ thinking_process:

> ...dering the code provided. It's a Solidity contract named "lottopollo" with a version pragma for Solidity ^0.4.0. There are three functions: payOut, randomGen, and draw. I need to analyze for specific vulnerabilities from the set: Reentrancy_Attacks, Arithmetic, Time_Manipulation, Access_Control, Front-running_Attacks, Denial_of_Service_Attacks, Short_Addresses, Insecure_Randomness, Unchecked_External_Calls, or "Other" if none match. Let me break down the code: - Line 7: pragma solidity ^0.4.0; (not a vulnerability)...

Giải thích: model đã phát hiện đúng label và bám vào một phần luồng/phạm vi lỗi, nhưng evidence chưa bao phủ đúng toàn bộ dòng GT. Đây là định vị một phần, không phải phát hiện hoàn chỉnh.

## Kết luận

Có Partial Localization trong output `my_results_l5`: model thường hiểu đúng loại lỗi, nhưng evidence line chỉ phản ánh một phần nguyên nhân hoặc một line đại diện. Khi dùng kết quả để audit thủ công, các case này vẫn hữu ích hơn detection failure, nhưng cần mở rộng kiểm tra quanh function/luồng liên quan để không bỏ sót dòng GT.
