# MRR Report

Model output: `LOGs/my_results/vulnerability_report.csv`
Ground truth: `Description/smartbugs_dataset.csv`

## Method

- Each contract-label pair in the ground truth is treated as one query.
- Model rows are kept in CSV order per contract and treated as the ranked result list.
- Reciprocal rank is `1 / rank` for the first predicted label matching the ground-truth label; missing matches receive `0`.
- Placeholder model rows `(none)` and `(error)` are ignored as vulnerability predictions.
- Label aliases normalized: `Front-Running` -> `Front-running_Attacks`, `Reentrancy_Attack` -> `Reentrancy_Attacks`, `other` -> `Other`.

## Summary

- Ground-truth contracts: 143
- Model contracts with vulnerability predictions: 123
- Evaluated contract-label queries: 143
- Queries with a matching prediction: 89
- Overall micro MRR: 0.526807

## MRR By Label

| Label | Queries | Found | Not Found | MRR |
|---|---:|---:|---:|---:|
| Access_Control | 18 | 10 | 8 | 0.435185 |
| Arithmetic | 15 | 14 | 1 | 0.900000 |
| Denial_of_Service_Attacks | 6 | 3 | 3 | 0.500000 |
| Front-running_Attacks | 4 | 0 | 4 | 0.000000 |
| Insecure_Randomness | 8 | 3 | 5 | 0.250000 |
| Other | 3 | 0 | 3 | 0.000000 |
| Reentrancy_Attacks | 31 | 28 | 3 | 0.903226 |
| Short_Addresses | 1 | 0 | 1 | 0.000000 |
| Time_Manipulation | 5 | 2 | 3 | 0.400000 |
| Unchecked_External_Calls | 52 | 29 | 23 | 0.365385 |

## Missing Prediction Contracts

- `access_control/mycontract.sol`
- `access_control/parity_wallet_bug_1.sol`
- `access_control/parity_wallet_bug_2.sol`
- `access_control/proxy.sol`
- `arithmetic/BECToken.sol`
- `bad_randomness/blackjack.sol`
- `bad_randomness/etheraffle.sol`
- `bad_randomness/lottery.sol`
- `bad_randomness/smart_billions.sol`
- `other/name_registrar.sol`
- `reentrancy/modifier_reentrancy.sol`
- `reentrancy/spank_chain_payment.sol`
- `time_manipulation/roulette.sol`
- `unchecked_low_level_calls/0x19cf8481ea15427a98ba3cdd6d9e14690011ab10.sol`
- `unchecked_low_level_calls/0x663e4229142a27f00bafb5d087e1e730648314c3.sol`
- `unchecked_low_level_calls/0x70f9eddb3931491aab1aeafbc1e7f1ca2a012db4.sol`
- `unchecked_low_level_calls/0x9d06cbafa865037a01d322d3f4222fa3e04e5488.sol`
- `unchecked_low_level_calls/0xe09b1ab8111c2729a76f16de96bc86a7af837928.sol`
- `unchecked_low_level_calls/0xec329ffc97d75fe03428ae155fc7793431487f63.sol`
- `unchecked_low_level_calls/0xf70d589d76eebdd7c12cc5eec99f8f6fa4233b9e.sol`

Detailed per-query ranks are in `mrr_query_details.csv`; machine-readable label summary is in `mrr_by_label.csv`.