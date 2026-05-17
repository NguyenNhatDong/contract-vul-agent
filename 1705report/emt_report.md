# EMT Report

Model output: `LOGs/my_results/vulnerability_report.csv`
Ground truth: `Description/smartbugs_dataset.csv`

## Method

- `N` is the number of unique ground-truth contracts for each label.
- `E` increases by 1 only when that contract has exactly one non-placeholder model prediction and that prediction equals the ground-truth label being evaluated.
- Model `(none)` and `(error)` rows are treated as no vulnerability prediction.
- Label aliases normalized: `Front-Running` -> `Front-running_Attacks`, `Reentrancy_Attack` -> `Reentrancy_Attacks`, `other` -> `Other`.

## Summary

- Overall E: 38
- Overall N: 143
- Overall EMT: 0.265734

## EMT By Label

| Label | E | N | EMT |
|---|---:|---:|---:|
| Access_Control | 5 | 18 | 0.277778 |
| Arithmetic | 10 | 15 | 0.666667 |
| Denial_of_Service_Attacks | 3 | 6 | 0.500000 |
| Front-running_Attacks | 0 | 4 | 0.000000 |
| Insecure_Randomness | 0 | 8 | 0.000000 |
| Other | 0 | 3 | 0.000000 |
| Reentrancy_Attacks | 10 | 31 | 0.322581 |
| Short_Addresses | 0 | 1 | 0.000000 |
| Time_Manipulation | 1 | 5 | 0.200000 |
| Unchecked_External_Calls | 9 | 52 | 0.173077 |

Detailed per-contract decisions are in `emt_query_details.csv`; machine-readable label summary is in `emt_by_label.csv`.