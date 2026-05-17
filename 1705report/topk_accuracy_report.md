# TOP-K Accuracy Report

Model output: `LOGs/my_results/vulnerability_report.csv`
Ground truth: `Description/smartbugs_dataset.csv`

## Method

- Each ground-truth contract-label pair is treated as one query.
- Model rows are kept in CSV order per contract and treated as ranked predictions.
- `TOP-1 Accuracy = O / N`, where `O` counts queries whose first prediction equals the ground-truth label.
- `TOP-3 Accuracy = T / N`, where `T` counts queries whose ground-truth label appears in the first 3 predictions.
- `TOP-max Accuracy = M / N`, where `M` counts queries whose ground-truth label appears anywhere in the model predictions.
- Placeholder model rows `(none)` and `(error)` are ignored as vulnerability predictions.
- Label aliases normalized: `Front-Running` -> `Front-running_Attacks`, `Reentrancy_Attack` -> `Reentrancy_Attacks`, `other` -> `Other`.

## Overall

- N: 143
- TOP-1: 65 / 143 = 0.454545
- TOP-3: 87 / 143 = 0.608392
- TOP-max: 89 / 143 = 0.622378

## Accuracy By Label

| Label | N | O Top-1 | TOP-1 Accuracy | T Top-3 | TOP-3 Accuracy | M TOP-max | TOP-max Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|
| Access_Control | 18 | 6 | 0.333333 | 10 | 0.555556 | 10 | 0.555556 |
| Arithmetic | 15 | 13 | 0.866667 | 14 | 0.933333 | 14 | 0.933333 |
| Denial_of_Service_Attacks | 6 | 3 | 0.500000 | 3 | 0.500000 | 3 | 0.500000 |
| Front-running_Attacks | 4 | 0 | 0.000000 | 0 | 0.000000 | 0 | 0.000000 |
| Insecure_Randomness | 8 | 1 | 0.125000 | 3 | 0.375000 | 3 | 0.375000 |
| Other | 3 | 0 | 0.000000 | 0 | 0.000000 | 0 | 0.000000 |
| Reentrancy_Attacks | 31 | 28 | 0.903226 | 28 | 0.903226 | 28 | 0.903226 |
| Short_Addresses | 1 | 0 | 0.000000 | 0 | 0.000000 | 0 | 0.000000 |
| Time_Manipulation | 5 | 2 | 0.400000 | 2 | 0.400000 | 2 | 0.400000 |
| Unchecked_External_Calls | 52 | 12 | 0.230769 | 27 | 0.519231 | 29 | 0.557692 |

Detailed per-query decisions are in `topk_accuracy_query_details.csv`; machine-readable summary is in `topk_accuracy_by_label.csv`.