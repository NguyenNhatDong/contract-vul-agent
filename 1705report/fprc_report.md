# FPR-C Report

Model output: `LOGs/my_results/vulnerability_report.csv`
Ground truth: `Description/smartbugs_dataset.csv`

## Method

- For each label, `N` is the number of ground-truth contracts of that label.
- `Sum FP` is counted separately per label.
- A false positive is counted when the model predicts that label for a contract, but that label does not exist in the ground truth for the same contract.
- Duplicate predictions of the same label for the same contract count once because this is FPR per contract.
- `FPR-C = Sum FP / N`.
- Placeholder model rows `(none)` and `(error)` are ignored as vulnerability predictions.
- Label aliases normalized: `Front-Running` -> `Front-running_Attacks`, `Reentrancy_Attack` -> `Reentrancy_Attacks`, `other` -> `Other`.

## Overall

- Sum FP: 129
- N contracts of labels: 143
- Overall FPR-C: 0.902098

## FPR-C By Label

| Label | Sum FP | N Contracts Of Label | FPR-C |
|---|---:|---:|---:|
| Access_Control | 26 | 18 | 1.444444 |
| Arithmetic | 31 | 15 | 2.066667 |
| Denial_of_Service_Attacks | 9 | 6 | 1.500000 |
| Front-running_Attacks | 1 | 4 | 0.250000 |
| Insecure_Randomness | 8 | 8 | 1.000000 |
| Other | 2 | 3 | 0.666667 |
| Reentrancy_Attacks | 45 | 31 | 1.451613 |
| Short_Addresses | 2 | 1 | 2.000000 |
| Time_Manipulation | 2 | 5 | 0.400000 |
| Unchecked_External_Calls | 3 | 52 | 0.057692 |

Detailed false-positive contracts are in `fprc_query_details.csv`; machine-readable summary is in `fprc_by_label.csv`.