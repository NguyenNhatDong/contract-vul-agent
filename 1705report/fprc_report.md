# FPR-C Report

Generated: 2026-05-27T16:22:39.994773

Model output: `LOGs\my_results_l5\vulnerability_report.csv`

Ground truth: `Description\smartbugs_dataset.csv`

## Method

- For each ground-truth label `L`, only contracts that belong to `L` in the ground truth are evaluated.
- `Sum FP(L)` is the number of valid model prediction rows on those contracts where `predicted_label != L`.
- Prediction rows are counted as rows, so repeated wrong predictions on the same contract still contribute to `Sum FP`.
- For each label, `N` is the number of unique ground-truth contracts of that label.
- Formula: `FPR-C(label) = Sum FP(label) / N(label)`.
- Overall FPR-C uses the sum of per-label false positives divided by the sum of per-label GT contract counts.
- Placeholder model rows `(none)` and `(error)` are ignored as vulnerability predictions.
- Label aliases are normalized, e.g. `Front-Running` -> `Front-running_Attacks`, `Reentrancy_Attack` -> `Reentrancy_Attacks`, `other` -> `Other`.

## Overall

- Sum FP: 160
- N contracts of labels: 143
- Overall FPR-C: 1.118881

## FPR-C By Label

| Label | Sum FP | N Contracts Of Label | FPR-C |
|---|---:|---:|---:|
| Access_Control | 15 | 18 | 0.833333 |
| Arithmetic | 6 | 15 | 0.400000 |
| Denial_of_Service_Attacks | 7 | 6 | 1.166667 |
| Front-running_Attacks | 4 | 4 | 1.000000 |
| Insecure_Randomness | 5 | 8 | 0.625000 |
| Other | 6 | 3 | 2.000000 |
| Reentrancy_Attacks | 38 | 31 | 1.225806 |
| Short_Addresses | 2 | 1 | 2.000000 |
| Time_Manipulation | 5 | 5 | 1.000000 |
| Unchecked_External_Calls | 72 | 52 | 1.384615 |

Detailed false-positive contracts are in `fprc_query_details.csv`; machine-readable summary is in `fprc_by_label.csv`.
