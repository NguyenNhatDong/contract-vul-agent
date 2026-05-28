# APL Report

Generated: 2026-05-25T14:58:34.083769

Model output: `LOGs\my_results_l5\vulnerability_report.csv`

Ground truth: `Description\smartbugs_dataset.csv`

## Method

- APL is computed per ground-truth label as the average number of model predictions per GT contract.
- Formula: `APL(label) = total model predictions on contracts of that GT label / total GT contracts of that label`.
- For each GT sample `(folder, file_name, label)`, every non-placeholder model prediction on that same contract is counted, regardless of whether the predicted label is correct or wrong.
- The denominator is the number of unique `(folder, file_name, label)` contract-label samples in the ground truth.
- Duplicate evidence rows for the same contract-label in ground truth are counted once in `GT Contracts`.
- Placeholder prediction rows `(none)` and `(error)` are excluded.
- Label aliases are normalized, e.g. `Reentrancy_Attack` -> `Reentrancy_Attacks`, `Front-Running` -> `Front-running_Attacks`, `other` -> `Other`.

## Summary

- Total model predictions counted against GT labels: 269
- Total GT contract-label samples: 143
- Overall APL: 1.881119

## APL By Label

| Label | Total Predictions | GT Contracts | APL |
|---|---:|---:|---:|
| Access_Control | 27 | 18 | 1.500000 |
| Arithmetic | 22 | 15 | 1.466667 |
| Denial_of_Service_Attacks | 10 | 6 | 1.666667 |
| Front-running_Attacks | 4 | 4 | 1.000000 |
| Insecure_Randomness | 12 | 8 | 1.500000 |
| Other | 6 | 3 | 2.000000 |
| Reentrancy_Attacks | 67 | 31 | 2.161290 |
| Short_Addresses | 2 | 1 | 2.000000 |
| Time_Manipulation | 6 | 5 | 1.200000 |
| Unchecked_External_Calls | 113 | 52 | 2.173077 |

Detailed prediction rows are in `apl_prediction_details.csv`; machine-readable summary is in `apl_by_label.csv`.
