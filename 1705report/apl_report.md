# APL Report

Model output: `LOGs/my_results/vulnerability_report.csv`

## Method

- APL is computed from the model output only.
- For each predicted vulnerability label, `Sum of predicted labels` is the number of model prediction rows with that label.
- `N` is the number of unique contracts where that label appears in the model output.
- `APL = Sum of predicted labels / N`.
- Placeholder rows `(none)` and `(error)` are excluded.
- Label aliases normalized: `Reentrancy_Attack` -> `Reentrancy_Attacks`, `Front-Running` -> `Front-running_Attacks`, `other` -> `Other`.

## Summary

- Total non-placeholder predictions: 246
- Total label-contract groups: 218
- Overall APL across label-contract groups: 1.128440

## APL By Label

| Label | Sum of Predicted Labels | N Contracts | APL |
|---|---:|---:|---:|
| Access_Control | 41 | 36 | 1.138889 |
| Arithmetic | 51 | 45 | 1.133333 |
| Denial_of_Service_Attacks | 12 | 12 | 1.000000 |
| Front-running_Attacks | 1 | 1 | 1.000000 |
| Insecure_Randomness | 11 | 11 | 1.000000 |
| Other | 2 | 2 | 1.000000 |
| Reentrancy_Attacks | 85 | 73 | 1.164384 |
| Short_Addresses | 2 | 2 | 1.000000 |
| Time_Manipulation | 4 | 4 | 1.000000 |
| Unchecked_External_Calls | 37 | 32 | 1.156250 |

Detailed prediction rows are in `apl_prediction_details.csv`; machine-readable summary is in `apl_by_label.csv`.