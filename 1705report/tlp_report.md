# Tolerant Line Precision Report

Generated: 2026-05-20T22:19:59.484393

Model output: `LOGs\my_results_l5\vulnerability_report.csv`
Ground truth: `Description\smartbugs_dataset.csv`

## Method

- TLP@k uses line tolerance `±k` for `k = 1, 3, 5`.
- For each ground-truth `(folder, file_name, label)` sample, `P` is built from all non-placeholder predicted vulnerable evidence for the same contract, across all predicted labels.
- Predicted line ranges are aligned per GT vulnerability before counting P: same-label overlapping ranges keep only the GT-overlapping lines; non-overlapping ranges and wrong-label ranges are compressed to the line closest to GT.
- Global evaluates all ground-truth samples.
- Conditional evaluates only samples where the model predicted the correct label at least once for the same contract.
- In Conditional, wrong-label predicted lines on an included contract still remain in the precision denominator.
- Conditional By Vuln evaluates the same included samples, but `P` includes only predicted lines from the correctly predicted vulnerability type.
- Percentages are `matched predicted lines / total predicted lines * 100`.

## Overall

| Scenario | Samples | GT Lines | Pred Lines | TLP@1 | TLP@3 | TLP@5 |
|---|---:|---:|---:|---:|---:|---:|
| Global | 143 | 222 | 280 | 50.36% | 57.14% | 62.50% |
| Conditional | 99 | 153 | 216 | 56.02% | 61.57% | 66.20% |
| Conditional By Vuln | 99 | 153 | 123 | 91.87% | 91.87% | 94.31% |

## Global By Label

| Label | Samples | GT Lines | Pred Lines | Match@1 | TLP@1 | Match@3 | TLP@3 | Match@5 | TLP@5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Access_Control | 18 | 24 | 28 | 13 | 46.43% | 14 | 50.00% | 18 | 64.29% |
| Arithmetic | 15 | 23 | 22 | 16 | 72.73% | 19 | 86.36% | 19 | 86.36% |
| Denial_of_Service_Attacks | 6 | 14 | 14 | 10 | 71.43% | 10 | 71.43% | 11 | 78.57% |
| Front-running_Attacks | 4 | 7 | 4 | 2 | 50.00% | 2 | 50.00% | 2 | 50.00% |
| Insecure_Randomness | 8 | 34 | 17 | 12 | 70.59% | 13 | 76.47% | 13 | 76.47% |
| Other | 3 | 5 | 6 | 1 | 16.67% | 1 | 16.67% | 2 | 33.33% |
| Reentrancy_Attacks | 31 | 32 | 72 | 28 | 38.89% | 34 | 47.22% | 36 | 50.00% |
| Short_Addresses | 1 | 1 | 2 | 0 | 0.00% | 2 | 100.00% | 2 | 100.00% |
| Time_Manipulation | 5 | 7 | 6 | 3 | 50.00% | 4 | 66.67% | 4 | 66.67% |
| Unchecked_External_Calls | 52 | 75 | 109 | 56 | 51.38% | 61 | 55.96% | 68 | 62.39% |
| Overall | 143 | 222 | 280 | 141 | 50.36% | 160 | 57.14% | 175 | 62.50% |

## Conditional By Label

| Label | Samples | GT Lines | Pred Lines | Match@1 | TLP@1 | Match@3 | TLP@3 | Match@5 | TLP@5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Access_Control | 10 | 13 | 19 | 11 | 57.89% | 12 | 63.16% | 14 | 73.68% |
| Arithmetic | 13 | 18 | 20 | 15 | 75.00% | 17 | 85.00% | 17 | 85.00% |
| Denial_of_Service_Attacks | 3 | 10 | 9 | 8 | 88.89% | 8 | 88.89% | 9 | 100.00% |
| Insecure_Randomness | 7 | 32 | 16 | 12 | 75.00% | 12 | 75.00% | 12 | 75.00% |
| Reentrancy_Attacks | 29 | 29 | 70 | 28 | 40.00% | 34 | 48.57% | 36 | 51.43% |
| Time_Manipulation | 1 | 2 | 2 | 2 | 100.00% | 2 | 100.00% | 2 | 100.00% |
| Unchecked_External_Calls | 36 | 49 | 80 | 45 | 56.25% | 48 | 60.00% | 53 | 66.25% |
| Overall | 99 | 153 | 216 | 121 | 56.02% | 133 | 61.57% | 143 | 66.20% |

## Conditional By Vuln

| Label | Samples | GT Lines | Pred Lines | Match@1 | TLP@1 | Match@3 | TLP@3 | Match@5 | TLP@5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Access_Control | 10 | 13 | 13 | 8 | 61.54% | 8 | 61.54% | 10 | 76.92% |
| Arithmetic | 13 | 18 | 16 | 15 | 93.75% | 15 | 93.75% | 15 | 93.75% |
| Denial_of_Service_Attacks | 3 | 10 | 8 | 7 | 87.50% | 7 | 87.50% | 8 | 100.00% |
| Insecure_Randomness | 7 | 32 | 12 | 11 | 91.67% | 11 | 91.67% | 11 | 91.67% |
| Reentrancy_Attacks | 29 | 29 | 29 | 28 | 96.55% | 28 | 96.55% | 28 | 96.55% |
| Time_Manipulation | 1 | 2 | 1 | 1 | 100.00% | 1 | 100.00% | 1 | 100.00% |
| Unchecked_External_Calls | 36 | 49 | 44 | 43 | 97.73% | 43 | 97.73% | 43 | 97.73% |
| Overall | 99 | 153 | 123 | 113 | 91.87% | 113 | 91.87% | 116 | 94.31% |

## Notes

- Label aliases and evidence parsing are shared with `evaluate_tlr.py`.
- Placeholder predictions such as `(none)`, `error`, `-`, and `--` are ignored as line predictions.
- Duplicate aligned predicted lines are deduplicated within each sample before precision is computed.
- Labels with zero predicted vulnerable lines have TLP reported as `0.00%`.
