# Tolerant Line Recall Report

Generated: 2026-05-20T14:43:29.588251

Model output: `LOGs\my_results_l5\vulnerability_report.csv`
Ground truth: `Description\smartbugs_dataset.csv`

## Method

- TLR@k uses line tolerance `±k` for `k = 1, 3, 5`.
- For each ground-truth `(folder, file_name, label)` sample, predictions are filtered to the same normalized label.
- Global evaluates all ground-truth samples.
- Conditional evaluates only samples where the model predicted the correct label at least once for the same contract.
- Percentages are `hit ground-truth lines / total ground-truth lines * 100`.

## Overall

| Scenario | Samples | GT Lines | TLR@1 | TLR@3 | TLR@5 |
|---|---:|---:|---:|---:|---:|
| Global | 143 | 222 | 50.90% | 52.70% | 54.05% |
| Conditional | 99 | 153 | 73.86% | 76.47% | 78.43% |

## Global By Label

| Label | Samples | GT Lines | Hit@1 | TLR@1 | Hit@3 | TLR@3 | Hit@5 | TLR@5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Access_Control | 18 | 24 | 8 | 33.33% | 8 | 33.33% | 8 | 33.33% |
| Arithmetic | 15 | 23 | 15 | 65.22% | 15 | 65.22% | 15 | 65.22% |
| Denial_of_Service_Attacks | 6 | 14 | 7 | 50.00% | 7 | 50.00% | 9 | 64.29% |
| Front-running_Attacks | 4 | 7 | 0 | 0.00% | 0 | 0.00% | 0 | 0.00% |
| Insecure_Randomness | 8 | 34 | 11 | 32.35% | 15 | 44.12% | 16 | 47.06% |
| Other | 3 | 5 | 0 | 0.00% | 0 | 0.00% | 0 | 0.00% |
| Reentrancy_Attacks | 31 | 32 | 28 | 87.50% | 28 | 87.50% | 28 | 87.50% |
| Short_Addresses | 1 | 1 | 0 | 0.00% | 0 | 0.00% | 0 | 0.00% |
| Time_Manipulation | 5 | 7 | 1 | 14.29% | 1 | 14.29% | 1 | 14.29% |
| Unchecked_External_Calls | 52 | 75 | 43 | 57.33% | 43 | 57.33% | 43 | 57.33% |
| Overall | 143 | 222 | 113 | 50.90% | 117 | 52.70% | 120 | 54.05% |

## Conditional By Label

| Label | Samples | GT Lines | Hit@1 | TLR@1 | Hit@3 | TLR@3 | Hit@5 | TLR@5 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Access_Control | 10 | 13 | 8 | 61.54% | 8 | 61.54% | 8 | 61.54% |
| Arithmetic | 13 | 18 | 15 | 83.33% | 15 | 83.33% | 15 | 83.33% |
| Denial_of_Service_Attacks | 3 | 10 | 7 | 70.00% | 7 | 70.00% | 9 | 90.00% |
| Insecure_Randomness | 7 | 32 | 11 | 34.38% | 15 | 46.88% | 16 | 50.00% |
| Reentrancy_Attacks | 29 | 29 | 28 | 96.55% | 28 | 96.55% | 28 | 96.55% |
| Time_Manipulation | 1 | 2 | 1 | 50.00% | 1 | 50.00% | 1 | 50.00% |
| Unchecked_External_Calls | 36 | 49 | 43 | 87.76% | 43 | 87.76% | 43 | 87.76% |
| Overall | 99 | 153 | 113 | 73.86% | 117 | 76.47% | 120 | 78.43% |

## Notes

- Label aliases normalized: `Front-Running` -> `Front-running_Attacks`, `Unchecked_External Calls` -> `Unchecked_External_Calls`, `other` -> `Other`.
- Evidence parser supports single lines, inclusive ranges, comma lists, and mixed comma/range values.
- Placeholder predictions such as `(none)`, `error`, `-`, and `--` are ignored as line predictions.
- Duplicate lines are deduplicated within each sample before recall is computed.
