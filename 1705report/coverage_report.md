# Coverage@K Report

Generated: 2026-05-20T23:00:17.784168

Model output: `LOGs\my_results_l5\vulnerability_report.csv`
Ground truth: `Description\smartbugs_dataset.csv`

## Method

- Coverage@K evaluates how many GT vulnerable lines are covered by the first K ranked predicted lines.
- Top-K values are `1`, `3`, and `5`; tolerance values are `±1`, `±3`, and `±5`.
- Model CSV order is used as ranking order because no confidence scores are available.
- `All Labels` uses ranked predictions from every vulnerability type for the same contract.
- `Correct Label Only` uses ranked predictions whose normalized type matches the GT label.
- Conditional includes only samples where the correct normalized vulnerability type appears at least once for the same contract.
- Predicted line ranges use the same range-aware alignment as TLP before ranking/deduplication.

## Overall

| Scope | Scenario | Samples | GT Lines | C@1±1 | C@1±3 | C@1±5 | C@3±1 | C@3±3 | C@3±5 | C@5±1 | C@5±3 | C@5±5 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| All Labels | Global | 143 | 222 | 40.09% | 45.95% | 51.35% | 60.81% | 66.67% | 70.27% | 63.06% | 68.47% | 71.62% |
| All Labels | Conditional | 99 | 153 | 50.98% | 56.21% | 60.13% | 75.82% | 80.39% | 81.70% | 78.43% | 82.35% | 83.01% |
| Correct Label Only | Global | 143 | 222 | 42.79% | 46.40% | 49.10% | 50.00% | 52.70% | 54.05% | 50.90% | 52.70% | 54.05% |
| Correct Label Only | Conditional | 99 | 153 | 62.09% | 67.32% | 71.24% | 72.55% | 76.47% | 78.43% | 73.86% | 76.47% | 78.43% |

## All Labels - Global By Label

| Label | Samples | GT Lines | C@1±1 | C@1±3 | C@1±5 | C@3±1 | C@3±3 | C@3±5 | C@5±1 | C@5±3 | C@5±5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Access_Control | 18 | 24 | 41.67% | 41.67% | 50.00% | 50.00% | 50.00% | 58.33% | 50.00% | 50.00% | 58.33% |
| Arithmetic | 15 | 23 | 56.52% | 60.87% | 65.22% | 69.57% | 73.91% | 78.26% | 69.57% | 73.91% | 78.26% |
| Denial_of_Service_Attacks | 6 | 14 | 57.14% | 78.57% | 85.71% | 71.43% | 85.71% | 85.71% | 78.57% | 85.71% | 85.71% |
| Front-running_Attacks | 4 | 7 | 14.29% | 14.29% | 14.29% | 28.57% | 28.57% | 28.57% | 28.57% | 28.57% | 28.57% |
| Insecure_Randomness | 8 | 34 | 14.71% | 29.41% | 35.29% | 26.47% | 44.12% | 50.00% | 32.35% | 47.06% | 50.00% |
| Other | 3 | 5 | 20.00% | 20.00% | 20.00% | 20.00% | 20.00% | 40.00% | 20.00% | 20.00% | 40.00% |
| Reentrancy_Attacks | 31 | 32 | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% |
| Short_Addresses | 1 | 1 | 0.00% | 100.00% | 100.00% | 0.00% | 100.00% | 100.00% | 0.00% | 100.00% | 100.00% |
| Time_Manipulation | 5 | 7 | 28.57% | 42.86% | 57.14% | 42.86% | 57.14% | 71.43% | 42.86% | 57.14% | 71.43% |
| Unchecked_External_Calls | 52 | 75 | 28.00% | 30.67% | 37.33% | 72.00% | 74.67% | 76.00% | 74.67% | 78.67% | 80.00% |

## All Labels - Conditional By Label

| Label | Samples | GT Lines | C@1±1 | C@1±3 | C@1±5 | C@3±1 | C@3±3 | C@3±5 | C@5±1 | C@5±3 | C@5±5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Access_Control | 10 | 13 | 69.23% | 69.23% | 69.23% | 76.92% | 76.92% | 76.92% | 76.92% | 76.92% | 76.92% |
| Arithmetic | 13 | 18 | 66.67% | 66.67% | 66.67% | 83.33% | 83.33% | 83.33% | 83.33% | 83.33% | 83.33% |
| Denial_of_Service_Attacks | 3 | 10 | 60.00% | 90.00% | 100.00% | 80.00% | 100.00% | 100.00% | 90.00% | 100.00% | 100.00% |
| Insecure_Randomness | 7 | 32 | 15.62% | 28.12% | 34.38% | 28.12% | 43.75% | 50.00% | 34.38% | 46.88% | 50.00% |
| Reentrancy_Attacks | 29 | 29 | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% |
| Time_Manipulation | 1 | 2 | 50.00% | 50.00% | 50.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% | 100.00% |
| Unchecked_External_Calls | 36 | 49 | 34.69% | 36.73% | 42.86% | 89.80% | 89.80% | 89.80% | 91.84% | 93.88% | 93.88% |

## Correct Label Only - Global By Label

| Label | Samples | GT Lines | C@1±1 | C@1±3 | C@1±5 | C@3±1 | C@3±3 | C@3±5 | C@5±1 | C@5±3 | C@5±5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Access_Control | 18 | 24 | 33.33% | 33.33% | 33.33% | 33.33% | 33.33% | 33.33% | 33.33% | 33.33% | 33.33% |
| Arithmetic | 15 | 23 | 52.17% | 52.17% | 52.17% | 65.22% | 65.22% | 65.22% | 65.22% | 65.22% | 65.22% |
| Denial_of_Service_Attacks | 6 | 14 | 28.57% | 42.86% | 64.29% | 42.86% | 50.00% | 64.29% | 50.00% | 50.00% | 64.29% |
| Front-running_Attacks | 4 | 7 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| Insecure_Randomness | 8 | 34 | 20.59% | 38.24% | 47.06% | 29.41% | 44.12% | 47.06% | 32.35% | 44.12% | 47.06% |
| Other | 3 | 5 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| Reentrancy_Attacks | 31 | 32 | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% | 87.50% |
| Short_Addresses | 1 | 1 | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| Time_Manipulation | 5 | 7 | 14.29% | 14.29% | 14.29% | 14.29% | 14.29% | 14.29% | 14.29% | 14.29% | 14.29% |
| Unchecked_External_Calls | 52 | 75 | 46.67% | 46.67% | 46.67% | 57.33% | 57.33% | 57.33% | 57.33% | 57.33% | 57.33% |

## Correct Label Only - Conditional By Label

| Label | Samples | GT Lines | C@1±1 | C@1±3 | C@1±5 | C@3±1 | C@3±3 | C@3±5 | C@5±1 | C@5±3 | C@5±5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Access_Control | 10 | 13 | 61.54% | 61.54% | 61.54% | 61.54% | 61.54% | 61.54% | 61.54% | 61.54% | 61.54% |
| Arithmetic | 13 | 18 | 66.67% | 66.67% | 66.67% | 83.33% | 83.33% | 83.33% | 83.33% | 83.33% | 83.33% |
| Denial_of_Service_Attacks | 3 | 10 | 40.00% | 60.00% | 90.00% | 60.00% | 70.00% | 90.00% | 70.00% | 70.00% | 90.00% |
| Insecure_Randomness | 7 | 32 | 21.88% | 40.62% | 50.00% | 31.25% | 46.88% | 50.00% | 34.38% | 46.88% | 50.00% |
| Reentrancy_Attacks | 29 | 29 | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% | 96.55% |
| Time_Manipulation | 1 | 2 | 50.00% | 50.00% | 50.00% | 50.00% | 50.00% | 50.00% | 50.00% | 50.00% | 50.00% |
| Unchecked_External_Calls | 36 | 49 | 71.43% | 71.43% | 71.43% | 87.76% | 87.76% | 87.76% | 87.76% | 87.76% | 87.76% |

## Notes

- Placeholder predictions `(none)`, `error`, `-`, and `--` are ignored.
- Duplicate predicted lines are deduplicated by first occurrence after range alignment.
- Label aliases are inherited from `evaluate_tlr.py`.
