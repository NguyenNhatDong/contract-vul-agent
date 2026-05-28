# First Correct Line Rank Report

Generated: 2026-05-21T10:32:18.749781

Model output: `LOGs\my_results_l5\vulnerability_report.csv`
Ground truth: `Description\smartbugs_dataset.csv`

## Method

- FCLR@k is the rank of the first predicted line within tolerance `±k` of any GT vulnerable line.
- Tolerance values are `1`, `3`, and `5`.
- Model CSV order is used as ranking order because no confidence scores are available.
- `All Labels` uses ranked predictions from every vulnerability type for the same contract.
- `Correct Label Only` uses ranked predictions whose normalized type matches the GT label.
- Conditional includes only samples where the correct normalized vulnerability type appears at least once for the same contract.
- Mean FCLR excludes `inf`: `sum(finite FCLR ranks) / number of finite samples`.
- Lower mean FCLR is better; Found% is the percentage of samples with finite FCLR.

## Overall

| Scope | Scenario | Label | Samples | Finite@1 | Found%@1 | Mean FCLR@1 | Inf@1 | Finite@3 | Found%@3 | Mean FCLR@3 | Inf@3 | Finite@5 | Found%@5 | Mean FCLR@5 | Inf@5 |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| All Labels | Global | Overall | 143 | 113 | 79.02% | 1.345133 | 30 | 118 | 82.52% | 1.322034 | 25 | 120 | 83.92% | 1.291667 | 23 |
| All Labels | Conditional | Overall | 99 | 96 | 96.97% | 1.312500 | 3 | 96 | 96.97% | 1.291667 | 3 | 96 | 96.97% | 1.260417 | 3 |
| Correct Label Only | Global | Overall | 143 | 93 | 65.03% | 1.021505 | 50 | 93 | 65.03% | 1.021505 | 50 | 94 | 65.73% | 1.021277 | 49 |
| Correct Label Only | Conditional | Overall | 99 | 93 | 93.94% | 1.021505 | 6 | 93 | 93.94% | 1.021505 | 6 | 94 | 94.95% | 1.021277 | 5 |

## All Labels - Global By Label

| Label | Samples | Finite@1 | Found%@1 | Mean FCLR@1 | Inf@1 | Finite@3 | Found%@3 | Mean FCLR@3 | Inf@3 | Finite@5 | Found%@5 | Mean FCLR@5 | Inf@5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Access_Control | 18 | 11 | 61.11% | 1.272727 | 7 | 11 | 61.11% | 1.181818 | 7 | 12 | 66.67% | 1.166667 | 6 |
| Arithmetic | 15 | 14 | 93.33% | 1.142857 | 1 | 15 | 100.00% | 1.133333 | 0 | 15 | 100.00% | 1.133333 | 0 |
| Denial_of_Service_Attacks | 6 | 5 | 83.33% | 1.000000 | 1 | 5 | 83.33% | 1.000000 | 1 | 5 | 83.33% | 1.000000 | 1 |
| Front-running_Attacks | 4 | 1 | 25.00% | 1.000000 | 3 | 1 | 25.00% | 1.000000 | 3 | 1 | 25.00% | 1.000000 | 3 |
| Insecure_Randomness | 8 | 6 | 75.00% | 1.333333 | 2 | 7 | 87.50% | 1.285714 | 1 | 7 | 87.50% | 1.285714 | 1 |
| Other | 3 | 1 | 33.33% | 1.000000 | 2 | 1 | 33.33% | 1.000000 | 2 | 2 | 66.67% | 1.500000 | 1 |
| Reentrancy_Attacks | 31 | 28 | 90.32% | 1.000000 | 3 | 28 | 90.32% | 1.000000 | 3 | 28 | 90.32% | 1.000000 | 3 |
| Short_Addresses | 1 | 0 | 0.00% | NA | 1 | 1 | 100.00% | 1.000000 | 0 | 1 | 100.00% | 1.000000 | 0 |
| Time_Manipulation | 5 | 2 | 40.00% | 1.000000 | 3 | 3 | 60.00% | 1.000000 | 2 | 3 | 60.00% | 1.000000 | 2 |
| Unchecked_External_Calls | 52 | 45 | 86.54% | 1.711111 | 7 | 46 | 88.46% | 1.695652 | 6 | 46 | 88.46% | 1.608696 | 6 |

## All Labels - Conditional By Label

| Label | Samples | Finite@1 | Found%@1 | Mean FCLR@1 | Inf@1 | Finite@3 | Found%@3 | Mean FCLR@3 | Inf@3 | Finite@5 | Found%@5 | Mean FCLR@5 | Inf@5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Access_Control | 10 | 9 | 90.00% | 1.222222 | 1 | 9 | 90.00% | 1.111111 | 1 | 9 | 90.00% | 1.111111 | 1 |
| Arithmetic | 13 | 13 | 100.00% | 1.153846 | 0 | 13 | 100.00% | 1.153846 | 0 | 13 | 100.00% | 1.153846 | 0 |
| Denial_of_Service_Attacks | 3 | 3 | 100.00% | 1.000000 | 0 | 3 | 100.00% | 1.000000 | 0 | 3 | 100.00% | 1.000000 | 0 |
| Insecure_Randomness | 7 | 6 | 85.71% | 1.333333 | 1 | 6 | 85.71% | 1.333333 | 1 | 6 | 85.71% | 1.333333 | 1 |
| Reentrancy_Attacks | 29 | 28 | 96.55% | 1.000000 | 1 | 28 | 96.55% | 1.000000 | 1 | 28 | 96.55% | 1.000000 | 1 |
| Time_Manipulation | 1 | 1 | 100.00% | 1.000000 | 0 | 1 | 100.00% | 1.000000 | 0 | 1 | 100.00% | 1.000000 | 0 |
| Unchecked_External_Calls | 36 | 36 | 100.00% | 1.666667 | 0 | 36 | 100.00% | 1.638889 | 0 | 36 | 100.00% | 1.555556 | 0 |

## Correct Label Only - Global By Label

| Label | Samples | Finite@1 | Found%@1 | Mean FCLR@1 | Inf@1 | Finite@3 | Found%@3 | Mean FCLR@3 | Inf@3 | Finite@5 | Found%@5 | Mean FCLR@5 | Inf@5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Access_Control | 18 | 7 | 38.89% | 1.000000 | 11 | 7 | 38.89% | 1.000000 | 11 | 7 | 38.89% | 1.000000 | 11 |
| Arithmetic | 15 | 13 | 86.67% | 1.076923 | 2 | 13 | 86.67% | 1.076923 | 2 | 13 | 86.67% | 1.076923 | 2 |
| Denial_of_Service_Attacks | 6 | 2 | 33.33% | 1.000000 | 4 | 2 | 33.33% | 1.000000 | 4 | 3 | 50.00% | 1.000000 | 3 |
| Front-running_Attacks | 4 | 0 | 0.00% | NA | 4 | 0 | 0.00% | NA | 4 | 0 | 0.00% | NA | 4 |
| Insecure_Randomness | 8 | 6 | 75.00% | 1.000000 | 2 | 6 | 75.00% | 1.000000 | 2 | 6 | 75.00% | 1.000000 | 2 |
| Other | 3 | 0 | 0.00% | NA | 3 | 0 | 0.00% | NA | 3 | 0 | 0.00% | NA | 3 |
| Reentrancy_Attacks | 31 | 28 | 90.32% | 1.000000 | 3 | 28 | 90.32% | 1.000000 | 3 | 28 | 90.32% | 1.000000 | 3 |
| Short_Addresses | 1 | 0 | 0.00% | NA | 1 | 0 | 0.00% | NA | 1 | 0 | 0.00% | NA | 1 |
| Time_Manipulation | 5 | 1 | 20.00% | 1.000000 | 4 | 1 | 20.00% | 1.000000 | 4 | 1 | 20.00% | 1.000000 | 4 |
| Unchecked_External_Calls | 52 | 36 | 69.23% | 1.027778 | 16 | 36 | 69.23% | 1.027778 | 16 | 36 | 69.23% | 1.027778 | 16 |

## Correct Label Only - Conditional By Label

| Label | Samples | Finite@1 | Found%@1 | Mean FCLR@1 | Inf@1 | Finite@3 | Found%@3 | Mean FCLR@3 | Inf@3 | Finite@5 | Found%@5 | Mean FCLR@5 | Inf@5 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Access_Control | 10 | 7 | 70.00% | 1.000000 | 3 | 7 | 70.00% | 1.000000 | 3 | 7 | 70.00% | 1.000000 | 3 |
| Arithmetic | 13 | 13 | 100.00% | 1.076923 | 0 | 13 | 100.00% | 1.076923 | 0 | 13 | 100.00% | 1.076923 | 0 |
| Denial_of_Service_Attacks | 3 | 2 | 66.67% | 1.000000 | 1 | 2 | 66.67% | 1.000000 | 1 | 3 | 100.00% | 1.000000 | 0 |
| Insecure_Randomness | 7 | 6 | 85.71% | 1.000000 | 1 | 6 | 85.71% | 1.000000 | 1 | 6 | 85.71% | 1.000000 | 1 |
| Reentrancy_Attacks | 29 | 28 | 96.55% | 1.000000 | 1 | 28 | 96.55% | 1.000000 | 1 | 28 | 96.55% | 1.000000 | 1 |
| Time_Manipulation | 1 | 1 | 100.00% | 1.000000 | 0 | 1 | 100.00% | 1.000000 | 0 | 1 | 100.00% | 1.000000 | 0 |
| Unchecked_External_Calls | 36 | 36 | 100.00% | 1.027778 | 0 | 36 | 100.00% | 1.027778 | 0 | 36 | 100.00% | 1.027778 | 0 |

## Notes

- `inf` values are excluded from mean FCLR and counted in `Inf@k`.
- Placeholder predictions `(none)`, `error`, `-`, and `--` are ignored.
- Duplicate predicted lines are deduplicated by first occurrence after range alignment.
- Label aliases and range alignment are shared with the existing Coverage/TLP scripts.
