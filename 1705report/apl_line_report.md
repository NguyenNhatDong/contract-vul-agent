# APL-Line Report

Generated: 2026-05-21T10:54:40.289789

Model output: `LOGs\my_results_l5\vulnerability_report.csv`
Ground truth: `Description\smartbugs_dataset.csv`

## Method

- APL-Line is the average number of predicted vulnerable lines per included sample.
- Formula: `APL-Line = total predicted_line_count / number of included samples`.
- APL-Line does not use a line tolerance value.
- `All Labels` counts aligned predicted lines from every vulnerability type for the same contract.
- `Correct Label Only` counts aligned predicted lines whose normalized type matches the GT label.
- `Global` includes every GT sample; `Conditional` includes only samples where the model predicted the correct vulnerability type at least once.
- Model CSV order is preserved before deduplicating predicted lines by first occurrence after range alignment.

## Overall

| Scope | Scenario | Label | Samples | Total Predicted Lines | APL-Line |
| --- | --- | --- | ---: | ---: | ---: |
| All Labels | Global | Overall | 143 | 280 | 1.958042 |
| All Labels | Conditional | Overall | 99 | 216 | 2.181818 |
| Correct Label Only | Global | Overall | 143 | 123 | 0.860140 |
| Correct Label Only | Conditional | Overall | 99 | 123 | 1.242424 |

## All Labels - Global By Label

| Label | Samples | Total Predicted Lines | APL-Line |
| --- | ---: | ---: | ---: |
| Access_Control | 18 | 28 | 1.555556 |
| Arithmetic | 15 | 22 | 1.466667 |
| Denial_of_Service_Attacks | 6 | 14 | 2.333333 |
| Front-running_Attacks | 4 | 4 | 1.000000 |
| Insecure_Randomness | 8 | 17 | 2.125000 |
| Other | 3 | 6 | 2.000000 |
| Reentrancy_Attacks | 31 | 72 | 2.322581 |
| Short_Addresses | 1 | 2 | 2.000000 |
| Time_Manipulation | 5 | 6 | 1.200000 |
| Unchecked_External_Calls | 52 | 109 | 2.096154 |

## All Labels - Conditional By Label

| Label | Samples | Total Predicted Lines | APL-Line |
| --- | ---: | ---: | ---: |
| Access_Control | 10 | 19 | 1.900000 |
| Arithmetic | 13 | 20 | 1.538462 |
| Denial_of_Service_Attacks | 3 | 9 | 3.000000 |
| Insecure_Randomness | 7 | 16 | 2.285714 |
| Reentrancy_Attacks | 29 | 70 | 2.413793 |
| Time_Manipulation | 1 | 2 | 2.000000 |
| Unchecked_External_Calls | 36 | 80 | 2.222222 |

## Correct Label Only - Global By Label

| Label | Samples | Total Predicted Lines | APL-Line |
| --- | ---: | ---: | ---: |
| Access_Control | 18 | 13 | 0.722222 |
| Arithmetic | 15 | 16 | 1.066667 |
| Denial_of_Service_Attacks | 6 | 8 | 1.333333 |
| Front-running_Attacks | 4 | 0 | 0.000000 |
| Insecure_Randomness | 8 | 12 | 1.500000 |
| Other | 3 | 0 | 0.000000 |
| Reentrancy_Attacks | 31 | 29 | 0.935484 |
| Short_Addresses | 1 | 0 | 0.000000 |
| Time_Manipulation | 5 | 1 | 0.200000 |
| Unchecked_External_Calls | 52 | 44 | 0.846154 |

## Correct Label Only - Conditional By Label

| Label | Samples | Total Predicted Lines | APL-Line |
| --- | ---: | ---: | ---: |
| Access_Control | 10 | 13 | 1.300000 |
| Arithmetic | 13 | 16 | 1.230769 |
| Denial_of_Service_Attacks | 3 | 8 | 2.666667 |
| Insecure_Randomness | 7 | 12 | 1.714286 |
| Reentrancy_Attacks | 29 | 29 | 1.000000 |
| Time_Manipulation | 1 | 1 | 1.000000 |
| Unchecked_External_Calls | 36 | 44 | 1.222222 |

## Notes

- Prediction parsing and range alignment are shared with Coverage/FCLR so the same `P` definition is used.
- Placeholder predictions such as `(none)`, `error`, `-`, and `--` do not contribute predicted lines.
- Ranges are aligned against GT lines before counting, so broad ranges are not blindly expanded into many predicted lines.
