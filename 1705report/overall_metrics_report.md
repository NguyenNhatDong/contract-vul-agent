# Overall Metrics Report

Generated: 2026-05-18

This file consolidates the overall results from the metric reports in `1705report/`.

## Overall Metrics

| Metric | Numerator / Denominator | Overall Value |
|---|---:|---:|
| EMT | 38 / 143 | 0.265734 |
| TOP-1 Acc | 65 / 143 | 0.454545 |
| TOP-3 Acc | 87 / 143 | 0.608392 |
| TOP-max Acc | 89 / 143 | 0.622378 |
| FPRC | 129 / 143 | 0.902098 |
| MRR | 89 matched / 143 queries | 0.526807 |
| APL | 246 predictions / 218 label-contract groups | 1.128440 |

## Metric Meaning

| Metric | Meaning | Better Direction |
|---|---|---|
| EMT | Exact-match tendency: contract has exactly one non-placeholder prediction and it matches the ground truth label. | Higher |
| TOP-1 Acc | Ground-truth label is the first model prediction. | Higher |
| TOP-3 Acc | Ground-truth label appears in the first 3 model predictions. | Higher |
| TOP-max Acc | Ground-truth label appears anywhere in the model predictions. | Higher |
| FPRC | False positives per contract for each label. | Lower |
| MRR | Mean reciprocal rank of the first matching prediction. | Higher |
| APL | Average predicted labels per label-contract group. | Lower is usually cleaner; values near 1 mean fewer duplicate predictions |

## Overall By Label

| Label | N | EMT | TOP-1 Acc | TOP-3 Acc | TOP-max Acc | FPRC | MRR | APL |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Access_Control | 18 | 0.277778 | 0.333333 | 0.555556 | 0.555556 | 1.444444 | 0.435185 | 1.138889 |
| Arithmetic | 15 | 0.666667 | 0.866667 | 0.933333 | 0.933333 | 2.066667 | 0.900000 | 1.133333 |
| Denial_of_Service_Attacks | 6 | 0.500000 | 0.500000 | 0.500000 | 0.500000 | 1.500000 | 0.500000 | 1.000000 |
| Front-running_Attacks | 4 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.250000 | 0.000000 | 1.000000 |
| Insecure_Randomness | 8 | 0.000000 | 0.125000 | 0.375000 | 0.375000 | 1.000000 | 0.250000 | 1.000000 |
| Other | 3 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 0.666667 | 0.000000 | 1.000000 |
| Reentrancy_Attacks | 31 | 0.322581 | 0.903226 | 0.903226 | 0.903226 | 1.451613 | 0.903226 | 1.164384 |
| Short_Addresses | 1 | 0.000000 | 0.000000 | 0.000000 | 0.000000 | 2.000000 | 0.000000 | 1.000000 |
| Time_Manipulation | 5 | 0.200000 | 0.400000 | 0.400000 | 0.400000 | 0.400000 | 0.400000 | 1.000000 |
| Unchecked_External_Calls | 52 | 0.173077 | 0.230769 | 0.519231 | 0.557692 | 0.057692 | 0.365385 | 1.156250 |

## Source Files

The consolidated values were taken from these files:

| Metric | Report | Label Summary | Detail File |
|---|---|---|---|
| EMT | `emt_report.md` | `emt_by_label.csv` | `emt_query_details.csv` |
| TOP-K Accuracy | `topk_accuracy_report.md` | `topk_accuracy_by_label.csv` | `topk_accuracy_query_details.csv` |
| FPRC | `fprc_report.md` | `fprc_by_label.csv` | `fprc_query_details.csv` |
| MRR | `mrr_report.md` | `mrr_by_label.csv` | `mrr_query_details.csv` |
| APL | `apl_report.md` | `apl_by_label.csv` | `apl_prediction_details.csv` |
