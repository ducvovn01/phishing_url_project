# Autoencoder Report - Phishing URL Detector

Source: `scripts/autoencoder_model.py`. Same test split as `model_report.md`.

## Summary of findings

- Autoencoder (test): ROC-AUC 0.6175, PR-AUC 0.6936, F1 0.6359 (precision 0.5773, recall 0.7078), accuracy 0.5621, MCC 0.1040, RMSE 0.4864.
- The median reconstruction error of a phishing URL is 3.0x that of a legitimate one: phishing URLs do look unusual to a model of legitimate URLs, but the two error distributions overlap (table below).
- At threshold 0.5, a URL is flagged when its reconstruction error is above 0.0006.

## Setup

- Features (20): `url_length`, `hostname_length`, `path_length`, `query_length`, `dot_count`, `hyphen_count`, `digit_count`, `at_count`, `underscore_count`, `percent_count`, `equals_count`, `ampersand_count`, `digit_ratio`, `subdomain_count`, `path_depth`, `is_ip_hostname`, `has_port`, `has_punycode`, `suspicious_keyword_count`, `hostname_entropy`. log1p then standard scaling, fitted on legitimate train rows.
- Network: 20 -> 64 -> 32 -> 8 -> 32 -> 64 -> 20, ReLU, mean squared error loss, Adam (learning rate 0.001), batch 2048.
- Trained on the 566313 legitimate rows of a domain-grouped fit split of train; early stopping on the reconstruction loss of the 60978 legitimate validation rows (patience 5, best epoch 59 of 60).
- Probability: logistic regression on log(error), fitted on all 138994 validation rows, both classes.

## Training history

|   epoch |   train_loss |   val_loss |
|--------:|-------------:|-----------:|
|  1.0000 |       0.5402 |     0.1954 |
|  2.0000 |       0.1701 |     0.0823 |
|  3.0000 |       0.0757 |     0.0751 |
|  4.0000 |       0.0623 |     0.0504 |
|  5.0000 |       0.0456 |     0.0458 |
|  6.0000 |       0.0436 |     0.0455 |
|  7.0000 |       0.0369 |     0.0374 |
|  8.0000 |       0.0398 |     0.0528 |
|  9.0000 |       0.0408 |     0.0315 |
| 10.0000 |       0.0270 |     0.0281 |
| 11.0000 |       0.0251 |     0.0258 |
| 12.0000 |       0.0248 |     0.0264 |
| 13.0000 |       0.0259 |     0.0249 |
| 14.0000 |       0.0242 |     0.0280 |
| 15.0000 |       0.0203 |     0.0207 |
| 16.0000 |       0.0191 |     0.0245 |
| 17.0000 |       0.0228 |     0.0249 |
| 18.0000 |       0.0190 |     0.0203 |
| 19.0000 |       0.0170 |     0.0193 |
| 20.0000 |       0.0333 |     0.0205 |
| 21.0000 |       0.0163 |     0.0180 |
| 22.0000 |       0.0155 |     0.0173 |
| 23.0000 |       0.0169 |     0.0186 |
| 24.0000 |       0.0156 |     0.0163 |
| 25.0000 |       0.0154 |     0.0218 |
| 26.0000 |       0.0149 |     0.0160 |
| 27.0000 |       0.0144 |     0.0160 |
| 28.0000 |       0.0182 |     0.0172 |
| 29.0000 |       0.0153 |     0.0160 |
| 30.0000 |       0.0135 |     0.0145 |
| 31.0000 |       0.0130 |     0.0148 |
| 32.0000 |       0.0214 |     0.0144 |
| 33.0000 |       0.0146 |     0.0135 |
| 34.0000 |       0.0123 |     0.0168 |
| 35.0000 |       0.0146 |     0.0145 |
| 36.0000 |       0.0122 |     0.0141 |
| 37.0000 |       0.0124 |     0.0145 |
| 38.0000 |       0.0221 |     0.0131 |
| 39.0000 |       0.0115 |     0.0130 |
| 40.0000 |       0.0114 |     0.0129 |
| 41.0000 |       0.0134 |     0.0187 |
| 42.0000 |       0.0119 |     0.0122 |
| 43.0000 |       0.0116 |     0.0124 |
| 44.0000 |       0.0109 |     0.0120 |
| 45.0000 |       0.0131 |     0.0124 |
| 46.0000 |       0.0121 |     0.0118 |
| 47.0000 |       0.0108 |     0.0118 |
| 48.0000 |       0.0115 |     0.0112 |
| 49.0000 |       0.0110 |     0.0111 |
| 50.0000 |       0.0113 |     0.0133 |
| 51.0000 |       0.0137 |     0.0183 |
| 52.0000 |       0.0146 |     0.0112 |
| 53.0000 |       0.0100 |     0.0109 |
| 54.0000 |       0.0097 |     0.0108 |
| 55.0000 |       0.0101 |     0.0104 |
| 56.0000 |       0.0098 |     0.0111 |
| 57.0000 |       0.0107 |     0.0105 |
| 58.0000 |       0.0101 |     0.0106 |
| 59.0000 |       0.0114 |     0.0103 |
| 60.0000 |       0.0112 |     0.0118 |

## Test results

Same metrics as `model_report.md`; threshold 0.5 on the calibrated probability.

|             |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |    mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:------------|------------:|---------:|-------:|-----------:|--------------:|--------------------:|-------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| Autoencoder |      0.5773 |   0.7078 | 0.6359 |     0.5621 |        0.3909 |              0.5493 | 0.1040 | 0.4683 |      0.2366 | 0.4864 |     0.6633 |    0.6175 |   0.6936 |               0.1251 |

## Precision, recall and F1 by class (test split)

|              |   precision |   recall |     f1 |     support |
|:-------------|------------:|---------:|-------:|------------:|
| legitimate   |      0.5323 |   0.3909 | 0.4508 | 152983.0000 |
| phishing     |      0.5773 |   0.7078 | 0.6359 | 179786.0000 |
| macro avg    |      0.5548 |   0.5493 | 0.5433 | 332769.0000 |
| weighted avg |      0.5566 |   0.5621 | 0.5508 | 332769.0000 |

## Results by source (test split)

| source        |        rows |   phishing_share |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |     mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------|------------:|-----------------:|------------:|---------:|-------:|-----------:|--------------:|--------------------:|--------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| harisudhan411 |  47605.0000 |           0.8547 |      0.8265 |   0.6947 | 0.7549 |     0.6144 |        0.1427 |              0.4187 | -0.1275 | 0.4456 |      0.2138 | 0.4624 |     0.6154 |    0.4938 |   0.8787 |               0.0535 |
| mitake        | 173555.0000 |           0.3181 |      0.3589 |   0.8594 | 0.5063 |     0.4669 |        0.2838 |              0.5716 |  0.1565 | 0.4994 |      0.2678 | 0.5175 |     0.7289 |    0.6619 |   0.5595 |               0.1887 |
| phiusiil      |  40942.0000 |           0.3418 |      0.7992 |   0.5903 | 0.6791 |     0.8093 |        0.9230 |              0.7567 |  0.5605 | 0.4330 |      0.1951 | 0.4417 |     0.5795 |    0.7944 |   0.7798 |               0.4220 |
| semihguner    |  70667.0000 |           0.9891 |      0.9904 |   0.6192 | 0.7620 |     0.6174 |        0.4511 |              0.5352 |  0.0150 | 0.4276 |      0.1995 | 0.4467 |     0.5830 |    0.6042 |   0.9940 |               0.1891 |

## Reconstruction error by class (test split)

| label      |       count |   mean |     std |    min |    25% |    50% |    75% |    95% |      max |
|:-----------|------------:|-------:|--------:|-------:|-------:|-------:|-------:|-------:|---------:|
| legitimate | 152983.0000 | 0.0142 |  0.3493 | 0.0001 | 0.0002 | 0.0011 | 0.0066 | 0.0389 | 127.3750 |
| phishing   | 179786.0000 | 0.8193 | 12.3960 | 0.0001 | 0.0004 | 0.0033 | 0.0302 | 0.8556 | 609.0157 |

## Caveats

- An anomaly detector flags whatever is unusual, not only phishing: legitimate URLs with long paths or query strings also rebuild badly and become false positives.
- Phishing URLs that look like ordinary short URLs rebuild well and are missed; the supervised models can learn those patterns, this one cannot.
- Same as `model_report.md`: the test split comes from the same four overlapping sources as train.
