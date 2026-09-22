# Char N-gram Report - Phishing URL Detector

Source: `scripts/train_char_ngram.py`. Compared with the models from `scripts/train_model.py` on the same test split.

## Summary of findings

- Char n-gram + Logistic Regression (test): ROC-AUC 0.9674, PR-AUC 0.9742, F1 0.9133 (precision 0.9150, recall 0.9117) at threshold 0.5. At a 1% false-positive rate it catches 66.80% of phishing URLs.
- Char n-gram accuracy 0.9065, balanced accuracy 0.9061, specificity 0.9004, MCC 0.8119; macro F1 over both classes 0.9059.
- LightGBM on the same rows: ROC-AUC 0.9077, PR-AUC 0.9330, F1 0.8352, recall at 1% FPR 55.25%.
- Logistic Regression on the 21 URL features: ROC-AUC 0.8145, PR-AUC 0.8675, F1 0.7413. Same classifier as the n-gram model, so the gap between the two is down to the input representation.
- Probability error (test, lower is better): char n-gram MAE 0.1213, RMSE 0.2649, log loss 0.2399; LightGBM MAE 0.2160, RMSE 0.3498, log loss 0.3888; Logistic Regression MAE 0.3195, RMSE 0.4190, log loss 0.5204.
- At threshold 0.5, the n-gram model misses 15871 of 179786 phishing URLs and flags 15234 of 152983 legitimate URLs (9.96%).

## Setup

- Test split: `split_by_domain()` from `train_model.py` (same rows as `model_report.md`).
- Input: URL with the scheme stripped and lowercased. Scheme and letter case mostly record how each source formatted its URLs (phiusiil has no uppercase at all), so they are removed.
- Features: every 3-5 character substring, hashed into 1,048,576 columns (`HashingVectorizer`), then TF-IDF with sublinear term frequency.
- Classifier: `LogisticRegression(solver="liblinear")` with L2 penalty.
- `C` (inverse regularization strength) was picked from [1.0, 3.0, 10.0, 30.0] by PR-AUC on a domain-grouped validation split of train (1136013 fit / 138994 validation rows). The final model was refit on all of train.

## Tuning (validation split of train)

|       C |   val_pr_auc |
|--------:|-------------:|
|  1.0000 |       0.9612 |
|  3.0000 |       0.9649 |
| 10.0000 |       0.9674 |
| 30.0000 |       0.9677 |

Selected: C=30.0

## Test results

Threshold-based metrics use threshold 0.5. `recall_at_1pct_fpr` is the share of phishing URLs caught when 1% of legitimate URLs are flagged. `precision`, `recall` and `f1` are for the phishing class; `specificity` is the recall of the legitimate class, `balanced_accuracy` the mean of the two recalls, and `mcc` the Matthews correlation (-1 to 1, 0 = chance). `mae`, `mse_brier`, `rmse` and `log_loss` compare the predicted phishing probability with the 0/1 label (lower is better); `mse_brier` is the Brier score and `rmse` its square root.

|                                                   |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |    mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------------------------------------------|------------:|---------:|-------:|-----------:|--------------:|--------------------:|-------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| Char n-gram + Logistic Regression                 |      0.9150 |   0.9117 | 0.9133 |     0.9065 |        0.9004 |              0.9061 | 0.8119 | 0.1213 |      0.0702 | 0.2649 |     0.2399 |    0.9674 |   0.9742 |               0.6680 |
| LightGBM (saved model)                            |      0.8862 |   0.7897 | 0.8352 |     0.8316 |        0.8808 |              0.8353 | 0.6688 | 0.2160 |      0.1224 | 0.3498 |     0.3888 |    0.9077 |   0.9330 |               0.5525 |
| Logistic Regression on URL features (saved model) |      0.8238 |   0.6739 | 0.7413 |     0.7459 |        0.8306 |              0.7522 | 0.5062 | 0.3195 |      0.1756 | 0.4190 |     0.5204 |    0.8145 |   0.8675 |               0.3756 |

## Char n-gram precision, recall and F1 by class (test split)

|              |   precision |   recall |     f1 |     support |
|:-------------|------------:|---------:|-------:|------------:|
| legitimate   |      0.8967 |   0.9004 | 0.8985 | 152983.0000 |
| phishing     |      0.9150 |   0.9117 | 0.9133 | 179786.0000 |
| macro avg    |      0.9058 |   0.9061 | 0.9059 | 332769.0000 |
| weighted avg |      0.9066 |   0.9065 | 0.9065 | 332769.0000 |

## Char n-gram results by source (test split)

| source        |        rows |   phishing_share |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |    mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------|------------:|-----------------:|------------:|---------:|-------:|-----------:|--------------:|--------------------:|-------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| harisudhan411 |  47605.0000 |           0.8547 |      0.9835 |   0.8395 | 0.9058 |     0.8508 |        0.9170 |              0.8783 | 0.6003 | 0.1859 |      0.1101 | 0.3317 |     0.3632 |    0.9540 |   0.9906 |               0.4367 |
| mitake        | 173555.0000 |           0.3181 |      0.8080 |   0.9534 | 0.8747 |     0.9131 |        0.8943 |              0.9238 | 0.8153 | 0.1155 |      0.0656 | 0.2560 |     0.2258 |    0.9795 |   0.9626 |               0.7146 |
| phiusiil      |  40942.0000 |           0.3418 |      0.8326 |   0.7248 | 0.7750 |     0.8561 |        0.9243 |              0.8246 | 0.6735 | 0.1812 |      0.1095 | 0.3309 |     0.3800 |    0.8972 |   0.8749 |               0.5684 |
| semihguner    |  70667.0000 |           0.9891 |      0.9983 |   0.9583 | 0.9779 |     0.9572 |        0.8540 |              0.9061 | 0.3843 | 0.0573 |      0.0320 | 0.1788 |     0.1103 |    0.9777 |   0.9997 |               0.7905 |

## Char n-gram confusion matrix (test split)

|                   |   predicted legitimate |   predicted phishing |
|:------------------|-----------------------:|---------------------:|
| actual legitimate |                 137749 |                15234 |
| actual phishing   |                  15871 |               163915 |

## Strongest n-grams

Largest positive (phishing) and negative (legitimate) weights among n-grams seen in at least 200 of 300,000 sampled train URLs. Weights are per hashed column, so a column shared by two n-grams shows their combined weight.

| direction   | ngram   |   weight |
|:------------|:--------|---------:|
| phishing    | `.top`  |   48.800 |
| phishing    | `.jp.`  |   33.409 |
| phishing    | `ww.`   |   30.392 |
| phishing    | `o.jp.` |   25.456 |
| phishing    | `.tk`   |   24.796 |
| phishing    | `jp.`   |   23.852 |
| phishing    | `.cn/`  |   22.377 |
| phishing    | `.io/`  |   21.918 |
| phishing    | `.gq`   |   21.767 |
| phishing    | `.ml`   |   21.647 |
| phishing    | `.com.` |   19.537 |
| phishing    | `hgs`   |   19.257 |
| phishing    | `cn/`   |   19.164 |
| phishing    | `.cf`   |   18.857 |
| phishing    | `.php`  |   18.664 |
| legitimate  | `www.`  |  -37.389 |
| legitimate  | `.co`   |  -32.594 |
| legitimate  | `www`   |  -31.894 |
| legitimate  | `.de`   |  -29.823 |
| legitimate  | `.jp`   |  -29.704 |
| legitimate  | `.cfm`  |  -29.070 |
| legitimate  | `.gov`  |  -27.598 |
| legitimate  | `.io`   |  -24.938 |
| legitimate  | `.pdf`  |  -22.266 |
| legitimate  | `.fr`   |  -21.681 |
| legitimate  | `.pd`   |  -21.565 |
| legitimate  | `.edu`  |  -21.551 |
| legitimate  | `.nl`   |  -21.487 |
| legitimate  | `htm`   |  -21.309 |
| legitimate  | `.ca`   |  -21.274 |

## Brand-substring signal (vs. the FR3 brand-similarity features)

`scripts/extract_features.py` now computes `brand_similarity_score` and `is_exact_brand_match` against a curated brand list (see `model_report.md`) for the LightGBM/Logistic Regression models. The char n-gram model gets no such list — it only ever sees 3-5 character substrings of the raw URL — so the question is whether it already learns brand-name substrings as a signal on its own. Summing the model's learned weight over every 3-5 character n-gram in a brand name (both the clean spelling and a leetspeak typo) answers this directly:

| word       |   sum_weight |
|:-----------|-------------:|
| paypal     |       40.773 |
| paypa1     |       36.200 |
| amazon     |       16.840 |
| amaz0n     |       20.840 |
| google     |       -7.725 |
| g00gle     |       -6.157 |
| apple      |        8.008 |
| appleid    |       18.443 |
| facebook   |       16.857 |
| faceb00k   |       15.452 |
| netflix    |       12.751 |
| chase      |       10.419 |
| wellsfargo |       12.151 |
| instagram  |        4.115 |
| instagrame |       -0.078 |
| microsoft  |        8.591 |

Most brand substrings push toward phishing (positive sum), both in clean and leetspeak form (`paypal`/`paypa1`, `amazon`/`amaz0n`) — so yes, the n-gram model already captures a version of brand-impersonation signal implicitly, purely from substring frequency, with no brand list at all. `google`/`g00gle` are the exception (negative sum): google.com's own legitimate traffic is common enough in this dataset that the substring reads as *more* legitimate than phishing on balance, which is exactly the failure mode the engineered features avoid — `is_exact_brand_match` separates "is the real google.com" from "looks like google" by construction, while the n-gram model can only learn one weight per substring regardless of which case it's in.

## Caveats

- Same as `model_report.md`: the test split comes from the same four overlapping sources as train, so expect lower scores on URLs from a new source.
- Lowercasing and stripping the scheme remove only some source-formatting shortcuts. Others remain and the n-grams can see them directly: e.g. every phiusiil legitimate URL is a bare `www.<domain>` with no path, and no semihguner URL starts with `www.`.
