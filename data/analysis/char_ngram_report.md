# Char N-gram Report - Phishing URL Detector

Source: `scripts/train_char_ngram.py`. Compared with the models from `scripts/train_model.py` on the same test split.

## Summary of findings

- Char n-gram + Logistic Regression (test): ROC-AUC 0.9674, PR-AUC 0.9742, F1 0.9133 (precision 0.9149, recall 0.9117) at threshold 0.5. At a 1% false-positive rate it catches 66.81% of phishing URLs.
- LightGBM on the same rows: ROC-AUC 0.9038, PR-AUC 0.9276, F1 0.8250, recall at 1% FPR 50.62%.
- Logistic Regression on the 21 URL features: ROC-AUC 0.8155, PR-AUC 0.8659, F1 0.7365. Same classifier as the n-gram model, so the gap between the two is down to the input representation.
- At threshold 0.5, the n-gram model misses 15873 of 179786 phishing URLs and flags 15241 of 152983 legitimate URLs (9.96%).

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

Threshold-based metrics use threshold 0.5. `recall_at_1pct_fpr` is the share of phishing URLs caught when 1% of legitimate URLs are flagged.

|                                                   |   precision |   recall |     f1 |   accuracy |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------------------------------------------|------------:|---------:|-------:|-----------:|----------:|---------:|---------------------:|
| Char n-gram + Logistic Regression                 |      0.9149 |   0.9117 | 0.9133 |     0.9065 |    0.9674 |   0.9742 |               0.6681 |
| LightGBM (saved model)                            |      0.8628 |   0.7904 | 0.8250 |     0.8189 |    0.9038 |   0.9276 |               0.5062 |
| Logistic Regression on URL features (saved model) |      0.8257 |   0.6647 | 0.7365 |     0.7430 |    0.8155 |   0.8659 |               0.3721 |

## Char n-gram results by source (test split)

| source        |        rows |   phishing_share |   precision |   recall |     f1 |   accuracy |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------|------------:|-----------------:|------------:|---------:|-------:|-----------:|----------:|---------:|---------------------:|
| harisudhan411 |  47605.0000 |           0.8547 |      0.9834 |   0.8394 | 0.9057 |     0.8507 |    0.9540 |   0.9906 |               0.4364 |
| mitake        | 173555.0000 |           0.3181 |      0.8079 |   0.9534 | 0.8747 |     0.9131 |    0.9795 |   0.9626 |               0.7148 |
| phiusiil      |  40942.0000 |           0.3418 |      0.8324 |   0.7246 | 0.7748 |     0.8560 |    0.8972 |   0.8749 |               0.5685 |
| semihguner    |  70667.0000 |           0.9891 |      0.9983 |   0.9583 | 0.9779 |     0.9572 |    0.9777 |   0.9997 |               0.7905 |

## Char n-gram confusion matrix (test split)

|                   |   predicted legitimate |   predicted phishing |
|:------------------|-----------------------:|---------------------:|
| actual legitimate |                 137742 |                15241 |
| actual phishing   |                  15873 |               163913 |

## Strongest n-grams

Largest positive (phishing) and negative (legitimate) weights among n-grams seen in at least 200 of 300,000 sampled train URLs. Weights are per hashed column, so a column shared by two n-grams shows their combined weight.

| direction   | ngram   |   weight |
|:------------|:--------|---------:|
| phishing    | `.top`  |   48.821 |
| phishing    | `.jp.`  |   33.415 |
| phishing    | `ww.`   |   30.404 |
| phishing    | `o.jp.` |   25.461 |
| phishing    | `.tk`   |   24.796 |
| phishing    | `jp.`   |   23.854 |
| phishing    | `.cn/`  |   22.376 |
| phishing    | `.io/`  |   21.924 |
| phishing    | `.gq`   |   21.769 |
| phishing    | `.ml`   |   21.649 |
| phishing    | `.com.` |   19.540 |
| phishing    | `hgs`   |   19.258 |
| phishing    | `cn/`   |   19.162 |
| phishing    | `.cf`   |   18.864 |
| phishing    | `.php`  |   18.665 |
| legitimate  | `www.`  |  -37.400 |
| legitimate  | `.co`   |  -32.597 |
| legitimate  | `www`   |  -31.895 |
| legitimate  | `.de`   |  -29.827 |
| legitimate  | `.jp`   |  -29.710 |
| legitimate  | `.cfm`  |  -29.071 |
| legitimate  | `.gov`  |  -27.601 |
| legitimate  | `.io`   |  -24.943 |
| legitimate  | `.pdf`  |  -22.269 |
| legitimate  | `.fr`   |  -21.686 |
| legitimate  | `.pd`   |  -21.567 |
| legitimate  | `.edu`  |  -21.559 |
| legitimate  | `.nl`   |  -21.493 |
| legitimate  | `htm`   |  -21.319 |
| legitimate  | `.ca`   |  -21.278 |

## Caveats

- Same as `model_report.md`: the test split comes from the same four overlapping sources as train, so expect lower scores on URLs from a new source.
- Lowercasing and stripping the scheme remove only some source-formatting shortcuts. Others remain and the n-grams can see them directly: e.g. every phiusiil legitimate URL is a bare `www.<domain>` with no path, and no semihguner URL starts with `www.`.
