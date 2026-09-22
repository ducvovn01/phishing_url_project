# Model Report - Phishing URL Detector

Feature table: `data/processed/features.parquet` (from `scripts/extract_features.py`)

## Summary of findings

- Train/test split is by registrable domain: 1275007 train rows (653644 domains) vs 332769 test rows (163412 domains), with no domain on both sides. Phishing share: 50.80% train, 54.03% test.
- LightGBM (test): ROC-AUC 0.9077, PR-AUC 0.9330, F1 0.8352 (precision 0.8862, recall 0.7897) at threshold 0.5. At a 1% false-positive rate it catches 55.25% of phishing URLs.
- LightGBM accuracy 0.8316, balanced accuracy 0.8353, specificity 0.8808, MCC 0.6688; macro F1 over both classes 0.8315.
- Logistic Regression baseline (test): ROC-AUC 0.8145, PR-AUC 0.8675, F1 0.7413, recall at 1% FPR 37.56%.
- Probability error (test, lower is better): LightGBM MAE 0.2160, RMSE 0.3498, log loss 0.3888; Logistic Regression MAE 0.3195, RMSE 0.4190, log loss 0.5204.
- At threshold 0.5, LightGBM misses 37803 of 179786 phishing URLs and flags 18236 of 152983 legitimate URLs (11.92%).
- Weakest source for LightGBM by F1: mitake (F1 0.7509). Per-source scores are not directly comparable: each source has a very different phishing share.
- Ablation: adding `has_protocol`/`uses_https` back moves test ROC-AUC from 0.9077 to 0.9320 and recall at 1% FPR from 55.25% to 60.01%. Those flags mostly record how each source formatted its URLs, so any gain from them would not carry over to real traffic. They are left out of the saved models.
- Top features by split gain: `tld` (37.4%), `path_length` (10.2%), `brand_similarity_score` (8.2%), `suspicious_keyword_count` (6.6%), `hostname_entropy` (6.4%).
- Brand-similarity features (FR3, added over the original 21): `brand_similarity_score` ranks 3 of 23 by split gain (8.24%) — just behind `tld` and `path_length`, ahead of every lexical count feature. `is_exact_brand_match` ranks 17 (0.66%): most of its signal is already implied by a high `brand_similarity_score`, so it adds little on top of the continuous score.

## Setup

- Split: `GroupShuffleSplit` on `domain`, test size 0.2, random_state 42.
- Features (23): `url_length`, `hostname_length`, `path_length`, `query_length`, `dot_count`, `hyphen_count`, `digit_count`, `at_count`, `underscore_count`, `percent_count`, `equals_count`, `ampersand_count`, `digit_ratio`, `subdomain_count`, `path_depth`, `is_ip_hostname`, `has_port`, `has_punycode`, `suspicious_keyword_count`, `tld`, `hostname_entropy`, `brand_similarity_score`, `is_exact_brand_match`.
- Not used as features: `url` (identifier), `label` (target), `domain` (grouping key), `source` (provenance; a shortcut to the label), `has_protocol` and `uses_https` (source-formatting artifacts - see ablation), `matched_brand` (string, which brand won the fuzzy match - kept for the A2 report's misclassification analysis, not a model input; `brand_similarity_score`/`is_exact_brand_match` are its model-facing summary).
- `tld` is categorical. TLDs seen fewer than 100 times in train are pooled into `(other)`, and a missing suffix is `(none)` (250 categories in total).
- Logistic Regression: log1p + standard scaling on numeric features, one-hot `tld`.
- LightGBM: learning rate 0.1, row/column subsampling 0.8. The grid below was scored by 3-fold `GroupKFold` on the train split (grouped by `domain`), with early stopping after 50 rounds. The final model was refit on all of train with the best config and its mean best iteration.

## LightGBM tuning (CV on train split)

|   num_leaves |   min_child_samples |   cv_pr_auc_mean |   cv_pr_auc_std |   best_iteration_mean |
|-------------:|--------------------:|-----------------:|----------------:|----------------------:|
|           31 |                  20 |           0.9342 |          0.0126 |                   337 |
|          127 |                  50 |           0.9378 |          0.0116 |                   175 |
|          255 |                 100 |           0.9338 |          0.0185 |                   144 |

Selected: {'num_leaves': 127, 'min_child_samples': 50, 'n_estimators': 175}

## Test results

Threshold-based metrics use threshold 0.5. `recall_at_1pct_fpr` is the share of phishing URLs caught when 1% of legitimate URLs are flagged. `precision`, `recall` and `f1` are for the phishing class; `specificity` is the recall of the legitimate class, `balanced_accuracy` the mean of the two recalls, and `mcc` the Matthews correlation (-1 to 1, 0 = chance). `mae`, `mse_brier`, `rmse` and `log_loss` compare the predicted phishing probability with the 0/1 label (lower is better); `mse_brier` is the Brier score and `rmse` its square root.

|                                                 |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |    mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:------------------------------------------------|------------:|---------:|-------:|-----------:|--------------:|--------------------:|-------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| LightGBM                                        |      0.8862 |   0.7897 | 0.8352 |     0.8316 |        0.8808 |              0.8353 | 0.6688 | 0.2160 |      0.1224 | 0.3498 |     0.3888 |    0.9077 |   0.9330 |               0.5525 |
| Logistic Regression                             |      0.8238 |   0.6739 | 0.7413 |     0.7459 |        0.8306 |              0.7522 | 0.5062 | 0.3195 |      0.1756 | 0.4190 |     0.5204 |    0.8145 |   0.8675 |               0.3756 |
| LightGBM + protocol flags (ablation, not saved) |      0.8949 |   0.8180 | 0.8547 |     0.8498 |        0.8871 |              0.8525 | 0.7028 | 0.1886 |      0.1079 | 0.3285 |     0.3388 |    0.9320 |   0.9486 |               0.6001 |

## LightGBM precision, recall and F1 by class (test split)

|              |   precision |   recall |     f1 |     support |
|:-------------|------------:|---------:|-------:|------------:|
| legitimate   |      0.7809 |   0.8808 | 0.8279 | 152983.0000 |
| phishing     |      0.8862 |   0.7897 | 0.8352 | 179786.0000 |
| macro avg    |      0.8335 |   0.8353 | 0.8315 | 332769.0000 |
| weighted avg |      0.8378 |   0.8316 | 0.8318 | 332769.0000 |

## LightGBM results by source (test split)

| source        |        rows |   phishing_share |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |    mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------|------------:|-----------------:|------------:|---------:|-------:|-----------:|--------------:|--------------------:|-------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| harisudhan411 |  47605.0000 |           0.8547 |      0.9593 |   0.7450 | 0.8387 |     0.7550 |        0.8140 |              0.7795 | 0.4171 | 0.2679 |      0.1612 | 0.4015 |     0.4909 |    0.8787 |   0.9753 |               0.4025 |
| mitake        | 173555.0000 |           0.3181 |      0.7303 |   0.7727 | 0.7509 |     0.8369 |        0.8669 |              0.8198 | 0.6304 | 0.2133 |      0.1232 | 0.3510 |     0.4005 |    0.8820 |   0.8574 |               0.5888 |
| phiusiil      |  40942.0000 |           0.3418 |      0.8947 |   0.6536 | 0.7554 |     0.8553 |        0.9601 |              0.8068 | 0.6725 | 0.2311 |      0.1138 | 0.3373 |     0.3711 |    0.8717 |   0.8516 |               0.5397 |
| semihguner    |  70667.0000 |           0.9891 |      0.9980 |   0.8565 | 0.9218 |     0.8564 |        0.8462 |              0.8513 | 0.2032 | 0.1789 |      0.0990 | 0.3147 |     0.3017 |    0.9190 |   0.9990 |               0.5175 |

## LightGBM confusion matrix (test split)

|                   |   predicted legitimate |   predicted phishing |
|:------------------|-----------------------:|---------------------:|
| actual legitimate |                 134747 |                18236 |
| actual phishing   |                  37803 |               141983 |

## LightGBM feature importance

|                          |   gain_share_pct |
|:-------------------------|-----------------:|
| tld                      |            37.44 |
| path_length              |            10.17 |
| brand_similarity_score   |             8.24 |
| suspicious_keyword_count |             6.60 |
| hostname_entropy         |             6.40 |
| hyphen_count             |             4.79 |
| digit_ratio              |             3.98 |
| url_length               |             3.40 |
| digit_count              |             3.11 |
| dot_count                |             3.04 |
| path_depth               |             2.80 |
| hostname_length          |             2.66 |
| subdomain_count          |             2.56 |
| underscore_count         |             1.12 |
| query_length             |             1.10 |
| percent_count            |             0.75 |
| is_exact_brand_match     |             0.66 |
| equals_count             |             0.60 |
| at_count                 |             0.34 |
| ampersand_count          |             0.20 |
| has_punycode             |             0.03 |
| has_port                 |             0.02 |
| is_ip_hostname           |             0.00 |

## Plots

![ROC and precision-recall curves](plots/model_roc_pr_curves.png)

![Confusion matrix](plots/model_confusion_matrix.png)

![Feature importance](plots/model_feature_importance.png)

## Caveats

- The four sources overlap and are not independent samples (see `eda_report.md`). Grouping by domain stops the same site from appearing on both sides of the split, but the test split still comes from the same sources as train. Expect lower scores on URLs from a new source.
- Hosting and dynamic-DNS domains (e.g. `blogspot.com`, `duckdns.org`) are one group each, so all of their subdomains fall on the same side of the split.
- `brand_similarity_score` (`rapidfuzz.fuzz.ratio`) is a normalized edit distance, which is noisy on short domain labels: a 3-4 character label needs only a one- or two-character difference from some brand in the list to score >=0.85 by chance (e.g. `fida.com` scores 0.857 against `fda`), independent of any real typosquat intent. Longer look-alike labels (`instagrame.net` vs `instagram`, `tercent.tk` vs `tencent`) score high for the right reason. Because of this the dataset-wide mean score is *higher* for legitimate rows than phishing rows (0.675 vs 0.600) — driven by legitimate rows that are literally a brand's own domain (`is_exact_brand_match=True`, 16.6% of legitimate rows vs 7.2% of phishing rows) — so read the two features together, not `brand_similarity_score` alone, when explaining a prediction.
- Threshold 0.5 was not tuned. Pick the operating point from the ROC curve based on how many false alarms are acceptable.
