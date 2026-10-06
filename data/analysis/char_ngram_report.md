# Char N-gram Report - Phishing URL Detector

Source: `scripts/train_char_ngram.py`. Compared with the models from `scripts/train_model.py` on the same test split.

## Summary of findings

- Char n-gram + Logistic Regression (test): ROC-AUC 0.9746, PR-AUC 0.9796, F1 0.9242 (precision 0.9338, recall 0.9147) at threshold 0.5. At a 1% false-positive rate it catches 71.00% of phishing URLs.
- Char n-gram accuracy 0.9189, balanced accuracy 0.9192, specificity 0.9238, MCC 0.8372; macro F1 over both classes 0.9185.
- LightGBM on the same rows: ROC-AUC 0.9077, PR-AUC 0.9330, F1 0.8352, recall at 1% FPR 55.25%.
- Logistic Regression on the 21 URL features: ROC-AUC 0.8145, PR-AUC 0.8675, F1 0.7413. Same classifier as the n-gram model, so the gap between the two is down to the input representation.
- Probability error (test, lower is better): char n-gram MAE 0.1189, RMSE 0.2459, log loss 0.2029; LightGBM MAE 0.2160, RMSE 0.3498, log loss 0.3888; Logistic Regression MAE 0.3195, RMSE 0.4190, log loss 0.5204.
- At threshold 0.5, the n-gram model misses 15338 of 179786 phishing URLs and flags 11656 of 152983 legitimate URLs (7.62%).
- Brand masking: of the 19285.0 legitimate test URLs on official brand domains, the model flags 0.50%, against 16.10% for the same model without the mask. Over the whole test split the mask moves PR-AUC from 0.9757 to 0.9796, F1 from 0.9160 to 0.9242 and the false-positive rate from 9.55% to 7.62%.

## Setup

- Test split: `split_by_domain()` from `train_model.py` (same rows as `model_report.md`).
- Input: URL with the scheme stripped and lowercased. Scheme and letter case mostly record how each source formatted its URLs (phiusiil has no uppercase at all), so they are removed.
- Brand mask: when the registrable domain is one of 64 official brand domains (`OFFICIAL_BRAND_DOMAINS` in `extract_features.py`, drawn up from public brand-phishing rankings), its brand label is replaced by `§`: `docs.google.com/forms/x` becomes `docs.§.com/forms/x`. The brand name anywhere else (`facebook.com.evil.tk`, `singin-facebook.com`, a path) is left as is.
- Features: every 3-5 character substring, hashed into 1,048,576 columns (`HashingVectorizer`), then TF-IDF with sublinear term frequency.
- Classifier: `LogisticRegression(solver="liblinear")` with L2 penalty.
- `C` (inverse regularization strength) was picked from [1.0, 3.0, 10.0, 30.0] by PR-AUC on a domain-grouped validation split of train (1136013 fit / 138994 validation rows). The final model was refit on all of train.

## Tuning (validation split of train)

|       C |   val_pr_auc |
|--------:|-------------:|
|  1.0000 |       0.9731 |
|  3.0000 |       0.9760 |
| 10.0000 |       0.9772 |
| 30.0000 |       0.9765 |

Selected: C=10.0

## Test results

Threshold-based metrics use threshold 0.5. `recall_at_1pct_fpr` is the share of phishing URLs caught when 1% of legitimate URLs are flagged. `precision`, `recall` and `f1` are for the phishing class; `specificity` is the recall of the legitimate class, `balanced_accuracy` the mean of the two recalls, and `mcc` the Matthews correlation (-1 to 1, 0 = chance). `mae`, `mse_brier`, `rmse` and `log_loss` compare the predicted phishing probability with the 0/1 label (lower is better); `mse_brier` is the Brier score and `rmse` its square root.

|                                                         |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |    mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------------------------------------------------|------------:|---------:|-------:|-----------:|--------------:|--------------------:|-------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| Char n-gram + Logistic Regression                       |      0.9338 |   0.9147 | 0.9242 |     0.9189 |        0.9238 |              0.9192 | 0.8372 | 0.1189 |      0.0604 | 0.2459 |     0.2029 |    0.9746 |   0.9796 |               0.7100 |
| Char n-gram without brand masking (ablation, not saved) |      0.9183 |   0.9137 | 0.9160 |     0.9095 |        0.9045 |              0.9091 | 0.8179 | 0.1298 |      0.0670 | 0.2588 |     0.2232 |    0.9693 |   0.9757 |               0.6794 |
| LightGBM (saved model)                                  |      0.8862 |   0.7897 | 0.8352 |     0.8316 |        0.8808 |              0.8353 | 0.6688 | 0.2160 |      0.1224 | 0.3498 |     0.3888 |    0.9077 |   0.9330 |               0.5525 |
| Logistic Regression on URL features (saved model)       |      0.8238 |   0.6739 | 0.7413 |     0.7459 |        0.8306 |              0.7522 | 0.5062 | 0.3195 |      0.1756 | 0.4190 |     0.5204 |    0.8145 |   0.8675 |               0.3756 |

## Brand masking (test split)

Share of legitimate URLs flagged as phishing, on the official brand domains with the most legitimate test rows and over all of them. The domain-grouped split put every `facebook.com` and `netflix.com` row in test, so without the mask the model knows these brands only from train URLs that impersonate them. With the mask it can apply what it learned from official domains that are in train (`amazon.com`, `microsoft.com`, `yahoo.com`...).

| domain                 |   legit_rows |   Char n-gram + Logistic Regression |   Char n-gram without brand masking (ablation, not saved) |   LightGBM (saved model) |   Logistic Regression on URL features (saved model) |
|:-----------------------|-------------:|------------------------------------:|----------------------------------------------------------:|-------------------------:|----------------------------------------------------:|
| youtube.com            |         9078 |                              0.0012 |                                                    0.0051 |                   0.0013 |                                              0      |
| facebook.com           |         8739 |                              0.0061 |                                                    0.331  |                   0.0078 |                                              0.0008 |
| ebay.com               |         1134 |                              0.0265 |                                                    0.0811 |                   0.0062 |                                              0      |
| netflix.com            |          168 |                              0.006  |                                                    0.1071 |                   0.0536 |                                              0      |
| alibaba.com            |           99 |                              0.0101 |                                                    0.303  |                   0.0303 |                                              0      |
| bankofamerica.com      |           25 |                              0      |                                                    0.44   |                   0.32   |                                              0.24   |
| spotify.com            |           18 |                              0.0556 |                                                    0.1111 |                   0.1667 |                                              0.1111 |
| aliexpress.com         |           15 |                              0      |                                                    0.2    |                   0.0667 |                                              0      |
| coinbase.com           |            9 |                              0      |                                                    1      |                   0.1111 |                                              0      |
| (all official domains) |        19285 |                              0.005  |                                                    0.161  |                   0.0058 |                                              0.0008 |

## Char n-gram precision, recall and F1 by class (test split)

|              |   precision |   recall |     f1 |     support |
|:-------------|------------:|---------:|-------:|------------:|
| legitimate   |      0.9021 |   0.9238 | 0.9128 | 152983.0000 |
| phishing     |      0.9338 |   0.9147 | 0.9242 | 179786.0000 |
| macro avg    |      0.9180 |   0.9192 | 0.9185 | 332769.0000 |
| weighted avg |      0.9192 |   0.9189 | 0.9189 | 332769.0000 |

## Char n-gram results by source (test split)

| source        |        rows |   phishing_share |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |    mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------|------------:|-----------------:|------------:|---------:|-------:|-----------:|--------------:|--------------------:|-------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| harisudhan411 |  47605.0000 |           0.8547 |      0.9880 |   0.8464 | 0.9117 |     0.8599 |        0.9397 |              0.8930 | 0.6256 | 0.1891 |      0.1005 | 0.3170 |     0.3212 |    0.9665 |   0.9931 |               0.4657 |
| mitake        | 173555.0000 |           0.3181 |      0.8463 |   0.9561 | 0.8979 |     0.9308 |        0.9190 |              0.9376 | 0.8495 | 0.1069 |      0.0522 | 0.2284 |     0.1791 |    0.9848 |   0.9712 |               0.7595 |
| phiusiil      |  40942.0000 |           0.3418 |      0.8669 |   0.7203 | 0.7868 |     0.8666 |        0.9426 |              0.8314 | 0.6972 | 0.1858 |      0.1011 | 0.3180 |     0.3388 |    0.9051 |   0.8848 |               0.5974 |
| semihguner    |  70667.0000 |           0.9891 |      0.9984 |   0.9607 | 0.9792 |     0.9596 |        0.8592 |              0.9099 | 0.3964 | 0.0622 |      0.0302 | 0.1737 |     0.1029 |    0.9797 |   0.9998 |               0.8003 |

## Char n-gram confusion matrix (test split)

|                   |   predicted legitimate |   predicted phishing |
|:------------------|-----------------------:|---------------------:|
| actual legitimate |                 141327 |                11656 |
| actual phishing   |                  15338 |               164448 |

## Strongest n-grams

Largest positive (phishing) and negative (legitimate) weights among n-grams seen in at least 200 of 300,000 sampled train URLs. Weights are per hashed column, so a column shared by two n-grams shows their combined weight.

| direction   | ngram   |   weight |
|:------------|:--------|---------:|
| phishing    | `.top`  |   37.061 |
| phishing    | `.jp.`  |   24.396 |
| phishing    | `ww.`   |   22.592 |
| phishing    | `jp.`   |   20.034 |
| phishing    | `.tk`   |   19.010 |
| phishing    | `.cn/`  |   18.269 |
| phishing    | `o.jp.` |   18.166 |
| phishing    | `.ml`   |   17.639 |
| phishing    | `.io/`  |   17.218 |
| phishing    | `.gq`   |   17.106 |
| phishing    | `cn/`   |   16.395 |
| phishing    | `.cf`   |   15.408 |
| phishing    | `hgs`   |   15.333 |
| phishing    | `.exe`  |   14.392 |
| phishing    | `.php`  |   14.151 |
| legitimate  | `www.`  |  -29.397 |
| legitimate  | `www`   |  -25.652 |
| legitimate  | `.de`   |  -24.217 |
| legitimate  | `.co`   |  -24.125 |
| legitimate  | `.jp`   |  -22.849 |
| legitimate  | `.cfm`  |  -21.389 |
| legitimate  | `.gov`  |  -21.127 |
| legitimate  | `.io`   |  -20.511 |
| legitimate  | `.edu`  |  -17.679 |
| legitimate  | `.nl`   |  -17.594 |
| legitimate  | `.ca`   |  -17.177 |
| legitimate  | `.pdf`  |  -17.166 |
| legitimate  | `.fr`   |  -17.097 |
| legitimate  | `htm`   |  -16.756 |
| legitimate  | `.org`  |  -16.647 |

## Brand-substring signal (vs. the FR3 brand-similarity features)

`scripts/extract_features.py` now computes `brand_similarity_score` and `is_exact_brand_match` against a curated brand list (see `model_report.md`) for the LightGBM/Logistic Regression models. The char n-gram model gets no such list — it only ever sees 3-5 character substrings of the raw URL — so the question is whether it already learns brand-name substrings as a signal on its own. Summing the model's learned weight over every 3-5 character n-gram in a brand name (both the clean spelling and a leetspeak typo) answers this directly:

| word       |   sum_weight |
|:-----------|-------------:|
| paypal     |       44.095 |
| paypa1     |       35.157 |
| amazon     |       15.937 |
| amaz0n     |       17.007 |
| google     |       -3.896 |
| g00gle     |       -3.244 |
| apple      |        7.663 |
| appleid    |       14.301 |
| facebook   |       15.255 |
| faceb00k   |       13.860 |
| netflix    |       12.064 |
| chase      |        9.567 |
| wellsfargo |       19.554 |
| instagram  |        6.951 |
| instagrame |        3.359 |
| microsoft  |       11.542 |

Most brand substrings push toward phishing (positive sum), both in clean and leetspeak form (`paypal`/`paypa1`, `amazon`/`amaz0n`) — so yes, the n-gram model already captures a version of brand-impersonation signal implicitly, purely from substring frequency, with no brand list at all. `google`/`g00gle` are the exception (negative sum): google.com's own legitimate traffic is common enough in this dataset that the substring reads as *more* legitimate than phishing on balance, which is exactly the failure mode the engineered features avoid — `is_exact_brand_match` separates "is the real google.com" from "looks like google" by construction, while the n-gram model can only learn one weight per substring regardless of which case it's in.

## Caveats

- Same as `model_report.md`: the test split comes from the same four overlapping sources as train, so expect lower scores on URLs from a new source.
- Lowercasing and stripping the scheme remove only some source-formatting shortcuts. Others remain and the n-grams can see them directly: e.g. every phiusiil legitimate URL is a bare `www.<domain>` with no path, and no semihguner URL starts with `www.`.
- The brand mask only covers the brands on its list. A brand that is not on it, and whose own domain is not in train, is still known only from URLs impersonating it.
- The mask does not whitelist anything: a phishing page hosted on an official domain (`docs.google.com/forms/...`, `sites.google.com/...`) is still scored from its subdomain and path.
