# Char-CNN Report - Phishing URL Detector

Source: `scripts/train_char_cnn.py`. Compared with the LightGBM model from `scripts/train_model.py` on the same test split.

## Summary of findings

- Char-CNN (test): ROC-AUC 0.9738, PR-AUC 0.9791, F1 0.9211 (precision 0.9222, recall 0.9200) at threshold 0.5. At a 1% false-positive rate it catches 73.37% of phishing URLs.
- LightGBM on the same rows: ROC-AUC 0.9038, PR-AUC 0.9276, F1 0.8250, recall at 1% FPR 50.62%.
- At threshold 0.5, Char-CNN misses 14384 of 179786 phishing URLs and flags 13962 of 152983 legitimate URLs (9.13%).
- Best epoch: 3 of 5 (validation PR-AUC 0.9799).

## Setup

- Test split: `split_by_domain()` from `train_model.py` (same rows as `model_report.md`).
- Early stopping: 10% of train domains held out (`GroupShuffleSplit`, random_state 42); training stops after 2 epochs without a validation PR-AUC gain (max 8), and the best epoch is kept.
- Input: URL with the scheme stripped, lowercased, cut to 200 characters. Scheme and letter case mostly record how each source formatted its URLs (phiusiil has no uppercase at all), so they are removed.
- Tokens: printable ASCII characters, one id each; any other byte shares one id (97 ids with padding).
- Model: embedding 32 -> Conv1d with kernel sizes [3, 4, 5, 6] (128 filters each) -> global max pool -> dense 256 -> 1 logit; dropout 0.3. 208,929 parameters.
- Training: AdamW (lr 0.001, weight decay 0.0001), batch 1024, binary cross-entropy, mixed precision on GPU (cuda).

## Training history

|   epoch |   train_loss |   val_pr_auc |
|--------:|-------------:|-------------:|
|  1.0000 |       0.2967 |       0.9752 |
|  2.0000 |       0.2035 |       0.9778 |
|  3.0000 |       0.1859 |       0.9799 |
|  4.0000 |       0.1766 |       0.9780 |
|  5.0000 |       0.1705 |       0.9798 |

## Test results

Threshold-based metrics use threshold 0.5. `recall_at_1pct_fpr` is the share of phishing URLs caught when 1% of legitimate URLs are flagged.

|                        |   precision |   recall |     f1 |   accuracy |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:-----------------------|------------:|---------:|-------:|-----------:|----------:|---------:|---------------------:|
| Char-CNN               |      0.9222 |   0.9200 | 0.9211 |     0.9148 |    0.9738 |   0.9791 |               0.7337 |
| LightGBM (saved model) |      0.8628 |   0.7904 | 0.8250 |     0.8189 |    0.9038 |   0.9276 |               0.5062 |

## Char-CNN results by source (test split)

| source        |        rows |   phishing_share |   precision |   recall |     f1 |   accuracy |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:--------------|------------:|-----------------:|------------:|---------:|-------:|-----------:|----------:|---------:|---------------------:|
| harisudhan411 |  47605.0000 |           0.8547 |      0.9823 |   0.8823 | 0.9296 |     0.8858 |    0.9688 |   0.9936 |               0.5769 |
| mitake        | 173555.0000 |           0.3181 |      0.8088 |   0.9528 | 0.8749 |     0.9134 |    0.9799 |   0.9660 |               0.7695 |
| phiusiil      |  40942.0000 |           0.3418 |      0.9271 |   0.7005 | 0.7980 |     0.8788 |    0.9071 |   0.8916 |               0.6451 |
| semihguner    |  70667.0000 |           0.9891 |      0.9983 |   0.9600 | 0.9788 |     0.9588 |    0.9798 |   0.9998 |               0.8287 |

## Char-CNN confusion matrix (test split)

|                   |   predicted legitimate |   predicted phishing |
|:------------------|-----------------------:|---------------------:|
| actual legitimate |                 139021 |                13962 |
| actual phishing   |                  14384 |               165402 |

## Caveats

- Same as `model_report.md`: the test split comes from the same four overlapping sources as train, so expect lower scores on URLs from a new source.
- Lowercasing and stripping the scheme remove the source-formatting shortcuts we know about. The CNN can still pick up others (e.g. how a source encodes paths) that the hand-made features never saw.
- One training run with one seed; small score differences between models may not hold across seeds.
