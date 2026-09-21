# Clustering Report - Phishing URL Detector

Source: `scripts/clustering_model.py`. Same test split as `model_report.md`.

## Summary of findings

- K-Means (K=100) as a classifier (test): ROC-AUC 0.7854, PR-AUC 0.8246, F1 0.7164 (precision 0.7439, recall 0.6908), accuracy 0.7045, MCC 0.4100, RMSE 0.4318.
- HDBSCAN (min_cluster_size=50) as a classifier (test): ROC-AUC 0.7671, PR-AUC 0.7869, F1 0.7394 (precision 0.6974, recall 0.7869), accuracy 0.7004, MCC 0.3939, RMSE 0.4413. 28.0% of test URLs land in its noise group.
- Agreement with the label: K-Means ARI 0.0088, NMI 0.0765, purity 0.7309; HDBSCAN ARI 0.0118, NMI 0.0654, purity 0.7037.
- Cluster geometry: K-Means silhouette 0.2243, Davies-Bouldin 1.4961; HDBSCAN silhouette 0.0824, Davies-Bouldin 1.7409 (non-noise rows).
- For reference, the supervised LightGBM on the same rows: ROC-AUC 0.9038, PR-AUC 0.9276, F1 0.8250.

## Setup

- Features (20): `url_length`, `hostname_length`, `path_length`, `query_length`, `dot_count`, `hyphen_count`, `digit_count`, `at_count`, `underscore_count`, `percent_count`, `equals_count`, `ampersand_count`, `digit_ratio`, `subdomain_count`, `path_depth`, `is_ip_hostname`, `has_port`, `has_punycode`, `suspicious_keyword_count`, `hostname_entropy`. log1p then standard scaling, fitted on train. `tld` and the protocol flags are not used.
- K-Means: `MiniBatchKMeans`, fitted on all 1275007 train rows.
- HDBSCAN: fitted on 30000 randomly sampled train rows (min_samples 10). Any other URL takes the cluster of its nearest sampled row, noise included. Noise is kept as a group of its own.
- The label is not used to form clusters. It is only used afterwards: a URL's phishing probability is its cluster's phishing share in train (shrunk toward the overall share 0.5080 with weight 10 rows).
- K and min_cluster_size were picked by PR-AUC on a domain-grouped validation split of train (1136013 fit / 138994 validation rows).

## Tuning (validation split of train)

### K-Means

|   k |   clusters |   noise_share |   val_pr_auc |
|----:|-----------:|--------------:|-------------:|
|   2 |          2 |             0 |       0.581  |
|   5 |          5 |             0 |       0.6492 |
|  10 |         10 |             0 |       0.707  |
|  20 |         20 |             0 |       0.7666 |
|  50 |         50 |             0 |       0.8068 |
| 100 |        100 |             0 |       0.8308 |

Selected: K=100

### HDBSCAN

|   min_cluster_size |   clusters |   noise_share |   val_pr_auc |
|-------------------:|-----------:|--------------:|-------------:|
|                 25 |        218 |        0.2868 |       0.787  |
|                 50 |        115 |        0.2453 |       0.8051 |
|                100 |         59 |        0.2298 |       0.8051 |

Selected: min_cluster_size=50

## Test results: clusters as classifiers

Same metrics as `model_report.md`. Threshold-based metrics use threshold 0.5; `precision`, `recall` and `f1` are for the phishing class. `mae`, `mse_brier`, `rmse` and `log_loss` compare the cluster's phishing share with the 0/1 label (lower is better).

|                                   |   precision |   recall |     f1 |   accuracy |   specificity |   balanced_accuracy |    mcc |    mae |   mse_brier |   rmse |   log_loss |   roc_auc |   pr_auc |   recall_at_1pct_fpr |
|:----------------------------------|------------:|---------:|-------:|-----------:|--------------:|--------------------:|-------:|-------:|------------:|-------:|-----------:|----------:|---------:|---------------------:|
| K-Means                           |      0.7439 |   0.6908 | 0.7164 |     0.7045 |        0.7205 |              0.7057 | 0.4100 | 0.3621 |      0.1864 | 0.4318 |     0.5395 |    0.7854 |   0.8246 |               0.2466 |
| HDBSCAN                           |      0.6974 |   0.7869 | 0.7394 |     0.7004 |        0.5987 |              0.6928 | 0.3939 | 0.3914 |      0.1948 | 0.4413 |     0.5694 |    0.7671 |   0.7869 |               0.1712 |
| LightGBM (saved model, reference) |      0.8628 |   0.7904 | 0.8250 |     0.8189 |        0.8523 |              0.8213 | 0.6406 | 0.2327 |      0.1260 | 0.3549 |     0.3826 |    0.9038 |   0.9276 |               0.5062 |

## Test results: clustering scores

External scores compare the clusters with the label (1 = clusters match the classes perfectly; ARI 0 = chance). `homogeneity` is high when each cluster holds one class, `completeness` when each class sits in one cluster, `v_measure` is their harmonic mean, `purity` the share of URLs in their cluster's majority class. Internal scores ignore the label: `silhouette` (-1 to 1, higher = tighter, better separated clusters), `davies_bouldin` (lower is better), `calinski_harabasz` (higher is better). Internal scores leave HDBSCAN's noise out; `silhouette` uses 10000 sampled rows.

|         |   clusters |   noise_share |    ari |    nmi |   homogeneity |   completeness |   v_measure |   purity |   silhouette |   davies_bouldin |   calinski_harabasz |
|:--------|-----------:|--------------:|-------:|-------:|--------------:|---------------:|------------:|---------:|-------------:|-----------------:|--------------------:|
| K-Means |   100.0000 |        0.0000 | 0.0088 | 0.0765 |        0.2670 |         0.0447 |      0.0765 |   0.7309 |       0.2243 |           1.4961 |          22610.6836 |
| HDBSCAN |   114.0000 |        0.2803 | 0.0118 | 0.0654 |        0.2041 |         0.0389 |      0.0654 |   0.7037 |       0.0824 |           1.7409 |          10497.2442 |

## K-Means precision, recall and F1 by class (test split)

|              |   precision |   recall |     f1 |     support |
|:-------------|------------:|---------:|-------:|------------:|
| legitimate   |      0.6648 |   0.7205 | 0.6915 | 152983.0000 |
| phishing     |      0.7439 |   0.6908 | 0.7164 | 179786.0000 |
| macro avg    |      0.7043 |   0.7057 | 0.7040 | 332769.0000 |
| weighted avg |      0.7075 |   0.7045 | 0.7050 | 332769.0000 |

## HDBSCAN precision, recall and F1 by class (test split)

|              |   precision |   recall |     f1 |     support |
|:-------------|------------:|---------:|-------:|------------:|
| legitimate   |      0.7050 |   0.5987 | 0.6475 | 152983.0000 |
| phishing     |      0.6974 |   0.7869 | 0.7394 | 179786.0000 |
| macro avg    |      0.7012 |   0.6928 | 0.6935 | 332769.0000 |
| weighted avg |      0.7009 |   0.7004 | 0.6972 | 332769.0000 |

## K-Means: largest clusters (train)

Phishing share and median feature values per cluster.

|   cluster |     rows |   phishing_share |   url_length |   path_length |   query_length |   dot_count |   digit_count |   subdomain_count |   suspicious_keyword_count |
|----------:|---------:|-----------------:|-------------:|--------------:|---------------:|------------:|--------------:|------------------:|---------------------------:|
|         4 | 92973.00 |             0.35 |        18.00 |          0.00 |           0.00 |        2.00 |          0.00 |              1.00 |                       0.00 |
|        72 | 57919.00 |             0.38 |        25.00 |          0.00 |           0.00 |        2.00 |          0.00 |              1.00 |                       0.00 |
|        25 | 49850.00 |             0.28 |        14.00 |          0.00 |           0.00 |        2.00 |          0.00 |              1.00 |                       0.00 |
|        96 | 46319.00 |             0.55 |        15.00 |          0.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
|        38 | 41741.00 |             0.47 |        11.00 |          0.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
|        15 | 35728.00 |             0.57 |        16.00 |          0.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
|        63 | 35702.00 |             0.63 |        19.00 |          0.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
|        60 | 35195.00 |             0.28 |        30.00 |         13.00 |           0.00 |        2.00 |          0.00 |              1.00 |                       0.00 |
|        54 | 30830.00 |             0.69 |        21.00 |          0.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
|        48 | 28850.00 |             0.73 |        25.00 |          0.00 |           0.00 |        2.00 |          0.00 |              1.00 |                       0.00 |
|        67 | 27188.00 |             0.36 |         9.00 |          0.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
|        24 | 26202.00 |             0.79 |        18.00 |          0.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
|         7 | 24628.00 |             0.51 |        43.00 |         18.00 |           0.00 |        3.00 |          0.00 |              1.00 |                       0.00 |
|        13 | 24364.00 |             0.01 |        83.00 |         69.00 |           0.00 |        1.00 |          8.00 |              0.00 |                       0.00 |
|        39 | 23678.00 |             0.31 |        25.00 |         14.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |

## HDBSCAN: largest clusters (train)

Phishing share and median feature values per cluster.

| cluster   |    rows |   phishing_share |   url_length |   path_length |   query_length |   dot_count |   digit_count |   subdomain_count |   suspicious_keyword_count |
|:----------|--------:|-----------------:|-------------:|--------------:|---------------:|------------:|--------------:|------------------:|---------------------------:|
| noise     | 7605.00 |             0.57 |        39.00 |         10.00 |           0.00 |        2.00 |          2.00 |              1.00 |                       0.00 |
| 22        | 1472.00 |             0.15 |        52.00 |         39.00 |           0.00 |        1.00 |          4.00 |              0.00 |                       0.00 |
| 6         | 1044.00 |             0.96 |        42.00 |         13.50 |           0.00 |        2.00 |          0.00 |              1.00 |                       1.00 |
| 21        | 1043.00 |             0.56 |        34.00 |         19.00 |           0.00 |        2.00 |          0.00 |              0.00 |                       0.00 |
| 36        |  927.00 |             0.25 |        52.00 |         31.00 |           0.00 |        2.00 |          1.00 |              1.00 |                       0.00 |
| 29        |  710.00 |             0.85 |        19.00 |          0.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
| 24        |  687.00 |             0.32 |        18.00 |          1.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
| 20        |  666.00 |             0.34 |        51.00 |         35.00 |           0.00 |        2.00 |          0.00 |              0.00 |                       0.00 |
| 70        |  662.00 |             0.60 |        22.00 |          1.00 |           0.00 |        2.00 |          0.00 |              1.00 |                       0.00 |
| 60        |  654.00 |             0.85 |        19.00 |          0.00 |           0.00 |        2.00 |          2.00 |              1.00 |                       0.00 |
| 19        |  462.00 |             0.44 |        16.00 |          0.00 |           0.00 |        2.00 |          0.00 |              0.00 |                       0.00 |
| 48        |  382.00 |             0.38 |        22.00 |          9.00 |           0.00 |        1.00 |          0.00 |              0.00 |                       0.00 |
| 8         |  377.00 |             0.35 |        71.00 |         17.00 |          34.00 |        2.00 |          6.00 |              0.00 |                       0.00 |
| 78        |  349.00 |             0.49 |        21.00 |          0.00 |           0.00 |        2.00 |          0.00 |              1.00 |                       0.00 |
| 56        |  346.00 |             0.12 |        19.00 |          0.00 |           0.00 |        3.00 |          0.00 |              1.00 |                       0.00 |

## Caveats

- Clustering is unsupervised: the clusters follow whatever structure dominates the features (URL length, path, query...), which need not be phishing vs legitimate. Its scores here are a lower bound on what the features can do, not a competitor to the classifiers.
- More clusters give finer groups and so, almost always, a better PR-AUC on validation; the selected K says how much detail helps, not how many natural groups the data has. Use the internal scores for the latter.
- HDBSCAN sees only 30000 rows, and the 1-nearest-neighbour step is an approximation of the clusters it would have found on the full data.
- Same as `model_report.md`: the test split comes from the same four overlapping sources as train.
