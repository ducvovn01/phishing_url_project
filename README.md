# Phishing URL Detector (COS30049, Assignment 2)

Machine learning code for a phishing URL detector. A URL string goes in; a phishing probability comes out. Everything is computed from the URL text alone (no page fetching, no WHOIS, no blocklist or reputation calls), so scoring works fully offline once the models are trained.

## 1. Contents

| Path | What it holds |
|---|---|
| `scripts/` | The pipeline: data fetching and cleaning, feature extraction, model training, comparison and `predict.py` (run order in section 4). |
| `scripts/analysis/` | Stand-alone analyses and checks used in the report: EDA, phishing-only clustering, error analysis, unseen-source test and the figures for them. |
| `data/processed/combined_dataset.csv` | The cleaned, deduplicated dataset: `url`, `label` (1 = phishing, 0 = legitimate), `source`. 1,607,776 rows. |
| `data/processed/features.parquet` | The feature table built from it (the 23 model features, plus `url`, `label`, `source`, `domain`, `matched_brand`, and the `has_protocol` / `uses_https` flags, which are kept for the ablation but never used as model inputs). This is what every feature-based model trains on. |
| `data/reference/` | The brand list used for the brand-similarity features (`brand_list.py`, `tranco_top1000.csv`). |
| `data/analysis/` | Written reports (`*.md`), numbers (`*.json`) and `plots/` produced by the scripts. |
| `models/` | The six trained models (`*.joblib`). |
| `data/test_urls.csv` | A small hand-labelled set of URLs for a quick sanity check. |
| `requirements.txt` | Python dependencies. |

`data/processed/duplicates_removed.csv` (the rows dropped by deduplication) and `data/processed/features.csv` (a CSV copy of `features.parquet`) are not used by any final model; they are kept only for inspection.

## 2. Set up the environment

Python 3.11 or newer is needed.

```bash
conda create -n phishing-url python=3.11 -y
conda activate phishing-url
pip install -r requirements.txt
```

`torch` (only needed for the autoencoder) is the largest download. The CPU build is enough:

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
```

All commands below are run from the project root, with the environment active.

## 3. Raw data (only needed to rebuild the dataset from scratch)

If you only want to retrain or use the models, skip to section 4, step 3: the processed dataset is already in `data/processed/`.

The four source datasets are not stored in the repository (`data/raw/` is git-ignored). Create a `.env` file in the project root with your own credentials:

```
HF_TOKEN=<Hugging Face access token; semihGuner2002/PhishingURLsDataset is a gated dataset, accept its terms first>
KAGGLE_USERNAME=<your Kaggle username>
KAGGLE_KEY=<your Kaggle API key>
```

| Source | Where it comes from |
|---|---|
| Mitake/PhishingURLsANDBenignURLs | Hugging Face |
| semihGuner2002/PhishingURLsDataset | Hugging Face (gated) |
| harisudhan411/phishing-and-legitimate-urls | Kaggle |
| PhiUSIIL Phishing URL Dataset | UCI Machine Learning Repository |

## 4. Run the pipeline

```bash
# 1. Download the four raw datasets into data/raw/ (needs the .env above and internet)
python scripts/fetch_datasets.py

# 2. Convert each source to one schema (url, label, source), fix label direction,
#    remove malformed rows and duplicates.
#    Writes data/processed/combined_dataset.csv and duplicates_removed.csv
python scripts/normalize_datasets.py

# 3. Build the features: 21 base URL features plus the two brand-similarity features.
#    Writes data/processed/features.parquet (and features.csv)
python scripts/extract_features.py

# 4. (optional) Exploratory data analysis. Writes data/analysis/eda_report.md and plots/
python scripts/analysis/analyze_dataset.py
python scripts/analysis/make_typosquat_plots.py

# 5. Train the models. Every script uses the same domain-grouped 80/20 split
#    (no registrable domain appears in both train and test).
python scripts/train_model.py          # Logistic Regression + LightGBM  -> models/logreg.joblib, lightgbm.joblib
python scripts/train_char_ngram.py     # char n-gram + Logistic Regression -> models/char_ngram.joblib (selected model)
python scripts/clustering_model.py     # K-Means and HDBSCAN             -> models/kmeans.joblib, hdbscan.joblib
python scripts/autoencoder_model.py    # autoencoder anomaly detector    -> models/autoencoder.joblib

# 6. Compare all six models on the same test split. Writes data/analysis/model_comparison.md
python scripts/compare_models.py
```

Each training script writes its own report to `data/analysis/` (`model_report.md`, `char_ngram_report.md`, `clustering_report.md`, `autoencoder_report.md`).

### Extra analyses used in the report

```bash
# Clustering inside one class: K-Means on the phishing URLs only (no labels used),
# with each cluster described by its feature profile and example URLs.
python scripts/analysis/cluster_phishing.py          # -> data/analysis/phishing_clusters.json
python scripts/analysis/plot_phishing_clusters.py    # -> data/analysis/plots/phishing_cluster_profile.png

# Error analysis of the selected model: confusion matrix, error rates by source and
# URL shape, and a random sample of 40 false positives and 40 false negatives.
python scripts/analysis/error_analysis.py            # -> data/analysis/error_analysis.json, error_samples.csv
python scripts/analysis/plot_error_figures.py      # -> plots/ngram_confusion_matrix.png, ngram_weights.png (run after error_analysis)

# Harder test: train on three sources, test on the fourth (run once per source).
python scripts/analysis/leave_one_source_out.py phiusiil          # -> data/analysis/loso_phiusiil.json
python scripts/analysis/leave_one_source_out.py harisudhan411
python scripts/analysis/leave_one_source_out.py mitake
python scripts/analysis/leave_one_source_out.py semihguner
```

`leave_one_source_out.py` trains on a 600,000-row sample so that it fits in 8 GB of memory.

## 5. Use a trained model to score URLs

```bash
# One or more URLs on the command line (default model: lightgbm)
python scripts/predict.py https://example.com paypal-login-verify.xyz/account

# The selected model, with a custom threshold
python scripts/predict.py --model char_ngram --threshold 0.5 paypa1-secure-login.top

# A text file with one URL per line
python scripts/predict.py --file urls.txt --model char_ngram
```

`--model` accepts `lightgbm`, `logreg`, `char_ngram`, `kmeans`, `hdbscan` or `autoencoder`. The output has one row per URL: `url`, `phishing_probability`, `is_phishing`.

From Python:

```python
import sys
sys.path.insert(0, "scripts")
from predict import PhishingDetector
from train_model import MODELS_DIR

detector = PhishingDetector(MODELS_DIR / "char_ngram.joblib")
print(detector.predict(["https://example.com", "paypa1-login.xyz/verify"]))
```

To check every saved model against the hand-labelled URLs in `data/test_urls.csv`:

```bash
python scripts/analysis/check_test_urls.py          # summary plus the rows some model got wrong
python scripts/analysis/check_test_urls.py --all    # every row
```

## 6. Models

| Model | Input | Script |
|---|---|---|
| Char n-gram + Logistic Regression (selected) | URL text, 3-5 character n-grams, hashed, TF-IDF | `train_char_ngram.py` |
| LightGBM | 23 URL features | `train_model.py` |
| Logistic Regression | 23 URL features | `train_model.py` |
| K-Means, HDBSCAN | 20 numeric URL features | `clustering_model.py` |
| Autoencoder | 20 numeric URL features, trained on legitimate URLs only | `autoencoder_model.py` |

## 7. Notes

- Random seeds are fixed (`RANDOM_STATE = 42` in `scripts/train_model.py`), so re-running a script on the same data reproduces its numbers.
- Feature extraction uses `tldextract` with `suffix_list_urls=()`, so it uses the public-suffix snapshot bundled with the package and never touches the network.
- Run every script from the project root as shown above. The scripts in `scripts/` import each other (`extract_features`, `train_model`), and the ones in `scripts/analysis/` add `scripts/` to the import path themselves.
