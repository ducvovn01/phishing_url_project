# Leave-one-source-out test: train the char n-gram model on three sources, test on the
# fourth, since the main split shares sources and may overstate generalisation.
# Domains found in the held-out source are dropped from training to avoid leakage.
#
# Usage: python scripts/analysis/leave_one_source_out.py <source>
# Writes data/analysis/loso_<source>.json
import json
import sys
import time

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.linear_model import LogisticRegression

from pathlib import Path

# Scripts import each other from scripts/, one level up.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from train_char_ngram import ngram_hasher
from train_model import ANALYSIS_DIR, PROCESSED_DIR, evaluate, log

C = 30.0  # value chosen in train_char_ngram.py
# liblinear copies the matrix, so train on a sample to fit in 8 GB (main model: 1.27M rows).
TRAIN_SAMPLE = 600_000


def main(held_out: str) -> None:
    """Train without `held_out`, evaluate on it and save metrics to JSON."""
    start = time.perf_counter()
    df = pd.read_parquet(PROCESSED_DIR / "features.parquet", columns=["url", "label", "source", "domain"])
    test = df[df["source"] == held_out].reset_index(drop=True)
    train = df[df["source"] != held_out]
    train = train[~train["domain"].isin(set(test["domain"]))]
    train = train.sample(min(TRAIN_SAMPLE, len(train)), random_state=42).reset_index(drop=True)
    log(f"held out {held_out}: train {len(train)} rows, test {len(test)} rows", start)

    hasher = ngram_hasher()
    X_train = hasher.transform(train["url"])
    tfidf = TfidfTransformer(sublinear_tf=True).fit(X_train)
    X_train = tfidf.transform(X_train).astype(np.float64)
    model = LogisticRegression(solver="liblinear", C=C).fit(X_train, train["label"].to_numpy())
    del X_train
    log("fitted", start)
    proba = model.predict_proba(tfidf.transform(hasher.transform(test["url"])))[:, 1]
    metrics = evaluate(test["label"], proba)
    metrics.update({"held_out": held_out, "train_rows": len(train), "test_rows": len(test),
                    "test_phishing_share": float(test["label"].mean())})
    json.dump(metrics, open(ANALYSIS_DIR / f"loso_{held_out}.json", "w"), indent=1)
    print(json.dumps(metrics, indent=1))


if __name__ == "__main__":
    main(sys.argv[1])
