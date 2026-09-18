# Character n-gram baseline: TF-IDF over 3-5 character substrings of the raw
# URL, fed to a Logistic Regression.
#
# Unlike train_model.py it gets no hand-made features: every run of 3-5
# characters in the URL (e.g. "ver", "erif", ".top/") is a feature, and the
# model learns one weight per n-gram. It uses the same domain-grouped
# train/test split and the same metrics as train_model.py, and scores the
# saved LightGBM and Logistic Regression models on that test split for a
# side-by-side table.
#
# URLs go through extract_features.preprocess_url() first (scheme stripped,
# lowercased), to keep source formatting out of the input - same reason
# has_protocol/uses_https are dropped in train_model.py. It lives there rather
# than here so the pickled pipeline refers to an importable module, not
# __main__.
#
# Writes models/char_ngram.joblib and data/analysis/char_ngram_report.md.
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer, HashingVectorizer, TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline

from extract_features import preprocess_url
from train_model import (
    ANALYSIS_DIR,
    MODELS_DIR,
    PROCESSED_DIR,
    RANDOM_STATE,
    TARGET_FPR,
    THRESHOLD,
    build_matrix,
    evaluate,
    log,
    per_source_table,
    positive_proba,
    split_by_domain,
)

NGRAM_RANGE = (3, 5)
# Hashing instead of a learned vocabulary: the train split has tens of
# millions of distinct n-grams, and a vocabulary dict that size doesn't fit in
# memory. Rare collisions (two n-grams sharing one column) are the trade-off.
N_FEATURES = 2 ** 20
VAL_SIZE = 0.1  # share of train domains held out to pick C
C_GRID = [1.0, 3.0, 10.0, 30.0]


def ngram_hasher(analyzer="char") -> HashingVectorizer:
    return HashingVectorizer(
        analyzer=analyzer,
        ngram_range=NGRAM_RANGE,
        preprocessor=preprocess_url,
        n_features=N_FEATURES,
        alternate_sign=False,
        norm=None,
        dtype=np.float32,
    )


def build_char_ngram(C: float) -> Pipeline:
    """Raw URL strings in, phishing probability out."""
    return Pipeline([
        ("ngrams", ngram_hasher()),
        ("tfidf", TfidfTransformer(sublinear_tf=True)),
        ("model", LogisticRegression(solver="liblinear", C=C)),
    ])


def tune_C(urls: pd.Series, y: np.ndarray, groups: pd.Series, start: float):
    splitter = GroupShuffleSplit(n_splits=1, test_size=VAL_SIZE, random_state=RANDOM_STATE)
    fit_idx, val_idx = next(splitter.split(urls, groups=groups))
    # Hashing is stateless, so the n-gram counts are computed once and only
    # the TF-IDF weights and the classifier are fitted per C.
    counts = ngram_hasher().transform(urls)
    tfidf = TfidfTransformer(sublinear_tf=True).fit(counts[fit_idx])
    X_fit, X_val = tfidf.transform(counts[fit_idx]), tfidf.transform(counts[val_idx])
    rows = []
    for C in C_GRID:
        model = LogisticRegression(solver="liblinear", C=C).fit(X_fit, y[fit_idx])
        score = average_precision_score(y[val_idx], model.predict_proba(X_val)[:, 1])
        rows.append({"C": C, "val_pr_auc": score})
        log(f"  C={C}: validation PR-AUC {score:.4f}", start)
    table = pd.DataFrame(rows)
    return float(table.loc[table["val_pr_auc"].idxmax(), "C"]), table, len(fit_idx), len(val_idx)


def top_ngrams(pipeline: Pipeline, urls: pd.Series, n: int = 15) -> pd.DataFrame:
    """Weights of the most common n-grams in `urls`. The model only stores
    hashed columns, so the n-gram text is recovered by hashing a vocabulary
    of real n-grams and reading their columns' weights."""
    vocab = CountVectorizer(
        analyzer="char", ngram_range=NGRAM_RANGE, preprocessor=preprocess_url, min_df=200,
    ).fit(urls).get_feature_names_out()
    # Hash each n-gram as a single token to find its column.
    columns = ngram_hasher(analyzer=lambda s: [s]).transform(vocab).indices
    weights = pipeline.named_steps["model"].coef_[0][columns]
    table = pd.DataFrame({"ngram": vocab, "weight": weights}).sort_values("weight")
    table["ngram"] = "`" + table["ngram"] + "`"
    return pd.concat([
        table.tail(n)[::-1].assign(direction="phishing"),
        table.head(n).assign(direction="legitimate"),
    ])[["direction", "ngram", "weight"]]


def main() -> None:
    start = time.perf_counter()

    # Whole table, so split_by_domain() reproduces train_model.py's split
    # exactly and the saved models can be scored on the same rows.
    df = pd.read_parquet(PROCESSED_DIR / "features.parquet")
    train, test = split_by_domain(df)
    del df
    y_train, y_test = train["label"].to_numpy(), test["label"].to_numpy()
    log(f"Split: {len(train)} train rows / {len(test)} test rows, no shared domains", start)

    log(f"Tuning C over {C_GRID} on a {VAL_SIZE:.0%} domain-grouped validation split", start)
    best_C, tuning, n_fit, n_val = tune_C(train["url"], y_train, train["domain"], start)

    pipeline = build_char_ngram(best_C).fit(train["url"], y_train)
    ngram_proba = positive_proba(pipeline, test["url"])
    log(f"Fitted char n-gram model on all of train with C={best_C}", start)

    probas = {"Char n-gram + Logistic Regression": ngram_proba}
    for name, label in [("lightgbm", "LightGBM (saved model)"),
                        ("logreg", "Logistic Regression on URL features (saved model)")]:
        bundle = joblib.load(MODELS_DIR / f"{name}.joblib")
        X = build_matrix(test, bundle["feature_columns"], bundle["tld_categories"])
        probas[label] = positive_proba(bundle["model"], X)

    results = pd.DataFrame({k: evaluate(test["label"], p) for k, p in probas.items()}).T
    by_source = per_source_table(test, ngram_proba)
    cm = confusion_matrix(y_test, (ngram_proba >= THRESHOLD).astype(int))
    ngrams = top_ngrams(pipeline, train["url"].sample(300_000, random_state=RANDOM_STATE))
    print()
    print(results.to_string(float_format="{:.4f}".format))
    print()
    print(by_source.to_string(float_format="{:.4f}".format))

    model_path = MODELS_DIR / "char_ngram.joblib"
    joblib.dump({
        "model": pipeline,  # takes raw URL strings; preprocessing is inside
        "threshold": THRESHOLD,
    }, model_path)
    print(f"saved {model_path}")

    ng, lg, lr = (results.iloc[i] for i in range(3))
    tn, fp, fn, tp = cm.ravel()
    report = [
        "# Char N-gram Report - Phishing URL Detector\n",
        "Source: `scripts/train_char_ngram.py`. Compared with the models from "
        "`scripts/train_model.py` on the same test split.\n",
        "## Summary of findings\n",
        f"- Char n-gram + Logistic Regression (test): ROC-AUC {ng['roc_auc']:.4f}, PR-AUC "
        f"{ng['pr_auc']:.4f}, F1 {ng['f1']:.4f} (precision {ng['precision']:.4f}, recall "
        f"{ng['recall']:.4f}) at threshold {THRESHOLD}. At a {TARGET_FPR:.0%} false-positive "
        f"rate it catches {ng['recall_at_1pct_fpr']:.2%} of phishing URLs.",
        f"- LightGBM on the same rows: ROC-AUC {lg['roc_auc']:.4f}, PR-AUC {lg['pr_auc']:.4f}, "
        f"F1 {lg['f1']:.4f}, recall at {TARGET_FPR:.0%} FPR {lg['recall_at_1pct_fpr']:.2%}.",
        f"- Logistic Regression on the 21 URL features: ROC-AUC {lr['roc_auc']:.4f}, PR-AUC "
        f"{lr['pr_auc']:.4f}, F1 {lr['f1']:.4f}. Same classifier as the n-gram model, so the "
        "gap between the two is down to the input representation.",
        f"- At threshold {THRESHOLD}, the n-gram model misses {fn} of {fn + tp} phishing URLs "
        f"and flags {fp} of {tn + fp} legitimate URLs ({fp / (tn + fp):.2%}).\n",
        "## Setup\n",
        "- Test split: `split_by_domain()` from `train_model.py` (same rows as `model_report.md`).",
        f"- Input: URL with the scheme stripped and lowercased. Scheme and letter case mostly "
        "record how each source formatted its URLs (phiusiil has no uppercase at all), so "
        "they are removed.",
        f"- Features: every {NGRAM_RANGE[0]}-{NGRAM_RANGE[1]} character substring, hashed into "
        f"{N_FEATURES:,} columns (`HashingVectorizer`), then TF-IDF with sublinear term "
        "frequency.",
        "- Classifier: `LogisticRegression(solver=\"liblinear\")` with L2 penalty.",
        f"- `C` (inverse regularization strength) was picked from {C_GRID} by PR-AUC on a "
        f"domain-grouped validation split of train ({n_fit} fit / {n_val} validation rows). "
        "The final model was refit on all of train.\n",
        "## Tuning (validation split of train)\n",
        tuning.to_markdown(index=False, floatfmt=".4f"),
        "",
        f"Selected: C={best_C}\n",
        "## Test results\n",
        f"Threshold-based metrics use threshold {THRESHOLD}. `recall_at_1pct_fpr` is the share "
        f"of phishing URLs caught when {TARGET_FPR:.0%} of legitimate URLs are flagged.\n",
        results.to_markdown(floatfmt=".4f"),
        "",
        "## Char n-gram results by source (test split)\n",
        by_source.to_markdown(floatfmt=".4f"),
        "",
        "## Char n-gram confusion matrix (test split)\n",
        pd.DataFrame(cm, index=["actual legitimate", "actual phishing"],
                     columns=["predicted legitimate", "predicted phishing"]).to_markdown(),
        "",
        "## Strongest n-grams\n",
        "Largest positive (phishing) and negative (legitimate) weights among n-grams seen in "
        "at least 200 of 300,000 sampled train URLs. Weights are per hashed column, so a "
        "column shared by two n-grams shows their combined weight.\n",
        ngrams.to_markdown(index=False, floatfmt=".3f"),
        "",
        "## Caveats\n",
        "- Same as `model_report.md`: the test split comes from the same four overlapping "
        "sources as train, so expect lower scores on URLs from a new source.",
        "- Lowercasing and stripping the scheme remove only some source-formatting "
        "shortcuts. Others remain and the n-grams can see them directly: e.g. every phiusiil "
        "legitimate URL is a bare `www.<domain>` with no path, and no semihguner URL starts "
        "with `www.`.",
        "",
    ]
    report_path = ANALYSIS_DIR / "char_ngram_report.md"
    report_path.write_text("\n".join(report), encoding="utf-8")
    print(f"saved {report_path}")
    log("Done", start)


if __name__ == "__main__":
    main()
