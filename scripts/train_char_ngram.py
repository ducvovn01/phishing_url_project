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
# URLs go through extract_features.preprocess_url_masked() first: scheme
# stripped and lowercased, to keep source formatting out of the input (same
# reason has_protocol/uses_https are dropped in train_model.py), and the brand
# label of an official brand domain replaced by a shared mask ("facebook.com"
# -> "§.com"). Without the mask, a brand whose own domain is missing from train
# is known only from pages impersonating it, and its real site gets flagged:
# the domain-grouped split put every facebook.com row in test. The same
# pipeline without the mask is fitted once more as an ablation. The
# preprocessors live in extract_features.py so the pickled pipeline refers to
# an importable module, not __main__.
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

from extract_features import OFFICIAL_BRAND_DOMAINS, preprocess_url, preprocess_url_masked
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
    per_class_table,
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

# Row names in the results tables.
NGRAM = "Char n-gram + Logistic Regression"
UNMASKED = "Char n-gram without brand masking (ablation, not saved)"
LIGHTGBM = "LightGBM (saved model)"
LOGREG = "Logistic Regression on URL features (saved model)"
ALL_BRANDS = "(all official domains)"


def ngram_hasher(analyzer="char", preprocessor=preprocess_url_masked) -> HashingVectorizer:
    return HashingVectorizer(
        analyzer=analyzer,
        ngram_range=NGRAM_RANGE,
        preprocessor=preprocessor,
        n_features=N_FEATURES,
        alternate_sign=False,
        norm=None,
        dtype=np.float32,
    )


def build_char_ngram(C: float, preprocessor=preprocess_url_masked) -> Pipeline:
    """Raw URL strings in, phishing probability out."""
    return Pipeline([
        ("ngrams", ngram_hasher(preprocessor=preprocessor)),
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
        analyzer="char", ngram_range=NGRAM_RANGE, preprocessor=preprocess_url_masked, min_df=200,
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


def brand_domain_table(test: pd.DataFrame, probas: dict, top: int = 10) -> pd.DataFrame:
    """Share of legitimate test URLs on official brand domains that each model
    flags as phishing: per domain for the `top` domains with the most rows,
    and over all of them."""
    # `test` has a RangeIndex (split_by_domain resets it), so its index labels
    # are also row positions into each proba array.
    legit = test[test["domain"].isin(OFFICIAL_BRAND_DOMAINS) & (test["label"] == 0)]
    flagged = pd.DataFrame({name: proba[legit.index.to_numpy()] >= THRESHOLD
                            for name, proba in probas.items()}, index=legit.index)
    table = flagged.groupby(legit["domain"]).mean()
    table.insert(0, "legit_rows", legit["domain"].value_counts())
    table = table.sort_values("legit_rows", ascending=False).head(top)
    table.loc[ALL_BRANDS] = [len(legit), *flagged.mean()]
    table["legit_rows"] = table["legit_rows"].astype(int)
    return table


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

    # Ablation: same C without the brand mask, to show what the mask changes.
    unmasked = build_char_ngram(best_C, preprocessor=preprocess_url).fit(train["url"], y_train)
    probas = {NGRAM: ngram_proba, UNMASKED: positive_proba(unmasked, test["url"])}
    log("Fitted ablation without brand masking", start)

    for name, label in [("lightgbm", LIGHTGBM), ("logreg", LOGREG)]:
        bundle = joblib.load(MODELS_DIR / f"{name}.joblib")
        X = build_matrix(test, bundle["feature_columns"], bundle["tld_categories"])
        probas[label] = positive_proba(bundle["model"], X)

    results = pd.DataFrame({k: evaluate(test["label"], p) for k, p in probas.items()}).T
    by_source = per_source_table(test, ngram_proba)
    by_class = per_class_table(test["label"], ngram_proba)
    brands = brand_domain_table(test, probas)
    cm = confusion_matrix(y_test, (ngram_proba >= THRESHOLD).astype(int))
    ngrams = top_ngrams(pipeline, train["url"].sample(300_000, random_state=RANDOM_STATE))
    print()
    print(results.to_string(float_format="{:.4f}".format))
    print()
    print(by_source.to_string(float_format="{:.4f}".format))
    print()
    print(by_class.to_string(float_format="{:.4f}".format))
    print()
    print(brands.to_string(float_format="{:.4f}".format))

    model_path = MODELS_DIR / "char_ngram.joblib"
    joblib.dump({
        "model": pipeline,  # takes raw URL strings; preprocessing is inside
        "threshold": THRESHOLD,
    }, model_path)
    print(f"saved {model_path}")

    ng, ab, lg, lr = (results.loc[k] for k in [NGRAM, UNMASKED, LIGHTGBM, LOGREG])
    all_brands = brands.loc[ALL_BRANDS]
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
        f"- Char n-gram accuracy {ng['accuracy']:.4f}, balanced accuracy "
        f"{ng['balanced_accuracy']:.4f}, specificity {ng['specificity']:.4f}, MCC "
        f"{ng['mcc']:.4f}; macro F1 over both classes "
        f"{by_class.loc['macro avg', 'f1']:.4f}.",
        f"- LightGBM on the same rows: ROC-AUC {lg['roc_auc']:.4f}, PR-AUC {lg['pr_auc']:.4f}, "
        f"F1 {lg['f1']:.4f}, recall at {TARGET_FPR:.0%} FPR {lg['recall_at_1pct_fpr']:.2%}.",
        f"- Logistic Regression on the 21 URL features: ROC-AUC {lr['roc_auc']:.4f}, PR-AUC "
        f"{lr['pr_auc']:.4f}, F1 {lr['f1']:.4f}. Same classifier as the n-gram model, so the "
        "gap between the two is down to the input representation.",
        "- Probability error (test, lower is better): "
        + "; ".join(f"{name} MAE {row['mae']:.4f}, RMSE {row['rmse']:.4f}, log loss "
                    f"{row['log_loss']:.4f}"
                    for name, row in [("char n-gram", ng), ("LightGBM", lg),
                                      ("Logistic Regression", lr)]) + ".",
        f"- At threshold {THRESHOLD}, the n-gram model misses {fn} of {fn + tp} phishing URLs "
        f"and flags {fp} of {tn + fp} legitimate URLs ({fp / (tn + fp):.2%}).",
        f"- Brand masking: of the {all_brands['legit_rows']} legitimate test URLs on official "
        f"brand domains, the model flags {all_brands[NGRAM]:.2%}, against "
        f"{all_brands[UNMASKED]:.2%} for the same model without the mask. Over the whole test "
        f"split the mask moves PR-AUC from {ab['pr_auc']:.4f} to {ng['pr_auc']:.4f}, F1 from "
        f"{ab['f1']:.4f} to {ng['f1']:.4f} and the false-positive rate from "
        f"{1 - ab['specificity']:.2%} to {1 - ng['specificity']:.2%}.\n",
        "## Setup\n",
        "- Test split: `split_by_domain()` from `train_model.py` (same rows as `model_report.md`).",
        f"- Input: URL with the scheme stripped and lowercased. Scheme and letter case mostly "
        "record how each source formatted its URLs (phiusiil has no uppercase at all), so "
        "they are removed.",
        f"- Brand mask: when the registrable domain is one of {len(OFFICIAL_BRAND_DOMAINS)} "
        "official brand domains (`OFFICIAL_BRAND_DOMAINS` in `extract_features.py`, drawn up "
        "from public brand-phishing rankings), its brand label is replaced by `§`: "
        "`docs.google.com/forms/x` becomes `docs.§.com/forms/x`. The brand name anywhere else "
        "(`facebook.com.evil.tk`, `singin-facebook.com`, a path) is left as is.",
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
        f"of phishing URLs caught when {TARGET_FPR:.0%} of legitimate URLs are flagged. "
        "`precision`, `recall` and `f1` are for the phishing class; `specificity` is the recall "
        "of the legitimate class, `balanced_accuracy` the mean of the two recalls, and `mcc` "
        "the Matthews correlation (-1 to 1, 0 = chance). "
        "`mae`, `mse_brier`, `rmse` and `log_loss` compare the predicted phishing probability "
        "with the 0/1 label (lower is better); `mse_brier` is the Brier score and `rmse` its "
        "square root.\n",
        results.to_markdown(floatfmt=".4f"),
        "",
        "## Brand masking (test split)\n",
        "Share of legitimate URLs flagged as phishing, on the official brand domains with the "
        "most legitimate test rows and over all of them. The domain-grouped split put every "
        "`facebook.com` and `netflix.com` row in test, so without the mask the model knows "
        "these brands only from train URLs that impersonate them. With the mask it can apply "
        "what it learned from official domains that are in train (`amazon.com`, "
        "`microsoft.com`, `yahoo.com`...).\n",
        # Rounded rather than floatfmt'd, which would print legit_rows as 9078.0000.
        brands.round(4).to_markdown(),
        "",
        "## Char n-gram precision, recall and F1 by class (test split)\n",
        by_class.to_markdown(floatfmt=".4f"),
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
        "- The brand mask only covers the brands on its list. A brand that is not on it, and "
        "whose own domain is not in train, is still known only from URLs impersonating it.",
        "- The mask does not whitelist anything: a phishing page hosted on an official domain "
        "(`docs.google.com/forms/...`, `sites.google.com/...`) is still scored from its "
        "subdomain and path.",
        "",
    ]
    report_path = ANALYSIS_DIR / "char_ngram_report.md"
    report_path.write_text("\n".join(report), encoding="utf-8")
    print(f"saved {report_path}")
    log("Done", start)


if __name__ == "__main__":
    main()
