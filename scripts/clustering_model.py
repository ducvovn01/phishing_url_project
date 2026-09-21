# Clustering baselines: K-Means and HDBSCAN over the same hand-made URL
# features as train_model.py (numeric ones only: `tld` has no meaningful
# distance, and the protocol flags are left out for the same reason as there).
#
# Clustering never sees the label while it groups URLs. To compare it with the
# classifiers, each cluster becomes a predictor: a URL's phishing probability
# is the phishing share of its cluster in train. That way the same metrics as
# train_model.py apply (evaluate(), per_class_table()), next to the usual
# clustering scores:
# - external, cluster vs label: ARI, NMI, homogeneity, completeness,
#   V-measure, purity;
# - internal, geometry only: silhouette, Davies-Bouldin, Calinski-Harabasz.
#
# - K-Means (MiniBatchKMeans) is fitted on all of train.
# - HDBSCAN doesn't scale to a million rows, so it is fitted on a sample of
#   train, and any other URL takes the cluster of its nearest sampled
#   neighbour. HDBSCAN's noise points (-1) are kept as a group of their own,
#   with their own phishing share.
# K and min_cluster_size are picked by PR-AUC on a domain-grouped validation
# split of train, like C in train_char_ngram.py; the test split is touched
# once, for the final evaluation.
#
# Writes models/{kmeans,hdbscan}.joblib and data/analysis/clustering_report.md.
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.cluster import HDBSCAN, MiniBatchKMeans
from sklearn.metrics import (
    adjusted_rand_score,
    average_precision_score,
    calinski_harabasz_score,
    davies_bouldin_score,
    homogeneity_completeness_v_measure,
    normalized_mutual_info_score,
    silhouette_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

from train_model import (
    ANALYSIS_DIR,
    CATEGORICAL_FEATURES,
    MODELS_DIR,
    NON_FEATURE_COLUMNS,
    PROCESSED_DIR,
    PROTOCOL_FEATURES,
    RANDOM_STATE,
    THRESHOLD,
    build_matrix,
    evaluate,
    log,
    per_class_table,
    positive_proba,
    split_by_domain,
)

VAL_SIZE = 0.1  # share of train domains held out to pick K / min_cluster_size
KMEANS_GRID = [2, 5, 10, 20, 50, 100]
HDBSCAN_GRID = [25, 50, 100]  # min_cluster_size
HDBSCAN_MIN_SAMPLES = 10
# HDBSCAN runtime grows much faster than linearly: ~1 min for 50k rows here.
HDBSCAN_SAMPLE = 30_000
# Cluster phishing shares are shrunk toward the overall share as if each
# cluster had this many extra rows at that share, so a tiny cluster can't
# claim a probability of exactly 0 or 1.
PRIOR_WEIGHT = 10
SILHOUETTE_SAMPLE = 10_000  # silhouette is O(n^2) in memory
PROFILE_COLUMNS = ["url_length", "path_length", "query_length", "dot_count",
                   "digit_count", "subdomain_count", "suspicious_keyword_count"]
NOISE = -1


def numeric_feature_columns(df: pd.DataFrame) -> list:
    return [c for c in df.columns
            if c not in NON_FEATURE_COLUMNS + PROTOCOL_FEATURES + CATEGORICAL_FEATURES]


def bundle_proba(bundle: dict, rows: pd.DataFrame) -> np.ndarray:
    """Phishing probability for feature rows, from a models/{kmeans,hdbscan}.joblib bundle."""
    X = bundle["preprocess"].transform(rows[bundle["feature_columns"]])
    return cluster_to_proba(bundle["model"].predict(X), bundle["cluster_proba"], bundle["prior"])


def build_preprocess() -> Pipeline:
    # Same scaling as the Logistic Regression in train_model.py: counts and
    # lengths are heavy-tailed, and both algorithms work on raw distances.
    return Pipeline([
        ("log1p", FunctionTransformer(np.log1p)),
        ("scale", StandardScaler()),
    ])


def n_clusters(clusters: np.ndarray) -> int:
    return len(set(clusters.tolist()) - {NOISE})


def fit_kmeans(X: np.ndarray, k: int):
    """Returns the fitted model (its predict() assigns new rows) and the
    cluster of every row in X."""
    model = MiniBatchKMeans(n_clusters=k, n_init=3, batch_size=4096,
                            random_state=RANDOM_STATE).fit(X)
    return model, model.labels_


def fit_hdbscan(X: np.ndarray, min_cluster_size: int):
    """Returns a 1-nearest-neighbour model that gives new rows the cluster of
    their closest row in X (sklearn's HDBSCAN has no predict()), and the
    cluster of every row in X."""
    clusters = HDBSCAN(min_cluster_size=min_cluster_size, min_samples=HDBSCAN_MIN_SAMPLES,
                       copy=True, n_jobs=-1).fit_predict(X)
    assigner = KNeighborsClassifier(n_neighbors=1, n_jobs=-1).fit(X, clusters)
    return assigner, clusters


def cluster_proba_map(clusters: np.ndarray, y: np.ndarray, prior: float) -> pd.Series:
    stats = pd.DataFrame({"cluster": clusters, "label": y}).groupby("cluster")["label"]
    return (stats.sum() + PRIOR_WEIGHT * prior) / (stats.count() + PRIOR_WEIGHT)


def cluster_to_proba(clusters: np.ndarray, proba_map: pd.Series, prior: float) -> np.ndarray:
    return pd.Series(clusters).map(proba_map).fillna(prior).to_numpy()


def tune(fit, grid: list, param: str, X_fit, y_fit, X_val, y_val, start: float):
    prior = y_fit.mean()
    rows = []
    for value in grid:
        assigner, clusters = fit(X_fit, value)
        proba_map = cluster_proba_map(clusters, y_fit, prior)
        proba = cluster_to_proba(assigner.predict(X_val), proba_map, prior)
        rows.append({
            param: value,
            "clusters": n_clusters(clusters),
            "noise_share": float((clusters == NOISE).mean()),
            "val_pr_auc": average_precision_score(y_val, proba),
        })
        log(f"  {param}={value}: {rows[-1]['clusters']} clusters, "
            f"validation PR-AUC {rows[-1]['val_pr_auc']:.4f}", start)
    table = pd.DataFrame(rows)
    return int(table.loc[table["val_pr_auc"].idxmax(), param]), table


def clustering_scores(X: np.ndarray, clusters: np.ndarray, y: np.ndarray) -> dict:
    """External scores compare the clusters with the label (noise counts as
    one more cluster); internal scores only look at the geometry, over the
    non-noise rows."""
    homogeneity, completeness, v_measure = homogeneity_completeness_v_measure(y, clusters)
    scores = {
        "clusters": n_clusters(clusters),
        "noise_share": float((clusters == NOISE).mean()),
        "ari": adjusted_rand_score(y, clusters),
        "nmi": normalized_mutual_info_score(y, clusters),
        "homogeneity": homogeneity,
        "completeness": completeness,
        "v_measure": v_measure,
        # Share of rows whose label is their cluster's majority label.
        "purity": pd.crosstab(clusters, y).max(axis=1).sum() / len(y),
        "silhouette": np.nan,
        "davies_bouldin": np.nan,
        "calinski_harabasz": np.nan,
    }
    keep = clusters != NOISE
    if n_clusters(clusters) >= 2:
        X_kept, kept = X[keep], clusters[keep]
        scores["silhouette"] = silhouette_score(
            X_kept, kept, sample_size=min(SILHOUETTE_SAMPLE, len(kept)),
            random_state=RANDOM_STATE)
        scores["davies_bouldin"] = davies_bouldin_score(X_kept, kept)
        scores["calinski_harabasz"] = calinski_harabasz_score(X_kept, kept)
    return scores


def cluster_profile(rows: pd.DataFrame, clusters: np.ndarray, top: int = 15) -> pd.DataFrame:
    """The largest clusters with their phishing share and median feature
    values, in original units, to show what each cluster groups together."""
    grouped = rows.assign(cluster=clusters).groupby("cluster")
    profile = pd.concat([
        grouped.size().rename("rows"),
        grouped["label"].mean().rename("phishing_share"),
        grouped[PROFILE_COLUMNS].median(),
    ], axis=1).sort_values("rows", ascending=False).head(top)
    profile.index = profile.index.map(lambda c: "noise" if c == NOISE else str(c))
    return profile


def main() -> None:
    start = time.perf_counter()
    rng = np.random.default_rng(RANDOM_STATE)

    # Whole table, so split_by_domain() reproduces train_model.py's split
    # exactly and the saved LightGBM can be scored on the same rows.
    df = pd.read_parquet(PROCESSED_DIR / "features.parquet")
    feature_cols = numeric_feature_columns(df)
    train, test = split_by_domain(df)
    del df
    y_train, y_test = train["label"].to_numpy(), test["label"].to_numpy()
    prior = float(y_train.mean())
    log(f"Split: {len(train)} train rows / {len(test)} test rows, no shared domains", start)

    preprocess = build_preprocess().fit(train[feature_cols])
    X_train = preprocess.transform(train[feature_cols])
    X_test = preprocess.transform(test[feature_cols])

    splitter = GroupShuffleSplit(n_splits=1, test_size=VAL_SIZE, random_state=RANDOM_STATE)
    fit_idx, val_idx = next(splitter.split(X_train, groups=train["domain"]))
    X_fit, y_fit = X_train[fit_idx], y_train[fit_idx]
    X_val, y_val = X_train[val_idx], y_train[val_idx]

    # --- K-Means: tune K, refit on all of train ---
    log(f"Tuning K-Means K over {KMEANS_GRID}", start)
    best_k, kmeans_tuning = tune(fit_kmeans, KMEANS_GRID, "k", X_fit, y_fit, X_val, y_val, start)
    kmeans, kmeans_train_clusters = fit_kmeans(X_train, best_k)
    kmeans_map = cluster_proba_map(kmeans_train_clusters, y_train, prior)
    log(f"Fitted K-Means on all of train with K={best_k}", start)

    # --- HDBSCAN: tune min_cluster_size on a sample, refit on a new sample ---
    log(f"Tuning HDBSCAN min_cluster_size over {HDBSCAN_GRID} "
        f"({HDBSCAN_SAMPLE} sampled rows)", start)
    tune_idx = rng.choice(len(X_fit), HDBSCAN_SAMPLE, replace=False)
    best_mcs, hdbscan_tuning = tune(fit_hdbscan, HDBSCAN_GRID, "min_cluster_size",
                                    X_fit[tune_idx], y_fit[tune_idx], X_val, y_val, start)
    sample_idx = rng.choice(len(X_train), HDBSCAN_SAMPLE, replace=False)
    hdbscan, hdbscan_train_clusters = fit_hdbscan(X_train[sample_idx], best_mcs)
    hdbscan_map = cluster_proba_map(hdbscan_train_clusters, y_train[sample_idx], prior)
    log(f"Fitted HDBSCAN on {HDBSCAN_SAMPLE} train rows with min_cluster_size={best_mcs}", start)

    # --- Evaluation ---
    test_clusters = {"K-Means": kmeans.predict(X_test), "HDBSCAN": hdbscan.predict(X_test)}
    probas = {
        "K-Means": cluster_to_proba(test_clusters["K-Means"], kmeans_map, prior),
        "HDBSCAN": cluster_to_proba(test_clusters["HDBSCAN"], hdbscan_map, prior),
    }
    lightgbm_path = MODELS_DIR / "lightgbm.joblib"
    if lightgbm_path.exists():
        bundle = joblib.load(lightgbm_path)
        X = build_matrix(test, bundle["feature_columns"], bundle["tld_categories"])
        probas["LightGBM (saved model, reference)"] = positive_proba(bundle["model"], X)
    log("Scored test split", start)

    results = pd.DataFrame({k: evaluate(test["label"], p) for k, p in probas.items()}).T
    cluster_scores = pd.DataFrame({
        name: clustering_scores(X_test, clusters, y_test)
        for name, clusters in test_clusters.items()
    }).T
    by_class = {name: per_class_table(test["label"], probas[name]) for name in test_clusters}
    profiles = {
        "K-Means": cluster_profile(train, kmeans_train_clusters),
        "HDBSCAN": cluster_profile(train.iloc[sample_idx], hdbscan_train_clusters),
    }

    print()
    print(results.to_string(float_format="{:.4f}".format))
    print()
    print(cluster_scores.to_string(float_format="{:.4f}".format))
    for name, table in by_class.items():
        print(f"\n{name}")
        print(table.to_string(float_format="{:.4f}".format))

    # --- Save models ---
    for name, model, proba_map in [("kmeans", kmeans, kmeans_map),
                                   ("hdbscan", hdbscan, hdbscan_map)]:
        path = MODELS_DIR / f"{name}.joblib"
        joblib.dump({
            "preprocess": preprocess,  # log1p + scaling, fitted on train
            "model": model,  # predict() on preprocessed rows gives the cluster id
            "cluster_proba": proba_map,  # cluster id -> phishing probability
            "prior": prior,  # probability for a cluster id missing from the map
            "feature_columns": feature_cols,
            "threshold": THRESHOLD,
        }, path)
        print(f"saved {path}")

    # --- Report ---
    km, hd = results.loc["K-Means"], results.loc["HDBSCAN"]
    kmc, hdc = cluster_scores.loc["K-Means"], cluster_scores.loc["HDBSCAN"]
    summary = [
        f"- K-Means (K={best_k}) as a classifier (test): ROC-AUC {km['roc_auc']:.4f}, PR-AUC "
        f"{km['pr_auc']:.4f}, F1 {km['f1']:.4f} (precision {km['precision']:.4f}, recall "
        f"{km['recall']:.4f}), accuracy {km['accuracy']:.4f}, MCC {km['mcc']:.4f}, RMSE "
        f"{km['rmse']:.4f}.",
        f"- HDBSCAN (min_cluster_size={best_mcs}) as a classifier (test): ROC-AUC "
        f"{hd['roc_auc']:.4f}, PR-AUC {hd['pr_auc']:.4f}, F1 {hd['f1']:.4f} (precision "
        f"{hd['precision']:.4f}, recall {hd['recall']:.4f}), accuracy {hd['accuracy']:.4f}, "
        f"MCC {hd['mcc']:.4f}, RMSE {hd['rmse']:.4f}. {hdc['noise_share']:.1%} of test URLs "
        "land in its noise group.",
        f"- Agreement with the label: K-Means ARI {kmc['ari']:.4f}, NMI {kmc['nmi']:.4f}, "
        f"purity {kmc['purity']:.4f}; HDBSCAN ARI {hdc['ari']:.4f}, NMI {hdc['nmi']:.4f}, "
        f"purity {hdc['purity']:.4f}.",
        f"- Cluster geometry: K-Means silhouette {kmc['silhouette']:.4f}, Davies-Bouldin "
        f"{kmc['davies_bouldin']:.4f}; HDBSCAN silhouette {hdc['silhouette']:.4f}, "
        f"Davies-Bouldin {hdc['davies_bouldin']:.4f} (non-noise rows).",
    ]
    if "LightGBM (saved model, reference)" in results.index:
        lg = results.loc["LightGBM (saved model, reference)"]
        summary.append(
            f"- For reference, the supervised LightGBM on the same rows: ROC-AUC "
            f"{lg['roc_auc']:.4f}, PR-AUC {lg['pr_auc']:.4f}, F1 {lg['f1']:.4f}.")
    summary[-1] += "\n"

    report = [
        "# Clustering Report - Phishing URL Detector\n",
        "Source: `scripts/clustering_model.py`. Same test split as `model_report.md`.\n",
        "## Summary of findings\n",
        *summary,
        "## Setup\n",
        f"- Features ({len(feature_cols)}): " + ", ".join(f"`{c}`" for c in feature_cols)
        + ". log1p then standard scaling, fitted on train. `tld` and the protocol flags "
        "are not used.",
        f"- K-Means: `MiniBatchKMeans`, fitted on all {len(train)} train rows.",
        f"- HDBSCAN: fitted on {HDBSCAN_SAMPLE} randomly sampled train rows "
        f"(min_samples {HDBSCAN_MIN_SAMPLES}). Any other URL takes the cluster of its "
        "nearest sampled row, noise included. Noise is kept as a group of its own.",
        "- The label is not used to form clusters. It is only used afterwards: a URL's "
        "phishing probability is its cluster's phishing share in train (shrunk toward the "
        f"overall share {prior:.4f} with weight {PRIOR_WEIGHT} rows).",
        f"- K and min_cluster_size were picked by PR-AUC on a domain-grouped validation "
        f"split of train ({len(fit_idx)} fit / {len(val_idx)} validation rows).\n",
        "## Tuning (validation split of train)\n",
        "### K-Means\n",
        kmeans_tuning.round(4).to_markdown(index=False),
        "",
        f"Selected: K={best_k}\n",
        "### HDBSCAN\n",
        hdbscan_tuning.round(4).to_markdown(index=False),
        "",
        f"Selected: min_cluster_size={best_mcs}\n",
        "## Test results: clusters as classifiers\n",
        f"Same metrics as `model_report.md`. Threshold-based metrics use threshold "
        f"{THRESHOLD}; `precision`, `recall` and `f1` are for the phishing class. `mae`, "
        "`mse_brier`, `rmse` and `log_loss` compare the cluster's phishing share with the "
        "0/1 label (lower is better).\n",
        results.to_markdown(floatfmt=".4f"),
        "",
        "## Test results: clustering scores\n",
        "External scores compare the clusters with the label (1 = clusters match the "
        "classes perfectly; ARI 0 = chance). `homogeneity` is high when each cluster holds "
        "one class, `completeness` when each class sits in one cluster, `v_measure` is their "
        "harmonic mean, `purity` the share of URLs in their cluster's majority class. "
        "Internal scores ignore the label: `silhouette` (-1 to 1, higher = tighter, better "
        "separated clusters), `davies_bouldin` (lower is better), `calinski_harabasz` "
        "(higher is better). Internal scores leave HDBSCAN's noise out; `silhouette` uses "
        f"{SILHOUETTE_SAMPLE} sampled rows.\n",
        cluster_scores.to_markdown(floatfmt=".4f"),
        "",
    ]
    for name in test_clusters:
        report += [
            f"## {name} precision, recall and F1 by class (test split)\n",
            by_class[name].to_markdown(floatfmt=".4f"),
            "",
        ]
    for name, profile in profiles.items():
        report += [
            f"## {name}: largest clusters (train)\n",
            "Phishing share and median feature values per cluster.\n",
            profile.to_markdown(floatfmt=".2f"),
            "",
        ]
    report += [
        "## Caveats\n",
        "- Clustering is unsupervised: the clusters follow whatever structure dominates the "
        "features (URL length, path, query...), which need not be phishing vs legitimate. "
        "Its scores here are a lower bound on what the features can do, not a competitor to "
        "the classifiers.",
        "- More clusters give finer groups and so, almost always, a better PR-AUC on "
        "validation; the selected K says how much detail helps, not how many natural groups "
        "the data has. Use the internal scores for the latter.",
        f"- HDBSCAN sees only {HDBSCAN_SAMPLE} rows, and the 1-nearest-neighbour step is an "
        "approximation of the clusters it would have found on the full data.",
        "- Same as `model_report.md`: the test split comes from the same four overlapping "
        "sources as train.",
        "",
    ]
    report_path = ANALYSIS_DIR / "clustering_report.md"
    report_path.write_text("\n".join(report), encoding="utf-8")
    print(f"saved {report_path}")
    log("Done", start)


if __name__ == "__main__":
    main()
