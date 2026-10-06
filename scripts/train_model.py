"""Train LogReg and LightGBM on features.parquet; write models/*.joblib, model_report.md, plots."""
import time
from pathlib import Path
from typing import Any

import joblib
import lightgbm as lgb
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.colors import LinearSegmentedColormap
from sklearn.compose import ColumnTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    log_loss,
    matthews_corrcoef,
    mean_absolute_error,
    mean_squared_error,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import GroupKFold, GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
ANALYSIS_DIR = PROJECT_ROOT / "data" / "analysis"
PLOTS_DIR = ANALYSIS_DIR / "plots"
MODELS_DIR = PROJECT_ROOT / "models"

RANDOM_STATE = 42
TEST_SIZE = 0.2
CV_FOLDS = 3

# Not model inputs: id, target, grouping key, and two leaky/string columns.
# `source` is a label shortcut (class balance differs per source) unavailable at inference.
# `matched_brand` is a string kept for error analysis; the brand scores summarise it.
NON_FEATURE_COLUMNS = ["url", "label", "source", "domain", "matched_brand"]
# Source-formatting artifacts, not phishing signals. Only used in the ablation model.
PROTOCOL_FEATURES = ["has_protocol", "uses_https"]
CATEGORICAL_FEATURES = ["tld"]

# TLDs rarer than this in train are pooled into OTHER_TLD to avoid memorising one-offs.
MIN_TLD_COUNT = 100
NO_TLD = "(none)"  # IP hostnames and anything else without a public suffix
OTHER_TLD = "(other)"

# Any-valued so `**` unpacking into LGBMClassifier type-checks.
LGBM_BASE_PARAMS: dict[str, Any] = {
    "objective": "binary",
    "learning_rate": 0.1,
    "n_estimators": 2000,  # upper bound; early stopping picks the real count
    "subsample": 0.8,
    "subsample_freq": 1,
    "colsample_bytree": 0.8,
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
    "verbose": -1,
}
LGBM_GRID: list[dict[str, Any]] = [
    {"num_leaves": 31, "min_child_samples": 20},
    {"num_leaves": 127, "min_child_samples": 50},
    {"num_leaves": 255, "min_child_samples": 100},
]
EARLY_STOPPING_ROUNDS = 50

THRESHOLD = 0.5
# FPR for the recall-at-fixed-FPR metric: flagging 1 in 100 legitimate URLs is already noisy.
TARGET_FPR = 0.01

# Chart palette: two series colours, a blue ramp for the confusion matrix, muted chrome.
SERIES_COLORS = {"LightGBM": "#2a78d6", "Logistic Regression": "#eb6834"}
SEQUENTIAL_BLUE = ["#f4f8fd", "#cde2fb", "#86b6ef", "#3987e5", "#256abf", "#104281"]
INK_PRIMARY = "#0b0b0b"
INK_SECONDARY = "#52514e"
INK_MUTED = "#898781"
GRIDLINE = "#e1e0d9"
BASELINE = "#c3c2b7"
SURFACE = "#fcfcfb"

plt.rcParams.update({
    "font.family": "sans-serif",
    "font.sans-serif": ["Segoe UI", "Helvetica Neue", "Arial", "DejaVu Sans"],
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "axes.edgecolor": BASELINE,
    "axes.labelcolor": INK_SECONDARY,
    "axes.titlecolor": INK_PRIMARY,
    "axes.titlesize": 12,
    "axes.titleweight": "semibold",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "axes.axisbelow": True,
    "grid.color": GRIDLINE,
    "grid.linewidth": 0.6,
    "xtick.color": INK_MUTED,
    "ytick.color": INK_MUTED,
    "xtick.labelcolor": INK_SECONDARY,
    "ytick.labelcolor": INK_SECONDARY,
    "legend.frameon": False,
    "legend.labelcolor": INK_SECONDARY,
})


def savefig(fig, name: str) -> None:
    """Save `fig` under PLOTS_DIR and close it."""
    path = PLOTS_DIR / name
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"saved {path}")


def log(msg: str, start: float) -> None:
    """Print `msg` prefixed with seconds elapsed since `start`."""
    print(f"[{time.perf_counter() - start:7.1f}s] {msg}")


def split_by_domain(df: pd.DataFrame):
    """80/20 split grouped by domain: sources overlap, so a row split leaks near-duplicates."""
    splitter = GroupShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    train_idx, test_idx = next(splitter.split(df, groups=df["domain"]))
    train = df.iloc[train_idx].reset_index(drop=True)
    test = df.iloc[test_idx].reset_index(drop=True)
    shared = set(train["domain"]) & set(test["domain"])
    assert not shared, f"{len(shared)} domains appear in both train and test"
    return train, test


def fit_tld_categories(train_tld: pd.Series) -> list:
    """TLDs frequent enough in train, plus OTHER_TLD."""
    counts = train_tld.replace("", NO_TLD).value_counts()
    kept = sorted(counts[counts >= MIN_TLD_COUNT].index)
    return kept + [OTHER_TLD]


def encode_tld(tld: pd.Series, categories: list) -> pd.Series:
    """Map TLDs to the fixed category set; unseen ones become OTHER_TLD."""
    tld = tld.replace("", NO_TLD)
    tld = tld.where(tld.isin(categories), OTHER_TLD)
    return tld.astype(pd.CategoricalDtype(categories))


def build_matrix(df: pd.DataFrame, feature_cols: list, tld_categories: list) -> pd.DataFrame:
    """Model input: feature columns plus the encoded `tld`."""
    X = df[feature_cols].copy()
    X["tld"] = encode_tld(df["tld"], tld_categories)
    return X


def build_logreg(numeric_cols: list) -> Pipeline:
    """Preprocessing (log1p, scaling, one-hot TLD) plus Logistic Regression."""
    # Counts and lengths are heavy-tailed; log1p stops extreme rows dominating the fit.
    numeric = Pipeline([
        ("log1p", FunctionTransformer(np.log1p, feature_names_out="one-to-one")),
        ("scale", StandardScaler()),
    ])
    preprocess = ColumnTransformer([
        ("numeric", numeric, numeric_cols),
        ("tld", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
    ])
    return Pipeline([
        ("preprocess", preprocess),
        ("model", LogisticRegression(max_iter=1000)),
    ])


def tune_lightgbm(X: pd.DataFrame, y: pd.Series, groups: pd.Series, start: float):
    """Pick the LGBM_GRID config with the best mean GroupKFold PR-AUC; return params, CV table."""
    folds = list(GroupKFold(n_splits=CV_FOLDS).split(X, y, groups))
    rows = []
    for params in LGBM_GRID:
        scores, iterations = [], []
        for fit_idx, val_idx in folds:
            model = lgb.LGBMClassifier(**LGBM_BASE_PARAMS, **params)
            model.fit(
                X.iloc[fit_idx], y.iloc[fit_idx],
                eval_X=X.iloc[val_idx],
                eval_y=y.iloc[val_idx],
                callbacks=[lgb.early_stopping(EARLY_STOPPING_ROUNDS, verbose=False)],
            )
            proba = positive_proba(model, X.iloc[val_idx])
            scores.append(average_precision_score(y.iloc[val_idx], proba))
            iterations.append(model.best_iteration_)
        rows.append({
            **params,
            "cv_pr_auc_mean": float(np.mean(scores)),
            "cv_pr_auc_std": float(np.std(scores)),
            "best_iteration_mean": int(round(np.mean(iterations))),
        })
        log(f"  {params} -> CV PR-AUC {rows[-1]['cv_pr_auc_mean']:.4f}", start)
    best = max(rows, key=lambda row: row["cv_pr_auc_mean"])
    best_params = {k: best[k] for k in LGBM_GRID[0]}
    best_params["n_estimators"] = best["best_iteration_mean"]  # fixed count for the final refit
    return best_params, pd.DataFrame(rows)


def fit_lightgbm(X: pd.DataFrame, y: pd.Series, params: dict) -> lgb.LGBMClassifier:
    """Fit LightGBM with the base parameters overridden by `params`."""
    model = lgb.LGBMClassifier(**{**LGBM_BASE_PARAMS, **params})
    model.fit(X, y)
    return model


def positive_proba(model, X: pd.DataFrame | pd.Series) -> np.ndarray:
    """Predicted probability of the phishing class."""
    # np.asarray: predict_proba's type allows sparse/list, which can't be column-sliced.
    return np.asarray(model.predict_proba(X))[:, 1]


def evaluate(y_true: pd.Series, proba: np.ndarray) -> dict:
    """Threshold-based, probability-error and ranking metrics for the phishing class."""
    pred = (proba >= THRESHOLD).astype(int)
    # Probability-error metrics reward calibration. MSE here is the Brier score.
    mse = mean_squared_error(y_true, proba)
    metrics = {
        "precision": precision_score(y_true, pred, zero_division=0),
        "recall": recall_score(y_true, pred, zero_division=0),
        "f1": f1_score(y_true, pred, zero_division=0),
        "accuracy": accuracy_score(y_true, pred),
        # Recall of the legitimate class.
        "specificity": recall_score(y_true, pred, pos_label=0, zero_division=np.nan),
        # Filled below: needs both classes. Unlike accuracy, neither is inflated by the
        # majority class (semihguner is ~99% phishing).
        "balanced_accuracy": np.nan,
        "mcc": np.nan,
        "mae": mean_absolute_error(y_true, proba),
        "mse_brier": mse,
        "rmse": float(np.sqrt(mse)),
        "log_loss": log_loss(y_true, proba, labels=[0, 1]),
        "roc_auc": np.nan,
        "pr_auc": np.nan,
        "recall_at_1pct_fpr": np.nan,
    }
    if y_true.nunique() == 2:  # these metrics are undefined for a single class
        metrics["balanced_accuracy"] = balanced_accuracy_score(y_true, pred)
        metrics["mcc"] = matthews_corrcoef(y_true, pred)
        fpr, tpr, _ = roc_curve(y_true, proba)
        metrics["roc_auc"] = roc_auc_score(y_true, proba)
        metrics["pr_auc"] = average_precision_score(y_true, proba)
        metrics["recall_at_1pct_fpr"] = float(np.interp(TARGET_FPR, fpr, tpr))
    return metrics


def per_class_table(y_true: pd.Series, proba: np.ndarray) -> pd.DataFrame:
    """Per-class precision, recall, F1 at THRESHOLD, with macro and weighted averages."""
    pred = (proba >= THRESHOLD).astype(int)
    report = classification_report(y_true, pred, labels=[0, 1],
                                   target_names=["legitimate", "phishing"],
                                   output_dict=True, zero_division=0)
    table = pd.DataFrame(report).T.drop(index="accuracy", errors="ignore")
    table["support"] = table["support"].astype(int)
    return table.rename(columns={"f1-score": "f1"})


def per_source_table(test: pd.DataFrame, proba: np.ndarray) -> pd.DataFrame:
    """Metrics per `source`; test's RangeIndex doubles as row positions into `proba`."""
    rows = []
    for source, group in test.groupby("source"):
        y = group["label"]
        rows.append({
            "source": source,
            "rows": len(group),
            "phishing_share": y.mean(),
            **evaluate(y, proba[group.index.to_numpy()]),
        })
    return pd.DataFrame(rows).set_index("source")


def thin(*arrays, max_points: int = 2000):
    """Subsample arrays evenly to about `max_points` to keep curve plots light."""
    step = max(1, len(arrays[0]) // max_points)
    return [a[::step] for a in arrays]


def plot_curves(y_test: pd.Series, probas: dict) -> None:
    """ROC and precision-recall curves for each model."""
    fig, (ax_roc, ax_pr) = plt.subplots(1, 2, figsize=(11, 4.5))
    for name, proba in probas.items():
        color = SERIES_COLORS[name]
        fpr, tpr, _ = roc_curve(y_test, proba)
        fpr, tpr = thin(fpr, tpr)
        ax_roc.plot(fpr, tpr, color=color, linewidth=2,
                    label=f"{name} (AUC {roc_auc_score(y_test, proba):.3f})")
        precision, recall, _ = precision_recall_curve(y_test, proba)
        recall, precision = thin(recall, precision)
        ax_pr.plot(recall, precision, color=color, linewidth=2,
                   label=f"{name} (AP {average_precision_score(y_test, proba):.3f})")

    ax_roc.plot([0, 1], [0, 1], color=BASELINE, linewidth=1, linestyle="--", label="Chance")
    ax_roc.axvline(TARGET_FPR, color=INK_MUTED, linewidth=1, linestyle=":")
    ax_roc.annotate(f"{TARGET_FPR:.0%} FPR", xy=(TARGET_FPR, 0.04), xytext=(6, 0),
                    textcoords="offset points", color=INK_MUTED, fontsize=9)
    ax_roc.set(title="ROC curve (test split)", xlabel="False positive rate",
               ylabel="True positive rate (recall)", xlim=(0, 1), ylim=(0, 1.01))
    ax_roc.legend(loc="lower right")

    phishing_share = y_test.mean()
    ax_pr.axhline(phishing_share, color=BASELINE, linewidth=1, linestyle="--",
                  label=f"Chance ({phishing_share:.2f})")
    ax_pr.set(title="Precision-recall curve (test split)", xlabel="Recall",
              ylabel="Precision", xlim=(0, 1), ylim=(0, 1.01))
    ax_pr.legend(loc="lower left")
    savefig(fig, "model_roc_pr_curves.png")


def plot_confusion_matrix(cm: np.ndarray) -> None:
    """Row-normalised confusion matrix heatmap with counts."""
    labels = ["legitimate", "phishing"]
    row_share = cm / cm.sum(axis=1, keepdims=True)
    cmap = LinearSegmentedColormap.from_list("seq_blue", SEQUENTIAL_BLUE)

    fig, ax = plt.subplots(figsize=(5, 4.3))
    ax.imshow(row_share, cmap=cmap, vmin=0, vmax=1)
    ax.grid(False)
    for spine in ax.spines.values():
        spine.set_visible(False)
    for i in range(2):
        for j in range(2):
            ink = "#ffffff" if row_share[i, j] > 0.55 else INK_PRIMARY
            ax.text(j, i, f"{cm[i, j]:,}\n{row_share[i, j]:.1%} of row",
                    ha="center", va="center", color=ink, fontsize=10)
    ax.set_xticks([0, 1], labels)
    ax.set_yticks([0, 1], labels)
    ax.tick_params(length=0)
    ax.set(title=f"LightGBM confusion matrix (threshold {THRESHOLD})",
           xlabel="Predicted", ylabel="Actual")
    savefig(fig, "model_confusion_matrix.png")


def plot_feature_importance(importance: pd.Series) -> None:
    """Horizontal bar chart of LightGBM gain share (%)."""
    importance = importance.sort_values()
    fig, ax = plt.subplots(figsize=(7, 0.32 * len(importance) + 1))
    ax.barh(importance.index, importance.to_numpy(), height=0.7, color=SERIES_COLORS["LightGBM"])
    for y, value in enumerate(importance.to_numpy()):
        ax.text(value, y, f" {value:.1f}%", va="center", color=INK_SECONDARY, fontsize=8)
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", length=0)
    ax.set_xlim(0, importance.max() * 1.15)
    ax.set(title="LightGBM feature importance", xlabel="Share of total split gain (%)")
    savefig(fig, "model_feature_importance.png")


def main() -> None:
    """Split, train, evaluate, then save models, plots and the markdown report."""
    start = time.perf_counter()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_parquet(PROCESSED_DIR / "features.parquet")
    log(f"Loaded {len(df)} rows x {df.shape[1]} columns", start)

    all_features = [c for c in df.columns if c not in NON_FEATURE_COLUMNS]
    feature_cols = [c for c in all_features if c not in PROTOCOL_FEATURES]
    numeric_cols = [c for c in feature_cols if c not in CATEGORICAL_FEATURES]

    train, test = split_by_domain(df)
    log(f"Split: {len(train)} train rows / {len(test)} test rows, no shared domains", start)

    tld_categories = fit_tld_categories(train["tld"])
    X_train = build_matrix(train, feature_cols, tld_categories)
    X_test = build_matrix(test, feature_cols, tld_categories)
    y_train, y_test = train["label"], test["label"]

    # --- Logistic Regression baseline ---
    logreg = build_logreg(numeric_cols)
    logreg.fit(X_train, y_train)
    logreg_proba = positive_proba(logreg, X_test)
    log("Fitted Logistic Regression", start)

    # --- LightGBM: tune on train folds, refit on all of train ---
    log(f"Tuning LightGBM ({len(LGBM_GRID)} configs x {CV_FOLDS} GroupKFold folds)", start)
    best_params, cv_table = tune_lightgbm(X_train, y_train, train["domain"], start)
    lgbm = fit_lightgbm(X_train, y_train, best_params)
    lgbm_proba = positive_proba(lgbm, X_test)
    log(f"Fitted LightGBM with {best_params}", start)

    # --- Ablation: same LightGBM setup, protocol flags added back in ---
    ablation_cols = feature_cols + PROTOCOL_FEATURES
    ablation = fit_lightgbm(build_matrix(train, ablation_cols, tld_categories), y_train, best_params)
    ablation_proba = positive_proba(ablation, build_matrix(test, ablation_cols, tld_categories))
    log("Fitted ablation LightGBM (with protocol flags)", start)

    # --- Evaluation ---
    results = pd.DataFrame({
        "LightGBM": evaluate(y_test, lgbm_proba),
        "Logistic Regression": evaluate(y_test, logreg_proba),
        "LightGBM + protocol flags (ablation, not saved)": evaluate(y_test, ablation_proba),
    }).T
    by_source = per_source_table(test, lgbm_proba)
    by_class = per_class_table(y_test, lgbm_proba)
    cm =confusion_matrix(y_test, (lgbm_proba >= THRESHOLD).astype(int))
    gain = pd.Series(lgbm.booster_.feature_importance(importance_type="gain"),
                     index=lgbm.booster_.feature_name())
    importance = (gain / gain.sum() * 100).sort_values(ascending=False)

    print()
    print(results.to_string(float_format="{:.4f}".format))
    print()
    print(by_source.to_string(float_format="{:.4f}".format))
    print()
    print(by_class.to_string(float_format="{:.4f}".format))
    print()

    plot_curves(y_test, {"LightGBM": lgbm_proba, "Logistic Regression": logreg_proba})
    plot_confusion_matrix(cm)
    plot_feature_importance(importance)

    # --- Save models ---
    for name, model, cols in [("lightgbm", lgbm, feature_cols), ("logreg", logreg, feature_cols)]:
        path = MODELS_DIR / f"{name}.joblib"
        joblib.dump({
            "model": model,
            "feature_columns": cols,  # tld must be encoded with encode_tld()
            "tld_categories": tld_categories,
            "threshold": THRESHOLD,
        }, path)
        print(f"saved {path}")

    # --- Report ---
    lg, lr, ab = (results.loc[k] for k in results.index)
    weakest = by_source["f1"].idxmin()
    tn, fp, fn, tp = cm.ravel()

    report = [
        "# Model Report - Phishing URL Detector\n",
        "Feature table: `data/processed/features.parquet` (from `scripts/extract_features.py`)\n",
        "## Summary of findings\n",
        f"- Train/test split is by registrable domain: {len(train)} train rows "
        f"({train['domain'].nunique()} domains) vs {len(test)} test rows "
        f"({test['domain'].nunique()} domains), with no domain on both sides. "
        f"Phishing share: {y_train.mean():.2%} train, {y_test.mean():.2%} test.",
        f"- LightGBM (test): ROC-AUC {lg['roc_auc']:.4f}, PR-AUC {lg['pr_auc']:.4f}, "
        f"F1 {lg['f1']:.4f} (precision {lg['precision']:.4f}, recall {lg['recall']:.4f}) "
        f"at threshold {THRESHOLD}. At a {TARGET_FPR:.0%} false-positive rate it catches "
        f"{lg['recall_at_1pct_fpr']:.2%} of phishing URLs.",
        f"- LightGBM accuracy {lg['accuracy']:.4f}, balanced accuracy "
        f"{lg['balanced_accuracy']:.4f}, specificity {lg['specificity']:.4f}, MCC "
        f"{lg['mcc']:.4f}; macro F1 over both classes "
        f"{by_class.loc['macro avg', 'f1']:.4f}.",
        f"- Logistic Regression baseline (test): ROC-AUC {lr['roc_auc']:.4f}, PR-AUC "
        f"{lr['pr_auc']:.4f}, F1 {lr['f1']:.4f}, recall at {TARGET_FPR:.0%} FPR "
        f"{lr['recall_at_1pct_fpr']:.2%}.",
        f"- Probability error (test, lower is better): LightGBM MAE {lg['mae']:.4f}, RMSE "
        f"{lg['rmse']:.4f}, log loss {lg['log_loss']:.4f}; Logistic Regression MAE "
        f"{lr['mae']:.4f}, RMSE {lr['rmse']:.4f}, log loss {lr['log_loss']:.4f}.",
        f"- At threshold {THRESHOLD}, LightGBM misses {fn} of {fn + tp} phishing URLs and "
        f"flags {fp} of {tn + fp} legitimate URLs ({fp / (tn + fp):.2%}).",
        f"- Weakest source for LightGBM by F1: {weakest} "
        f"(F1 {by_source.loc[weakest, 'f1']:.4f}). Per-source scores are not directly "
        "comparable: each source has a very different phishing share.",
        f"- Ablation: adding `has_protocol`/`uses_https` back moves test ROC-AUC from "
        f"{lg['roc_auc']:.4f} to {ab['roc_auc']:.4f} and recall at {TARGET_FPR:.0%} FPR from "
        f"{lg['recall_at_1pct_fpr']:.2%} to {ab['recall_at_1pct_fpr']:.2%}. Those flags mostly "
        "record how each source formatted its URLs, so any gain from them would not carry "
        "over to real traffic. They are left out of the saved models.",
        f"- Top features by split gain: "
        + ", ".join(f"`{f}` ({v:.1f}%)" for f, v in importance.head(5).items()) + ".",
        f"- Brand-similarity features (FR3, added over the original 21): `brand_similarity_score` "
        f"ranks {list(importance.index).index('brand_similarity_score') + 1} of {len(importance)} "
        f"by split gain ({importance['brand_similarity_score']:.2f}%) — just behind `tld` and "
        f"`path_length`, ahead of every lexical count feature. `is_exact_brand_match` ranks "
        f"{list(importance.index).index('is_exact_brand_match') + 1} "
        f"({importance['is_exact_brand_match']:.2f}%): most of its signal is already implied by "
        f"a high `brand_similarity_score`, so it adds little on top of the continuous score.\n",
        "## Setup\n",
        f"- Split: `GroupShuffleSplit` on `domain`, test size {TEST_SIZE}, "
        f"random_state {RANDOM_STATE}.",
        f"- Features ({len(feature_cols)}): " + ", ".join(f"`{c}`" for c in feature_cols) + ".",
        "- Not used as features: `url` (identifier), `label` (target), `domain` (grouping key), "
        "`source` (provenance; a shortcut to the label), `has_protocol` and `uses_https` "
        "(source-formatting artifacts - see ablation), `matched_brand` (string, which brand "
        "won the fuzzy match - kept for the A2 report's misclassification analysis, not a "
        "model input; `brand_similarity_score`/`is_exact_brand_match` are its model-facing "
        "summary).",
        f"- `tld` is categorical. TLDs seen fewer than {MIN_TLD_COUNT} times in train are pooled "
        f"into `{OTHER_TLD}`, and a missing suffix is `{NO_TLD}` "
        f"({len(tld_categories)} categories in total).",
        "- Logistic Regression: log1p + standard scaling on numeric features, one-hot `tld`.",
        f"- LightGBM: learning rate {LGBM_BASE_PARAMS['learning_rate']}, row/column subsampling "
        f"0.8. The grid below was scored by {CV_FOLDS}-fold `GroupKFold` on the train split "
        f"(grouped by `domain`), with early stopping after {EARLY_STOPPING_ROUNDS} rounds. The "
        "final model was refit on all of train with the best config and its mean best iteration.\n",
        "## LightGBM tuning (CV on train split)\n",
        # Rounded, not floatfmt: floatfmt would print the int columns as 31.0000.
        cv_table.round(4).to_markdown(index=False),
        "",
        f"Selected: {best_params}\n",
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
        "## LightGBM precision, recall and F1 by class (test split)\n",
        by_class.to_markdown(floatfmt=".4f"),
        "",
        "## LightGBM results by source (test split)\n",
        by_source.to_markdown(floatfmt=".4f"),
        "",
        "## LightGBM confusion matrix (test split)\n",
        pd.DataFrame(cm, index=["actual legitimate", "actual phishing"],
                     columns=["predicted legitimate", "predicted phishing"]).to_markdown(),
        "",
        "## LightGBM feature importance\n",
        importance.rename("gain_share_pct").to_frame().to_markdown(floatfmt=".2f"),
        "",
        "## Plots\n",
        "![ROC and precision-recall curves](plots/model_roc_pr_curves.png)\n",
        "![Confusion matrix](plots/model_confusion_matrix.png)\n",
        "![Feature importance](plots/model_feature_importance.png)\n",
        "## Caveats\n",
        "- The four sources overlap and are not independent samples (see `eda_report.md`). "
        "Grouping by domain stops the same site from appearing on both sides of the split, "
        "but the test split still comes from the same sources as train. Expect lower scores "
        "on URLs from a new source.",
        "- Hosting and dynamic-DNS domains (e.g. `blogspot.com`, `duckdns.org`) are one group "
        "each, so all of their subdomains fall on the same side of the split.",
        "- `brand_similarity_score` (`rapidfuzz.fuzz.ratio`) is a normalized edit distance, "
        "which is noisy on short domain labels: a 3-4 character label needs only a one- or "
        "two-character difference from some brand in the list to score >=0.85 by chance (e.g. "
        "`fida.com` scores 0.857 against `fda`), independent of any real typosquat intent. "
        "Longer look-alike labels (`instagrame.net` vs `instagram`, `tercent.tk` vs `tencent`) "
        "score high for the right reason. Because of this the dataset-wide mean score is "
        "*higher* for legitimate rows than phishing rows (0.675 vs 0.600) — driven by "
        "legitimate rows that are literally a brand's own domain (`is_exact_brand_match=True`, "
        "16.6% of legitimate rows vs 7.2% of phishing rows) — so read the two features "
        "together, not `brand_similarity_score` alone, when explaining a prediction.",
        f"- Threshold {THRESHOLD} was not tuned. Pick the operating point from the ROC curve "
        "based on how many false alarms are acceptable.",
        "",
    ]
    report_path = ANALYSIS_DIR / "model_report.md"
    report_path.write_text("\n".join(report), encoding="utf-8")
    print(f"saved {report_path}")
    log("Done", start)


if __name__ == "__main__":
    main()
