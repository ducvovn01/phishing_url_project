# Side-by-side comparison of every saved model on the same test split.
#
# Loads models/*.joblib as written by train_model.py, train_char_ngram.py,
# clustering_model.py and autoencoder_model.py, scores the domain-grouped test
# split from split_by_domain() with each, and applies the same metrics to all
# of them (evaluate(), per_class_table(), per_source_table()). A model whose
# file is missing is skipped. Nothing is refitted.
#
# Writes data/analysis/model_comparison.md,
# data/analysis/plots/model_comparison.png and
# data/analysis/plots/model_pr_curves.png.
import time

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve

import autoencoder_model
import clustering_model
from train_model import (
    ANALYSIS_DIR,
    BASELINE,
    INK_MUTED,
    INK_SECONDARY,
    MODELS_DIR,
    PROCESSED_DIR,
    SURFACE,
    TARGET_FPR,
    THRESHOLD,
    build_matrix,
    evaluate,
    log,
    per_class_table,
    per_source_table,
    positive_proba,
    savefig,
    split_by_domain,
    thin,
)

# (file stem in models/, display name, family)
MODELS = [
    ("lightgbm", "LightGBM", "Supervised"),
    ("logreg", "Logistic Regression", "Supervised"),
    ("char_ngram", "Char n-gram + LogReg", "Supervised"),
    ("kmeans", "K-Means", "Clustering"),
    ("hdbscan", "HDBSCAN", "Clustering"),
    ("autoencoder", "Autoencoder", "Anomaly detection"),
]
# Categorical slots 1-3 of the chart palette (validated all-pairs, light mode).
FAMILY_COLORS = {"Supervised": "#2a78d6", "Clustering": "#eb6834",
                 "Anomaly detection": "#1baf7a"}
# One color per model for the precision-recall curves: slots 1-6 in MODELS
# order (validated adjacent pairs, light mode), so a model keeps its color
# whichever models are present. LightGBM and Logistic Regression match their
# colors in train_model.py's curves. Slots 3-5 are below 3:1 contrast on the
# surface, so the legend names every line and the report has the table.
MODEL_COLORS = {"LightGBM": "#2a78d6", "Logistic Regression": "#eb6834",
                "Char n-gram + LogReg": "#1baf7a", "K-Means": "#eda100",
                "HDBSCAN": "#e87ba4", "Autoencoder": "#008300"}
# (column, panel title, higher is better)
PLOT_METRICS = [
    ("pr_auc", "PR-AUC", True),
    ("roc_auc", "ROC-AUC", True),
    ("f1", "F1, phishing class", True),
    ("mcc", "MCC", True),
    ("rmse", "RMSE", False),
    ("log_loss", "Log loss", False),
]
HIGHER_IS_BETTER = ["precision", "recall", "f1", "accuracy", "specificity",
                    "balanced_accuracy", "mcc", "roc_auc", "pr_auc", "recall_at_1pct_fpr",
                    "macro_f1"]
LOWER_IS_BETTER = ["mae", "mse_brier", "rmse", "log_loss"]


def score(stem: str, bundle: dict, test: pd.DataFrame) -> np.ndarray:
    if stem == "char_ngram":
        return positive_proba(bundle["model"], test["url"])
    if stem in ("kmeans", "hdbscan"):
        return clustering_model.bundle_proba(bundle, test)
    if stem == "autoencoder":
        return autoencoder_model.bundle_proba(bundle, test)
    X = build_matrix(test, bundle["feature_columns"], bundle["tld_categories"])
    return positive_proba(bundle["model"], X)


def plot_comparison(results: pd.DataFrame) -> None:
    # Same model order in every panel (best PR-AUC on top), so a row can be
    # followed across panels; color marks the model family.
    order = results.index[::-1]
    colors = [FAMILY_COLORS[f] for f in results.loc[order, "family"]]
    fig, axes = plt.subplots(2, 3, figsize=(13, 6.5), sharey=True)
    for ax, (col, title, higher) in zip(axes.flat, PLOT_METRICS):
        values = results.loc[order, col].astype(float).to_numpy()
        ax.barh(order, values, height=0.7, color=colors)
        for y, value in enumerate(values):
            ax.text(value, y, f" {value:.3f}", va="center", color=INK_SECONDARY, fontsize=8)
        ax.grid(axis="y", visible=False)
        ax.tick_params(axis="y", length=0)
        if higher:  # bounded by 1; the extra room is for the value labels
            ax.set_xlim(min(0.0, values.min()), 1.15)
            ax.set_xticks(np.arange(0, 1.01, 0.2))
        else:
            ax.set_xlim(0, values.max() * 1.2)
        ax.set_title(f"{title} ({'higher' if higher else 'lower'} is better)", fontsize=10)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for c in FAMILY_COLORS.values()]
    fig.legend(handles, FAMILY_COLORS.keys(), loc="lower center", ncol=3,
               bbox_to_anchor=(0.5, -0.03))
    fig.suptitle("Model comparison on the test split", fontsize=13, fontweight="semibold")
    fig.tight_layout()
    savefig(fig, "model_comparison.png")


def plot_pr_curves(y_test: pd.Series, probas: dict, results: pd.DataFrame) -> None:
    # Every model's precision-recall curve on one axis. The legend follows
    # `results` (best PR-AUC first) so it reads as a ranking; a dot marks where
    # each model sits at THRESHOLD. Steps rather than straight segments, since
    # PR-AUC (average precision) is the area under the step curve - straight
    # lines would overstate the clustering models, which have few distinct scores.
    fig, ax = plt.subplots(figsize=(10, 5.5))
    lowest = 1.0
    for name in results.index:
        precision, recall, _ = precision_recall_curve(y_test, probas[name])
        lowest = min(lowest, precision.min())
        recall, precision = thin(recall, precision)
        color = MODEL_COLORS[name]
        ax.plot(recall, precision, color=color, linewidth=2, drawstyle="steps-post",
                label=f"{name} (PR-AUC {results.loc[name, 'pr_auc']:.3f})")
        ax.plot(results.loc[name, "recall"], results.loc[name, "precision"], "o", color=color,
                markersize=7, markeredgecolor=SURFACE, markeredgewidth=1.5, zorder=3)

    chance = y_test.mean()
    ax.axhline(chance, color=BASELINE, linewidth=1, linestyle="--",
               label=f"Chance ({chance:.2f} = phishing share)")
    ax.plot([], [], "o", color=INK_MUTED, markersize=7, label=f"Threshold {THRESHOLD}")
    # Precision never falls far below the phishing share, so the y-axis starts
    # at the lowest tenth any curve reaches instead of 0.
    ax.set(title="Precision-recall curves (test split)", xlabel="Recall", ylabel="Precision",
           xlim=(0, 1), ylim=(np.floor(min(lowest, chance) * 10) / 10, 1.01))
    # Outside the axes: a weak model's curve can cross any corner of the plot.
    ax.legend(loc="upper left", bbox_to_anchor=(1.02, 1))
    savefig(fig, "model_pr_curves.png")


def main() -> None:
    start = time.perf_counter()
    df = pd.read_parquet(PROCESSED_DIR / "features.parquet")
    _, test = split_by_domain(df)
    del df
    log(f"Test split: {len(test)} rows", start)

    rows, macro, by_source_f1, probas, skipped = {}, {}, {}, {}, []
    for stem, name, family in MODELS:
        path = MODELS_DIR / f"{stem}.joblib"
        if not path.exists():
            skipped.append(stem)
            print(f"skipping {name}: {path} not found")
            continue
        proba = score(stem, joblib.load(path), test)
        probas[name] = proba
        rows[name] = {"family": family, **evaluate(test["label"], proba)}
        macro[name] = per_class_table(test["label"], proba).loc["macro avg", "f1"]
        by_source_f1[name] = per_source_table(test, proba)["f1"]
        log(f"Scored {name}", start)

    results = pd.DataFrame(rows).T
    results.insert(results.columns.get_loc("f1") + 1, "macro_f1", pd.Series(macro))
    results = results.sort_values("pr_auc", ascending=False)
    metrics = results.drop(columns="family").astype(float)
    ranks = pd.concat([metrics[HIGHER_IS_BETTER].rank(ascending=False),
                       metrics[LOWER_IS_BETTER].rank(ascending=True)], axis=1)
    results.insert(1, "mean_rank", ranks.mean(axis=1))
    by_source = pd.DataFrame(by_source_f1).T.loc[results.index]

    print()
    print(results.to_string(float_format="{:.4f}".format))
    print()
    print(by_source.to_string(float_format="{:.4f}".format))
    plot_comparison(results)
    plot_pr_curves(test["label"], probas, results)

    best = {col: metrics[col].idxmax() for col in HIGHER_IS_BETTER}
    best |= {col: metrics[col].idxmin() for col in LOWER_IS_BETTER}
    top = results.index[0]
    families = results.groupby("family")["pr_auc"].idxmax()

    report = [
        "# Model Comparison - Phishing URL Detector\n",
        "Source: `scripts/compare_models.py`. Every saved model scored on the same "
        f"domain-grouped test split ({len(test)} rows, phishing share "
        f"{test['label'].mean():.2%}) with the same metrics.\n",
        "## Summary of findings\n",
        f"- Best by PR-AUC: {top} ({results.loc[top, 'pr_auc']:.4f}), also best mean rank "
        f"across all metrics: {results['mean_rank'].astype(float).idxmin()}.",
        "- Best of each family by PR-AUC: " + "; ".join(
            f"{family}: {name} ({results.loc[name, 'pr_auc']:.4f})"
            for family, name in families.items()) + ".",
    ]
    winners = pd.Series(best).groupby(pd.Series(best)).groups
    if len(winners) == 1:
        report.append(f"- {next(iter(winners))} is best on all {len(best)} metrics.")
    else:
        report.append("- Best per metric: " + "; ".join(
            f"{name}: " + ", ".join(f"`{col}`" for col in cols)
            for name, cols in winners.items()) + ".")
    if skipped:
        report.append("- Not found and skipped: " + ", ".join(f"`{s}`" for s in skipped) + ".")
    report[-1] += "\n"
    report += [
        "## Models\n",
        "| Model | Family | Input | Trained by |",
        "|---|---|---|---|",
        "| LightGBM | Supervised | 21 URL features incl. `tld` | `train_model.py` |",
        "| Logistic Regression | Supervised | 21 URL features incl. `tld` | `train_model.py` |",
        "| Char n-gram + LogReg | Supervised | raw URL, 3-5 char n-grams | "
        "`train_char_ngram.py` |",
        "| K-Means | Clustering (label used only to score clusters) | 20 numeric URL "
        "features | `clustering_model.py` |",
        "| HDBSCAN | Clustering (label used only to score clusters) | 20 numeric URL "
        "features | `clustering_model.py` |",
        "| Autoencoder | Anomaly detection (trained on legitimate URLs only) | 20 numeric URL "
        "features | `autoencoder_model.py` |",
        "",
        "## Test results\n",
        f"Sorted by PR-AUC. Threshold-based metrics use each model's probability at "
        f"{THRESHOLD}; `precision`, `recall` and `f1` are for the phishing class, `macro_f1` "
        "averages F1 over both classes. `recall_at_1pct_fpr` is the share of phishing URLs "
        f"caught when {TARGET_FPR:.0%} of legitimate URLs are flagged. `mae`, `mse_brier`, "
        "`rmse` and `log_loss` measure the probability error (lower is better). `mean_rank` "
        "is the model's average rank over all metrics (1 = best).\n",
        results.to_markdown(floatfmt=".4f"),
        "",
        "## F1 by source (test split)\n",
        "Sources have very different phishing shares, so compare models within a column, "
        "not across columns.\n",
        by_source.to_markdown(floatfmt=".4f"),
        "",
        "## Plots\n",
        "![Model comparison](plots/model_comparison.png)\n",
        "Precision-recall curve of every model on the test split. PR-AUC is the area under "
        f"each curve; dots mark each model's operating point at threshold {THRESHOLD}, and the "
        "dashed line is the precision of a random model (the phishing share).\n",
        "![Precision-recall curves](plots/model_pr_curves.png)\n",
        "## Caveats\n",
        "- The families answer different questions. The supervised models learn the label "
        "directly; the clustering and autoencoder models learn structure without it and only "
        "borrow the label to turn clusters or reconstruction errors into probabilities. "
        "Lower scores for them are expected, not a tuning failure.",
        "- All models are scored on the same test split, but it comes from the same four "
        "overlapping sources as train (see `model_report.md`).",
        "",
    ]
    report_path = ANALYSIS_DIR / "model_comparison.md"
    report_path.write_text("\n".join(report), encoding="utf-8")
    print(f"saved {report_path}")
    log("Done", start)


if __name__ == "__main__":
    main()
