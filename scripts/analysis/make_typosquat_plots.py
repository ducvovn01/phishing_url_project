"""
Plot typosquat / brand-similarity charts from data/processed/features.parquet.

Usage: python scripts/analysis/make_typosquat_plots.py
Writes typosquat_precision_by_threshold.png, typosquat_precision_by_label_length.png
and typosquat_lift_by_source.png to data/analysis/plots/.

"Non-exact" rows have is_exact_brand_match == 0. "Label length" is the length of the
bare domain label (e.g. "paypal"), the string brand_similarity_score is computed on.
"""
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import tldextract

ROOT = Path(__file__).resolve().parent.parent.parent
FEATURES = ROOT / "data" / "processed" / "features.parquet"
OUT_DIR = ROOT / "data" / "analysis" / "plots"

BLUE, RED, GREY = "#4C72B0", "#C44E52", "#7F7F7F"

# Offline: use the bundled public suffix list, never fetch one.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())


def load() -> pd.DataFrame:
    """Load the feature columns and add domain_label and label_len."""
    df = pd.read_parquet(
        FEATURES,
        columns=["domain", "label", "source", "brand_similarity_score", "is_exact_brand_match"],
    )
    # float32 stores 0.70 as 0.69999999, which fails ">= 0.70"; cast and round first.
    df["brand_similarity_score"] = df["brand_similarity_score"].astype("float64").round(6)
    # Bare domain label, computed once per unique domain (many rows share one).
    uniq = df["domain"].fillna("").unique()
    label_of = {d: _EXTRACT(d).domain for d in uniq}
    df["domain_label"] = df["domain"].fillna("").map(label_of)
    df["label_len"] = df["domain_label"].str.len()
    return df


def plot_threshold(ne: pd.DataFrame) -> None:
    """Phishing share of non-exact rows flagged at each similarity threshold."""
    thresholds = np.round(np.arange(0.70, 0.96, 0.05), 2)
    shares, counts = [], []
    for t in thresholds:
        s = ne[ne["brand_similarity_score"] >= t]
        shares.append(s["label"].mean() * 100)
        counts.append(len(s))
    base = ne["label"].mean() * 100

    fig, ax = plt.subplots(figsize=(7, 4.2))
    ax.plot(thresholds, shares, marker="o", color=RED, label="Flagged rows")
    ax.axhline(base, color=GREY, linestyle="--", label=f"Base rate, all non-exact rows ({base:.1f}%)")
    for x, y, n in zip(thresholds, shares, counts):
        dy = -16 if y < base else 9  # keep labels clear of the base-rate line
        ax.annotate(f"n={n:,}", (x, y), textcoords="offset points", xytext=(0, dy),
                    ha="center", fontsize=8)
    ax.set_xlabel("Minimum brand_similarity_score")
    ax.set_ylabel("Phishing share of flagged rows (%)")
    ax.set_title("Precision of a similarity-threshold rule (non-exact matches)")
    ax.set_ylim(30, 95)
    ax.set_xticks(thresholds)
    ax.legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "typosquat_precision_by_threshold.png", dpi=200)
    plt.close(fig)


def plot_label_length(ne: pd.DataFrame, threshold: float = 0.85) -> None:
    """Phishing share by domain label length, all rows vs flagged rows."""
    bins = [0, 3, 5, 8, 12, 20, 10_000]
    names = ["1-3", "4-5", "6-8", "9-12", "13-20", "21+"]
    cut = pd.cut(ne["label_len"], bins=bins, labels=names)
    flagged = ne[ne["brand_similarity_score"] >= threshold]
    cut_f = pd.cut(flagged["label_len"], bins=bins, labels=names)

    base = ne.groupby(cut, observed=False)["label"].mean() * 100
    flag = flagged.groupby(cut_f, observed=False)["label"].mean() * 100
    flag_n = flagged.groupby(cut_f, observed=False).size()

    x = np.arange(len(names))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    ax.bar(x - w / 2, base.values, w, color=BLUE, label="All non-exact rows")
    ax.bar(x + w / 2, flag.values, w, color=RED, label=f"Rows with score >= {threshold}")
    for i, n in enumerate(flag_n.values):
        top = np.nanmax([base.values[i], flag.values[i]])
        label = "no rows flagged" if n == 0 else f"flagged n={n:,}"
        ax.text(x[i], top + 2, label, ha="center", fontsize=8, color=GREY if n == 0 else "black")
    ax.set_xticks(x)
    ax.set_xticklabels(names)
    ax.set_xlabel("Domain label length (characters)")
    ax.set_ylabel("Phishing share (%)")
    ax.set_title("A high similarity score only carries signal for longer labels")
    ax.set_ylim(0, 100)
    ax.legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "typosquat_precision_by_label_length.png", dpi=200)
    plt.close(fig)


def plot_source_lift(ne: pd.DataFrame, threshold: float = 0.85, min_len: int = 8) -> None:
    """Phishing share per source, all rows vs flagged rows (long labels only)."""
    sub = ne[ne["label_len"] >= min_len]
    flagged = sub[sub["brand_similarity_score"] >= threshold]
    sources = ["mitake", "harisudhan411", "phiusiil", "semihguner"]
    base = [sub[sub["source"] == s]["label"].mean() * 100 for s in sources]
    flag = [flagged[flagged["source"] == s]["label"].mean() * 100 for s in sources]
    flag_n = [int((flagged["source"] == s).sum()) for s in sources]

    x = np.arange(len(sources))
    w = 0.38
    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    ax.bar(x - w / 2, base, w, color=BLUE, label="All rows from source")
    ax.bar(x + w / 2, flag, w, color=RED, label=f"Rows with score >= {threshold}")
    for i, n in enumerate(flag_n):
        ax.text(x[i] + w / 2, flag[i] + 1.5, f"n={n:,}", ha="center", fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(sources)
    ax.set_ylabel("Phishing share (%)")
    ax.set_title(f"Lift from the score depends on the source (label length >= {min_len})")
    ax.set_ylim(0, 112)
    ax.legend(loc="upper left", fontsize=9)
    fig.tight_layout()
    fig.savefig(OUT_DIR / "typosquat_lift_by_source.png", dpi=200)
    plt.close(fig)


def main() -> None:
    """Load features and write the three charts."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df = load()
    ne = df[df["is_exact_brand_match"] == 0]
    print(f"{len(df):,} rows, {len(ne):,} non-exact, base phishing share {ne['label'].mean() * 100:.2f}%")
    plot_threshold(ne)
    plot_label_length(ne)
    plot_source_lift(ne)
    print(f"Wrote 3 charts to {OUT_DIR}")


if __name__ == "__main__":
    main()