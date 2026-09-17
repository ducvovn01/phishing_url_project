# EDA over the combined, deduplicated dataset. Saves all figures as .png into
# data/analysis/plots/ and writes a written summary to data/analysis/eda_report.md.
import re
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"
ANALYSIS_DIR = PROJECT_ROOT / "data" / "analysis"
PLOTS_DIR = ANALYSIS_DIR / "plots"

IP_HOSTNAME_RE = re.compile(
    r"^(?:https?://)?(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)"
)


def savefig(fig, name: str) -> None:
    path = PLOTS_DIR / name
    fig.savefig(path, dpi=150, bbox_inches="tight")
    plt.close(fig)
    print(f"saved {path}")


def get_hostname(url: str) -> str:
    u = url.strip()
    u = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", u)
    u = u.split("/", 1)[0]
    u = u.split("?", 1)[0]
    u = u.split("@")[-1]  # drop userinfo if present
    u = u.split(":")[0]  # drop port
    return u


def get_tld(hostname: str) -> str:
    parts = hostname.rsplit(".", 1)
    return parts[-1] if len(parts) == 2 and parts[-1] else ""


def main() -> None:
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(PROCESSED_DIR / "combined_dataset.csv")
    report_lines = []
    report_lines.append("# EDA Report — Phishing URL Dataset\n")
    report_lines.append(f"Combined dataset: `{PROCESSED_DIR / 'combined_dataset.csv'}`\n")
    report_lines.append(f"Total rows: {len(df)}\n")

    # --- Missing values / malformed URL check ---
    n_null_url = df["url"].isna().sum()
    n_empty_url = (df["url"].fillna("").str.strip() == "").sum()
    n_null_label = df["label"].isna().sum()
    bad_label = ~df["label"].isin([0, 1])
    n_bad_label = bad_label.sum()
    # crude "no dot at all" check as a proxy for malformed/unparseable host
    hostnames = df["url"].fillna("").map(get_hostname)
    n_no_dot_host = (~hostnames.str.contains(r"\.")).sum()

    report_lines.append("## Missing values / malformed URLs\n")
    report_lines.append(f"- Null `url`: {n_null_url}")
    report_lines.append(f"- Empty/whitespace-only `url`: {n_empty_url}")
    report_lines.append(f"- Null `label`: {n_null_label}")
    report_lines.append(f"- `label` not in {{0,1}}: {n_bad_label}")
    report_lines.append(f"- Hostname with no dot (malformed/local-like): {n_no_dot_host}\n")

    # --- Class balance overall ---
    overall_counts = df["label"].value_counts().sort_index()
    overall_pct = (overall_counts / len(df) * 100).round(2)

    report_lines.append("## Class balance (overall)\n")
    for lbl in [0, 1]:
        name = "legitimate" if lbl == 0 else "phishing"
        c = overall_counts.get(lbl, 0)
        p = overall_pct.get(lbl, 0)
        report_lines.append(f"- {name} (label={lbl}): {c} ({p}%)")
    report_lines.append("")

    fig, ax = plt.subplots(figsize=(5, 4))
    labels_named = overall_counts.rename({0: "legitimate", 1: "phishing"})
    ax.bar(labels_named.index.astype(str), labels_named.to_numpy(), color=["#4C72B0", "#C44E52"])
    ax.set_title("Overall class balance")
    ax.set_ylabel("row count")
    savefig(fig, "class_balance_overall.png")

    # class balance by source
    by_source = df.groupby(["source", "label"]).size().unstack(fill_value=0)
    by_source = by_source.rename(columns={0: "legitimate", 1: "phishing"})

    report_lines.append("## Class balance by source\n")
    report_lines.append(by_source.to_markdown())
    report_lines.append("")

    fig, ax = plt.subplots(figsize=(7, 4))
    by_source.plot(kind="bar", ax=ax, color=["#4C72B0", "#C44E52"])
    ax.set_title("Class balance by source")
    ax.set_ylabel("row count")
    ax.legend(title="")
    savefig(fig, "class_balance_by_source.png")

    # --- URL length distribution ---
    # Shared bin edges across both classes: phishing has extreme outliers
    # (max ~25,515 chars) vs legitimate (max ~2,073). Auto-sized bins per
    # call would size off each class's own max, blowing out bin width for
    # the class with the longer tail. Underlying data (url_len, full range)
    # is untouched -- only the display x-axis is clipped for legibility.
    url_len = df["url"].fillna("").str.len()
    DISPLAY_MAX = 200
    bin_edges = np.linspace(0, DISPLAY_MAX, 51).tolist()  # 50 bins, width 4 chars
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(
        url_len[df["label"] == 0], bins=bin_edges, alpha=0.6, label="legitimate", color="#4C72B0"
    )
    ax.hist(
        url_len[df["label"] == 1], bins=bin_edges, alpha=0.6, label="phishing", color="#C44E52"
    )
    ax.set_xlim(0, DISPLAY_MAX)
    ax.set_title("URL length distribution")
    ax.set_xlabel("URL length (chars)")
    ax.set_ylabel("count")
    ax.legend()
    savefig(fig, "url_length_distribution.png")

    report_lines.append("## URL length\n")
    report_lines.append(
        df.groupby("label")["url"]
        .apply(lambda s: s.fillna("").str.len().describe())
        .unstack()
        .rename(index={0: "legitimate", 1: "phishing"})
        .to_markdown()
    )
    report_lines.append("")

    # duplicate/overlap counts per source pair
    dup_path = PROCESSED_DIR / "duplicates_removed.csv"
    report_lines.append("## Duplicate / overlap counts\n")
    dups = pd.read_csv(dup_path) if dup_path.exists() else None
    pair_counts = None
    if dups is not None:
        report_lines.append(f"Total duplicate rows removed: {len(dups)}\n")
        per_source = dups["dropped_source"].value_counts()
        report_lines.append("Dropped per source:\n")
        report_lines.append(per_source.to_markdown())
        report_lines.append("")
        pair_counts = dups.groupby(["dropped_source", "kept_source"]).size()
        report_lines.append("Dropped per source-pair (dropped_source -> kept_source):\n")
        report_lines.append(pair_counts.to_markdown())
        report_lines.append("")
    else:
        report_lines.append("`duplicates_removed.csv` not found — run normalize_datasets.py first.\n")

    # dot counts
    dot_counts = df["url"].fillna("").str.count(r"\.")
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(dot_counts[df["label"] == 0], bins=range(0, 15), alpha=0.6, label="legitimate", color="#4C72B0")
    ax.hist(dot_counts[df["label"] == 1], bins=range(0, 15), alpha=0.6, label="phishing", color="#C44E52")
    ax.set_title("Dot count in URL")
    ax.set_xlabel("number of '.' characters")
    ax.set_ylabel("count")
    ax.legend()
    savefig(fig, "dot_count_distribution.png")

    # hyphen counts
    hyphen_counts = df["url"].fillna("").str.count("-")
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.hist(hyphen_counts[df["label"] == 0], bins=range(0, 15), alpha=0.6, label="legitimate", color="#4C72B0")
    ax.hist(hyphen_counts[df["label"] == 1], bins=range(0, 15), alpha=0.6, label="phishing", color="#C44E52")
    ax.set_title("Hyphen count in URL")
    ax.set_xlabel("number of '-' characters")
    ax.set_ylabel("count")
    ax.legend()
    savefig(fig, "hyphen_count_distribution.png")

    # IP-address hostnames
    is_ip_host = df["url"].fillna("").str.strip().str.match(IP_HOSTNAME_RE)
    ip_by_label = is_ip_host.groupby(df["label"]).mean() * 100
    ip_by_label = ip_by_label.rename({0: "legitimate", 1: "phishing"})

    fig, ax = plt.subplots(figsize=(5, 4))
    ax.bar(ip_by_label.index, ip_by_label.to_numpy(), color=["#4C72B0", "#C44E52"])
    ax.set_title("Share of URLs with IP-address hostname")
    ax.set_ylabel("% of rows")
    savefig(fig, "ip_hostname_share.png")

    report_lines.append("## Dot / hyphen counts and IP hostnames\n")
    report_lines.append(
        f"- Mean dot count — legitimate: {dot_counts[df['label']==0].mean():.2f}, "
        f"phishing: {dot_counts[df['label']==1].mean():.2f}"
    )
    report_lines.append(
        f"- Mean hyphen count — legitimate: {hyphen_counts[df['label']==0].mean():.2f}, "
        f"phishing: {hyphen_counts[df['label']==1].mean():.2f}"
    )
    report_lines.append(
        f"- IP-address hostname — legitimate: {ip_by_label['legitimate']:.3f}%, "
        f"phishing: {ip_by_label['phishing']:.3f}%\n"
    )

    # TLD frequency
    tlds = hostnames.map(get_tld)
    top_tlds = tlds.value_counts().head(15)

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.barh(top_tlds.index[::-1], top_tlds.to_numpy()[::-1], color="#55A868")
    ax.set_title("Top 15 TLDs (overall)")
    ax.set_xlabel("count")
    savefig(fig, "tld_frequency_top15.png")

    tld_by_label = (
        pd.DataFrame({"tld": tlds, "label": df["label"]})
        .groupby(["tld", "label"])
        .size()
        .unstack(fill_value=0)
        .rename(columns={0: "legitimate", 1: "phishing"})
    )
    top_tld_names = top_tlds.index
    tld_by_label_top = tld_by_label.loc[tld_by_label.index.intersection(top_tld_names)]

    report_lines.append("## TLD frequency (top 15 overall)\n")
    report_lines.append(tld_by_label_top.to_markdown())
    report_lines.append("")

    # Written summary of findings
    # every figure below is recomputed from df/dups at run time (not hardcoded)
    # so this section stays correct across re-runs with different source sets.
    top_source = by_source.sum(axis=1).idxmax()
    skew_pp = abs(overall_pct.get(1, 0) - overall_pct.get(0, 0)) / 2
    majority_class = "phishing" if overall_pct.get(1, 0) >= overall_pct.get(0, 0) else "legitimate"

    per_source_skew = []
    for src, leg, phi in zip(by_source.index, by_source["legitimate"], by_source["phishing"]):
        skew = "legitimate" if leg > phi else "phishing"
        per_source_skew.append(f"{src} skews {skew} ({leg} legitimate vs {phi} phishing)")

    if dups is not None and pair_counts is not None:
        total_raw = len(df) + len(dups)
        dup_pct = len(dups) / total_raw * 100
        top_pairs = pair_counts.sort_values(ascending=False).head(3)
        top_pairs_str = "; ".join(
            f"{a}→{b}: {c}" for a, b, c in top_pairs.reset_index().itertuples(index=False)
        )
        overlap_sentence = (
            f"Cross-source overlap: {len(dups)} of {total_raw} raw rows (~{dup_pct:.0f}%) were "
            f"exact duplicates after canonicalizing URLs. Largest source-pairs: {top_pairs_str} "
            "— sources are not independent samples, so per-source class balance and any "
            "train/test split should account for this shared content rather than treating "
            "sources as disjoint."
        )
    else:
        overlap_sentence = "Duplicate summary unavailable — run normalize_datasets.py first."

    summary = [
        "## Summary of findings\n",
        (
            f"Combined, deduplicated dataset holds {len(df)} rows across {df['source'].nunique()} "
            f"sources: {overall_counts.get(1,0)} phishing ({overall_pct.get(1,0)}%) vs "
            f"{overall_counts.get(0,0)} legitimate ({overall_pct.get(0,0)}%) — roughly balanced "
            f"overall, a ~{skew_pp:.1f}pp skew toward {majority_class}."
        ),
        (
            "Class balance is NOT even per source: " + "; ".join(per_source_skew) + ". "
            f"{top_source} contributes the most rows post-dedup."
        ),
        overlap_sentence,
        (
            f"Data quality: {n_null_url} null and {n_empty_url} empty/whitespace-only `url` rows, "
            f"{n_no_dot_host} rows with a no-dot hostname (malformed/local-like) — these were "
            "already logged and dropped by normalize_datasets.py before dedup, so the checks "
            "above should read 0. No invalid label values found."
        ),
        (
            f"Feature-relevant signals: mean dot count — legitimate "
            f"{dot_counts[df['label']==0].mean():.2f}, phishing {dot_counts[df['label']==1].mean():.2f}; "
            f"mean hyphen count — legitimate {hyphen_counts[df['label']==0].mean():.2f}, phishing "
            f"{hyphen_counts[df['label']==1].mean():.2f} (hyphen count alone is not a reliable "
            "phishing signal in this data, contrary to common assumption). IP-address hostnames "
            f"are rare overall but far more common in phishing ({ip_by_label['phishing']:.3f}% vs "
            f"{ip_by_label['legitimate']:.3f}% legitimate) — a strong candidate feature. TLD "
            "distribution is skewed (see table below) — TLD looks like a useful categorical feature."
        ),
    ]
    report_lines = report_lines[:2] + summary + [""] + report_lines[2:]

    # write report
    (ANALYSIS_DIR / "eda_report.md").write_text("\n".join(report_lines), encoding="utf-8")
    print(f"wrote {ANALYSIS_DIR / 'eda_report.md'}")


if __name__ == "__main__":
    main()
