"""Build backend/app/data/rule_stats.json from the A2 feature table.

The rule signals in app/services/rules.py quote these numbers in their explanations, so
every claim they make ("x% of such URLs in the A2 dataset were phishing") is a count from
data/processed/features.parquet rather than a hand-written figure. The API reads only the
JSON at runtime; this script is re-run only when the A2 dataset changes.

Run from the project root:
    backend/.venv/Scripts/python backend/scripts/build_rule_stats.py   (Windows)
    backend/.venv/bin/python backend/scripts/build_rule_stats.py       (macOS/Linux)
"""
import json
import sys
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from extract_features import _BRAND_SET, normalize_homoglyphs, normalize_leetspeak  # noqa: E402

FEATURES = PROJECT_ROOT / "data" / "processed" / "features.parquet"
OUT = PROJECT_ROOT / "backend" / "app" / "data" / "rule_stats.json"

# A suffix counts as "common in phishing data" only with enough rows to mean something
# and a phishing share well above the dataset's 51% base rate.
TLD_MIN_ROWS = 1000
TLD_MIN_PHISHING_SHARE = 0.95
# Long-URL rule: longer than this quantile of legitimate URLs (url_length excludes the scheme).
LONG_URL_LEGIT_QUANTILE = 0.99
# Look-alike labels shorter than this are mostly accidental ("0k", "r7"; see model_report.md
# on short labels and fuzzy scores), so the rule ignores them.
LOOKALIKE_MIN_LABEL_LENGTH = 5


def domain_label(domain: str, suffix: str) -> str:
    """Registrable domain without its public suffix ("paypa1.com" -> "paypa1")."""
    if suffix and domain.endswith("." + suffix):
        return domain[: -(len(suffix) + 1)]
    return domain


def is_lookalike(label: str) -> bool:
    """Same test as rules.brand_lookalike(): not a brand itself, but one after undoing swaps."""
    if len(label) < LOOKALIKE_MIN_LABEL_LENGTH or label in _BRAND_SET:
        return False
    normalized = normalize_leetspeak(normalize_homoglyphs(label))
    return normalized != label and normalized in _BRAND_SET


def share(rows: pd.Series) -> dict:
    """Row count and phishing share of a boolean mask over the dataset."""
    return {"rows": int(rows.sum()), "phishing_share": round(float(LABELS[rows].mean()), 4)}


df = pd.read_parquet(FEATURES, columns=["label", "tld", "domain", "url_length",
                                        "is_ip_hostname", "has_punycode"])
LABELS = df["label"]

tld = df[df["tld"] != ""].groupby("tld")["label"].agg(["size", "mean"])
tld = tld[(tld["size"] >= TLD_MIN_ROWS) & (tld["mean"] >= TLD_MIN_PHISHING_SHARE)]

long_cutoff = int(df.loc[df["label"] == 0, "url_length"].quantile(LONG_URL_LEGIT_QUANTILE))

labels = pd.Series([domain_label(d, t) for d, t in zip(df["domain"], df["tld"])], index=df.index)
lookalike_labels = {lab for lab in labels.unique() if is_lookalike(lab)}

stats = {
    "source": "data/processed/features.parquet (A2 combined dataset, train and test rows)",
    "rows": len(df),
    "phishing_share": round(float(LABELS.mean()), 4),
    "ip_host": share(df["is_ip_hostname"] == 1),
    "punycode_host": share(df["has_punycode"] == 1),
    "long_url": {
        "legit_quantile": LONG_URL_LEGIT_QUANTILE,
        "max_typical_length": long_cutoff,
        **share(df["url_length"] > long_cutoff),
    },
    "tld": {
        "min_rows": TLD_MIN_ROWS,
        "min_phishing_share": TLD_MIN_PHISHING_SHARE,
        "suffixes": {s: {"rows": int(r["size"]), "phishing_share": round(float(r["mean"]), 4)}
                     for s, r in tld.sort_index().iterrows()},
    },
    "brand_lookalike": {
        "min_label_length": LOOKALIKE_MIN_LABEL_LENGTH,
        **share(labels.isin(lookalike_labels)),
    },
}

OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps(stats, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(f"wrote {OUT.relative_to(PROJECT_ROOT)}: {len(stats['tld']['suffixes'])} suffixes, "
      f"long URL > {long_cutoff} chars")
