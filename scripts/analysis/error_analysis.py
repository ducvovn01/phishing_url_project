# Error analysis of the char n-gram + Logistic Regression model on the test split:
# confusion counts, error rates by source / TLD / URL shape, and random samples of
# false positives and negatives (random, so representative of errors in general).
# Writes data/analysis/error_analysis.json and error_samples.csv
import json
import sys

import joblib
import numpy as np
import pandas as pd

from pathlib import Path

# Scripts import each other from scripts/, one level up.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from train_model import ANALYSIS_DIR, MODELS_DIR, PROCESSED_DIR, THRESHOLD, positive_proba, split_by_domain

SAMPLE_SIZE = 40
SEED = 7


def main() -> None:
    """Score the test split and write error statistics and sampled errors."""
    df = pd.read_parquet(PROCESSED_DIR / "features.parquet")
    _, test = split_by_domain(df)
    bundle = joblib.load(MODELS_DIR / "char_ngram.joblib")
    proba = positive_proba(bundle["model"], test["url"])
    test = test.assign(proba=proba, pred=(proba >= THRESHOLD).astype(int))
    fp = test[(test.label == 0) & (test.pred == 1)]
    fn = test[(test.label == 1) & (test.pred == 0)]
    tp = int(((test.label == 1) & (test.pred == 1)).sum())
    tn = int(((test.label == 0) & (test.pred == 0)).sum())
    out = {"tp": tp, "tn": tn, "fp": len(fp), "fn": len(fn), "n": len(test)}

    # Error rate by source, for each class.
    by_source = {}
    for s, g in test.groupby("source"):
        leg, phi = g[g.label == 0], g[g.label == 1]
        by_source[s] = {
            "legit_rows": len(leg), "fp_rate": float((leg.pred == 1).mean()) if len(leg) else None,
            "phish_rows": len(phi), "fn_rate": float((phi.pred == 0).mean()) if len(phi) else None,
        }
    out["by_source"] = by_source

    # Boolean URL-shape flags, to see what mistakes have in common.
    def shape(d: pd.DataFrame) -> pd.DataFrame:
        """Return boolean shape flags for each row of d."""
        u = d["url"].str.lower()
        return pd.DataFrame({
            "has_path": d["path_length"] > 1,
            "has_query": d["query_length"] > 0,
            "starts_www": u.str.startswith("www."),
            "short_host": d["hostname_length"] <= 12,
            "ip_host": d["is_ip_hostname"] == 1,
            "has_digits": d["digit_count"] > 0,
            "long_url": d["url_length"] > 75,
            "com_tld": d["tld"] == "com",
        })
    shapes = {}
    for name, grp in (("all_legit", test[test.label == 0]), ("fp", fp), ("all_phish", test[test.label == 1]), ("fn", fn)):
        shapes[name] = {k: float(v.mean()) for k, v in shape(grp).items()}
    out["shapes"] = shapes
    out["fp_top_tld"] = fp["tld"].value_counts(normalize=True).head(8).round(4).to_dict()
    out["fn_top_tld"] = fn["tld"].value_counts(normalize=True).head(8).round(4).to_dict()
    out["legit_top_tld"] = test[test.label == 0]["tld"].value_counts(normalize=True).head(8).round(4).to_dict()
    out["phish_top_tld"] = test[test.label == 1]["tld"].value_counts(normalize=True).head(8).round(4).to_dict()
    # How confident are the mistakes?
    out["fp_proba_quantiles"] = fp["proba"].quantile([.1, .5, .9]).round(3).tolist()
    out["fn_proba_quantiles"] = fn["proba"].quantile([.1, .5, .9]).round(3).tolist()
    # Do mistakes concentrate on a few domains (e.g. hosting platforms)?
    out["fp_top_domains"] = fp["domain"].value_counts().head(8).to_dict()
    out["fn_top_domains"] = fn["domain"].value_counts().head(8).to_dict()
    out["fp_domains_distinct"] = int(fp["domain"].nunique())
    out["fn_domains_distinct"] = int(fn["domain"].nunique())
    # Brand features among errors.
    out["fp_brand_match_share"] = float((fp["is_exact_brand_match"] == 1).mean())
    out["fn_brand_sim_ge_085"] = float((fn["brand_similarity_score"] >= 0.85).mean())

    s_fp = fp.sample(SAMPLE_SIZE, random_state=SEED)[["url", "source", "proba"]].assign(error="false_positive")
    s_fn = fn.sample(SAMPLE_SIZE, random_state=SEED)[["url", "source", "proba"]].assign(error="false_negative")
    pd.concat([s_fp, s_fn]).to_csv(ANALYSIS_DIR / "error_samples.csv", index=False)
    json.dump(out, open(ANALYSIS_DIR / "error_analysis.json", "w"), indent=1, default=str)
    print(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()
