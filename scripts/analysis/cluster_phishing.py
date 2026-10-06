# Clusters the phishing training rows (K-Means on 20 log1p + scaled URL features) to
# find kinds of phishing URL. K is picked by silhouette, without using labels.
# Each cluster is described by feature z-scores, example URLs, and features not used
# for clustering (TLD, brand score, source). Test legit URLs are assigned to the
# nearest cluster to show how phishing-specific each one is.
# Writes data/analysis/phishing_clusters.json and phishing_cluster_samples.csv
import json
import time

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.metrics import adjusted_rand_score, davies_bouldin_score, silhouette_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

import sys
from pathlib import Path

# Scripts import each other from scripts/, one level up.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from clustering_model import numeric_feature_columns
from train_model import ANALYSIS_DIR, PROCESSED_DIR, RANDOM_STATE, log, split_by_domain

# Candidate K values; silhouette is scored on a SIL_SAMPLE-row subsample for speed.
K_GRID = [2, 3, 4, 5, 6, 7, 8, 10, 12]
SIL_SAMPLE = 20_000
N_EXAMPLES = 4
DESCRIBE = ["url_length", "hostname_length", "path_length", "query_length", "dot_count", "hyphen_count",
            "digit_count", "digit_ratio", "subdomain_count", "path_depth", "suspicious_keyword_count",
            "hostname_entropy", "is_ip_hostname", "has_port", "has_punycode", "percent_count",
            "equals_count", "ampersand_count", "at_count", "underscore_count"]


def main() -> None:
    """Fit, choose K, check stability, describe clusters and write outputs."""
    start = time.perf_counter()
    df = pd.read_parquet(PROCESSED_DIR / "features.parquet")
    train, test = split_by_domain(df)
    phish = train[train["label"] == 1].reset_index(drop=True)
    cols = [c for c in numeric_feature_columns(df) if c not in ("brand_similarity_score", "is_exact_brand_match")]
    assert len(cols) == 20, cols
    prep = Pipeline([("log1p", FunctionTransformer(np.log1p)), ("scale", StandardScaler())]).fit(phish[cols])
    X = prep.transform(phish[cols])
    log(f"{len(phish)} phishing train rows, {len(cols)} features", start)

    rng = np.random.RandomState(RANDOM_STATE)
    sample = rng.choice(len(X), SIL_SAMPLE, replace=False)
    rows = []
    for k in K_GRID:
        km = KMeans(n_clusters=k, n_init=3, random_state=RANDOM_STATE).fit(X)
        lab = km.predict(X[sample])
        rows.append({"k": k, "silhouette": float(silhouette_score(X[sample], lab)),
                     "davies_bouldin": float(davies_bouldin_score(X[sample], lab)), "inertia": float(km.inertia_)})
        log(f"k={k}: silhouette {rows[-1]['silhouette']:.3f}, DB {rows[-1]['davies_bouldin']:.3f}", start)
    grid = pd.DataFrame(rows)
    # Best silhouette among K >= 4 (K = 2 or 3 only splits by overall size).
    k = int(grid[grid["k"] >= 4].sort_values("silhouette", ascending=False).iloc[0]["k"])
    km = KMeans(n_clusters=k, n_init=10, random_state=RANDOM_STATE).fit(X)
    phish["cluster"] = km.predict(X)

    # Stability: refit with other seeds and compare assignments.
    aris, jaccard = [], {c: [] for c in range(k)}
    for seed in (1, 2, 3):
        other = KMeans(n_clusters=k, n_init=10, random_state=seed).fit(X).predict(X)
        aris.append(float(adjusted_rand_score(phish["cluster"], other)))
        for c in range(k):
            mine = (phish["cluster"] == c).to_numpy()
            # best Jaccard overlap with any refit cluster
            jaccard[c].append(max(float((mine & (other == o)).sum() / (mine | (other == o)).sum())
                                  for o in range(k)))

    Z = pd.DataFrame(X, columns=cols)
    Z["cluster"] = phish["cluster"]
    z_mean = Z.groupby("cluster")[cols].mean()          # cluster mean in overall std units
    raw_median = phish.groupby("cluster")[cols].median()
    raw_mean = phish.groupby("cluster")[cols].mean()
    overall_mean = phish[cols].mean()
    overall_median = phish[cols].median()
    out = {"k": k, "grid": grid.to_dict("records"), "stability_ari": aris, "n_rows": len(phish), "clusters": {}}

    # Held-out check: assign all test URLs to the nearest phishing cluster.
    Xt = prep.transform(test[cols])
    test = test.assign(cluster=km.predict(Xt))
    for c in range(k):
        g = phish[phish["cluster"] == c]
        top = z_mean.loc[c].abs().sort_values(ascending=False).index[:3].tolist()
        ex = g.sample(N_EXAMPLES, random_state=RANDOM_STATE)["url"].str.slice(0, 90).tolist()
        t = test[test["cluster"] == c]
        out["clusters"][int(c)] = {
            "stability_jaccard": [round(j, 3) for j in jaccard[c]],
            "rows": int(len(g)), "share": float(len(g) / len(phish)),
            "label_phishing_share_fit": 1.0,
            "top_features": [{"feature": f, "z": float(z_mean.loc[c, f]),
                              "cluster_mean": float(raw_mean.loc[c, f]), "overall_mean": float(overall_mean[f]),
                              "cluster_median": float(raw_median.loc[c, f]), "overall_median": float(overall_median[f])}
                             for f in top],
            "source_share": g["source"].value_counts(normalize=True).round(3).to_dict(),
            "top_tld": g["tld"].replace("", "(none)").value_counts(normalize=True).head(5).round(3).to_dict(),
            "brand_sim_mean": float(g["brand_similarity_score"].mean()),
            "exact_brand_share": float(g["is_exact_brand_match"].mean()),
            "kw_share": float((g["suspicious_keyword_count"] > 0).mean()),
            "test_rows": int(len(t)), "test_phishing_share": float(t["label"].mean()),
            "test_legit_share_of_all_legit": float(((t["label"] == 0).sum()) / (test["label"] == 0).sum()),
            "examples": ex,
            "feature_z": {f: float(z_mean.loc[c, f]) for f in cols},
            "raw_medians": {f: float(raw_median.loc[c, f]) for f in cols},
        }
    out["test_overall_phishing_share"] = float(test["label"].mean())
    json.dump(out, open(ANALYSIS_DIR / "phishing_clusters.json", "w"), indent=1)
    phish[["url", "source", "cluster"]].sample(2000, random_state=1).to_csv(ANALYSIS_DIR / "phishing_cluster_samples.csv", index=False)
    print(grid.round(3).to_string(index=False)); print("chosen k", k, "ARI", aris)
    for c, d in out["clusters"].items():
        print(f"\n--- cluster {c}: {d['rows']} rows ({d['share']:.1%}); test phishing share {d['test_phishing_share']:.2f} "
              f"(legit share of all legit {d['test_legit_share_of_all_legit']:.1%})")
        for f in d["top_features"]:
            print(f"   {f['feature']:<26} z={f['z']:+.2f}  median {f['cluster_median']:.2f} vs {f['overall_median']:.2f}  mean {f['cluster_mean']:.2f} vs {f['overall_mean']:.2f}")
        print("   sources", d["source_share"], "tld", d["top_tld"], "brand_sim", round(d["brand_sim_mean"], 3), "kw", round(d["kw_share"], 3))
        print("   stability (best Jaccard in 3 refits):", d["stability_jaccard"])
        for u in d["examples"]: print("     ", u)


if __name__ == "__main__":
    main()
