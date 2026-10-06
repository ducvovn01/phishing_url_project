# Heatmap of each phishing cluster's mean feature value vs the overall phishing mean,
# in std devs (blue lower, red higher). Reads data/analysis/phishing_clusters.json,
# writes data/analysis/plots/phishing_cluster_profile.png
import json

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap

import sys
from pathlib import Path

# Scripts import each other from scripts/, one level up.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from train_model import ANALYSIS_DIR, PLOTS_DIR

# Hand-assigned cluster names, keyed by cluster id from cluster_phishing.py.
NAMES = {0: "Bare short host", 3: "Long path", 2: "Long query string", 1: "IP-address host"}
FEATURES = ["url_length", "hostname_length", "path_length", "path_depth", "query_length", "equals_count",
            "ampersand_count", "subdomain_count", "digit_ratio", "is_ip_hostname", "has_port",
            "suspicious_keyword_count"]
SURFACE, INK, INK2 = "#fcfcfb", "#0b0b0b", "#52514e"


def main() -> None:
    """Draw the cluster-by-feature z-score heatmap."""
    data = json.load(open(ANALYSIS_DIR / "phishing_clusters.json"))
    clusters = sorted(data["clusters"].items(), key=lambda kv: -kv[1]["rows"])
    Z = np.array([[d["feature_z"][f] for f in FEATURES] for _, d in clusters])
    cmap = LinearSegmentedColormap.from_list("div", ["#2a78d6", "#f0efec", "#d03b3b"])
    fig, ax = plt.subplots(figsize=(9.2, 3.6), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    im = ax.imshow(Z, cmap=cmap, vmin=-3, vmax=3, aspect="auto")
    ax.set_xticks(range(len(FEATURES)), [f.replace("_", " ") for f in FEATURES], rotation=35, ha="right", color=INK2, fontsize=9)
    ax.set_yticks(range(len(clusters)),
                  [f"{NAMES.get(int(c), 'Cluster ' + str(c))}\n{d['share']:.1%} of phishing" for c, d in clusters], color=INK, fontsize=9)
    for i in range(Z.shape[0]):
        for j in range(Z.shape[1]):
            ax.text(j, i, f"{Z[i, j] + 0.0:+.1f}".replace("-0.0", "+0.0"), ha="center", va="center", fontsize=8,
                    color="#ffffff" if abs(Z[i, j]) > 2 else INK)
    for s in ax.spines.values():
        s.set_visible(False)
    ax.grid(False)
    ax.tick_params(length=0)
    cb = fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02)
    cb.set_label("std. deviations from the\naverage phishing URL (clipped at +/-3)", color=INK2, fontsize=8)
    cb.outline.set_visible(False)
    cb.ax.tick_params(colors=INK2, labelsize=8)
    fig.tight_layout()
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(PLOTS_DIR / "phishing_cluster_profile.png", dpi=200, facecolor=SURFACE)
    print("saved", PLOTS_DIR / "phishing_cluster_profile.png")


if __name__ == "__main__":
    main()
