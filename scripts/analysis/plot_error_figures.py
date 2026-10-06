# Evaluation figures for the char n-gram model: confusion matrix (from error_analysis.json)
# and strongest n-gram weights. Writes ngram_confusion_matrix.png, ngram_weights.png
# to data/analysis/plots/
import json

import joblib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import sys
from pathlib import Path

# Scripts import each other from scripts/, one level up.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from train_char_ngram import top_ngrams
from train_model import ANALYSIS_DIR, MODELS_DIR, PLOTS_DIR, PROCESSED_DIR

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e1e0d9"
BLUE, RED = "#2a78d6", "#d03b3b"


def confusion_figure() -> None:
    """Draw the confusion matrix with counts and row-normalised shares."""
    e = json.load(open(ANALYSIS_DIR / "error_analysis.json"))
    legit, phish = e["tn"] + e["fp"], e["fn"] + e["tp"]
    cells = [[(e["tn"], e["tn"] / legit, "True negative"), (e["fp"], e["fp"] / legit, "False positive")],
             [(e["fn"], e["fn"] / phish, "False negative"), (e["tp"], e["tp"] / phish, "True positive")]]
    fig, ax = plt.subplots(figsize=(6.2, 3.3), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    ax.set_xlim(0, 3)
    ax.set_ylim(0, 3)
    ax.invert_yaxis()
    ax.axis("off")
    for x in (0, 1, 2, 3):
        ax.plot([x, x], [0, 3], color=GRID, lw=1)
    for y in (0, 1, 2, 3):
        ax.plot([0, 3], [y, y], color=GRID, lw=1)
    for j, t in enumerate(("Predicted\nlegitimate", "Predicted\nphishing")):
        ax.text(1.5 + j, 0.5, t, ha="center", va="center", fontsize=11, fontweight="bold", color=INK)
    for i, t in enumerate(("Actual\nlegitimate", "Actual\nphishing")):
        ax.text(0.5, 1.5 + i, t, ha="center", va="center", fontsize=11, fontweight="bold", color=INK)
    colour = {"True negative": INK, "False positive": RED, "False negative": RED, "True positive": INK}
    for i in range(2):
        for j in range(2):
            n, share, name = cells[i][j]
            ax.text(1.5 + j, 1.38 + i, f"{n:,}", ha="center", va="center", fontsize=14, color=INK)
            ax.text(1.5 + j, 1.68 + i, f"{share:.2%}  {name}", ha="center", va="center", fontsize=9,
                    color=colour[name])
    fig.tight_layout()
    fig.savefig(PLOTS_DIR / "ngram_confusion_matrix.png", dpi=200, facecolor=SURFACE)


def weights_figure() -> None:
    """Plot the top phishing and legitimate n-gram weights on a 300k URL sample."""
    bundle = joblib.load(MODELS_DIR / "char_ngram.joblib")
    urls = pd.read_parquet(PROCESSED_DIR / "features.parquet", columns=["url"])["url"]
    urls = urls.sample(min(300_000, len(urls)), random_state=42)
    table = top_ngrams(bundle["model"], urls, n=15)
    table["ngram"] = table["ngram"].str.strip("`")
    pos = table[table.direction == "phishing"]
    neg = table[table.direction == "legitimate"]
    fig, axes = plt.subplots(1, 2, figsize=(7.4, 4.4), facecolor=SURFACE)
    for ax, part, title, colour in ((axes[0], pos, "Pushes towards phishing", RED), (axes[1], neg, "Pushes towards legitimate", BLUE)):
        ax.set_facecolor(SURFACE)
        y = np.arange(len(part))[::-1]
        ax.barh(y, part["weight"].abs(), color=colour, height=0.7)
        ax.set_yticks(y, [f"'{g}'" for g in part["ngram"]], color=INK, fontsize=9)
        for yy, w in zip(y, part["weight"]):
            ax.text(abs(w) + 0.6, yy, f"{w:+.1f}", va="center", fontsize=8, color=INK2)
        ax.set_title(title, color=INK, fontsize=10, loc="left")
        ax.set_xlim(0, 58)
        ax.tick_params(axis="x", colors=INK2, labelsize=8)
        ax.tick_params(axis="y", length=0)
        for s in ("top", "right", "left"):
            ax.spines[s].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
        ax.set_xlabel("size of the learned weight", color=INK2, fontsize=8)
    fig.tight_layout()
    fig.savefig(PLOTS_DIR / "ngram_weights.png", dpi=200, facecolor=SURFACE)
    print(table.to_string())


if __name__ == "__main__":
    PLOTS_DIR.mkdir(parents=True, exist_ok=True)
    confusion_figure()
    weights_figure()
