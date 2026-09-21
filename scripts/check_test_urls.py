# Scores the hand-written URLs in data/test_urls.csv with every saved model and
# shows, per category, how many each model gets right. Rows marked "ambiguous"
# (URL shorteners) have no right answer, so only their scores are listed.
#
# Usage:
#   python scripts/check_test_urls.py              # summary + rows some model got wrong
#   python scripts/check_test_urls.py --all        # every row
#   python scripts/check_test_urls.py --file my_urls.csv   # columns: url,expected,category
import argparse
from pathlib import Path

import pandas as pd

from predict import MODEL_NAMES, PhishingDetector
from train_model import MODELS_DIR, PROJECT_ROOT

MODELS = MODEL_NAMES
EXPECTED_IS_PHISHING = {"phishing": True, "legitimate": False}


def main() -> None:
    parser = argparse.ArgumentParser(description="Check every saved model against hand-labelled URLs.")
    parser.add_argument("--file", type=Path, default=PROJECT_ROOT / "data" / "test_urls.csv")
    parser.add_argument("--all", action="store_true", help="print every row, not only mistakes")
    args = parser.parse_args()

    cases = pd.read_csv(args.file)
    expected = cases["expected"].map(EXPECTED_IS_PHISHING)  # NaN for ambiguous
    labelled = expected.notna()

    scores = cases[["url", "expected", "category"]].copy()
    correct = pd.DataFrame(index=cases.index)
    for name in MODELS:
        result = PhishingDetector(MODELS_DIR / f"{name}.joblib").predict(cases["url"].tolist())
        scores[name] = result["phishing_probability"].to_numpy()
        correct[name] = (result["is_phishing"].to_numpy() == expected).where(labelled)

    pd.set_option("display.width", 250)
    pd.set_option("display.max_colwidth", 70)
    pd.set_option("display.max_rows", None)

    groups = cases.loc[labelled, ["category", "expected"]]
    summary = correct[labelled].groupby([groups["category"], groups["expected"]], sort=False).mean()
    summary.insert(0, "urls", groups.groupby(["category", "expected"], sort=False).size())
    for exp in ["legitimate", "phishing"]:
        summary.loc[("ALL " + exp, exp), :] = [
            (groups["expected"] == exp).sum(), *correct[cases["expected"] == exp].mean()
        ]
    summary.loc[("ALL", ""), :] = [labelled.sum(), *correct[labelled].mean()]
    summary["urls"] = summary["urls"].astype(int)
    print(f"Share of URLs each model got right (threshold saved with each model), {args.file.name}:\n")
    print(summary.to_string(formatters={m: "{:.0%}".format for m in MODELS}))

    # Mark wrong verdicts with "*" next to the probability.
    shown = scores.copy()
    for name in MODELS:
        wrong = correct[name] == 0
        shown[name] = shown[name].map("{:.3f}".format) + wrong.map({True: "*", False: " "})
    rows = shown if args.all else shown[labelled & (correct == 0).any(axis=1)]
    title = "All URLs" if args.all else "URLs at least one model got wrong"
    print(f"\n{title} (phishing probability; * = wrong verdict): {len(rows)}\n")
    print(rows.to_string(index=False))

    if not args.all:
        print("\nURL shorteners (no right answer - a short link can hide anything):\n")
        print(shown[~labelled].drop(columns=["expected", "category"]).to_string(index=False))


if __name__ == "__main__":
    main()
