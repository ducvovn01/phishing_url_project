# Scores URLs with any saved model in models/ (see MODEL_NAMES).
# Uses the training-time feature code, so new URLs are scored like the test split.
#
# Usage:
#   python scripts/predict.py https://example.com paypal-login-verify.xyz/account
#   python scripts/predict.py --file urls.txt --model logreg --threshold 0.7
import argparse
import sys
from pathlib import Path

import joblib
import pandas as pd

from extract_features import extract_features
from train_model import MODELS_DIR, build_matrix, positive_proba

# Every models/<name>.joblib that PhishingDetector can load.
MODEL_NAMES = ["lightgbm", "logreg", "char_ngram", "kmeans", "hdbscan", "autoencoder"]


class PhishingDetector:
    """Wraps a models/*.joblib bundle. Load once, then call predict() per batch."""

    def __init__(self, model_path: Path = MODELS_DIR / "lightgbm.joblib",
                 threshold: float | None = None):
        bundle = joblib.load(model_path)
        self.bundle = bundle
        self.model = bundle.get("model")  # the autoencoder bundle stores weights instead
        # None for char_ngram, whose pipeline takes the raw URL strings.
        self.feature_columns = bundle.get("feature_columns")
        self.tld_categories = bundle.get("tld_categories")
        self.threshold = bundle["threshold"] if threshold is None else threshold

    def _feature_proba(self, feats: pd.DataFrame):
        """Phishing probability from a feature table, using the right bundle type."""
        # Clustering and autoencoder bundles carry their own preprocessing; imported
        # lazily so other models don't load torch.
        if "cluster_proba" in self.bundle:
            from clustering_model import bundle_proba
            return bundle_proba(self.bundle, feats)
        if "state_dict" in self.bundle:
            from autoencoder_model import bundle_proba
            return bundle_proba(self.bundle, feats)
        X = build_matrix(feats, self.feature_columns, self.tld_categories)
        return positive_proba(self.model, X)

    def predict(self, urls: list[str]) -> pd.DataFrame:
        """Return one row per URL: url, phishing_probability, is_phishing."""
        urls = [str(u).strip() for u in urls]
        if not urls:
            return pd.DataFrame(columns=["url", "phishing_probability", "is_phishing"])
        if self.feature_columns is None:
            proba = positive_proba(self.model, pd.Series(urls))
        else:
            proba = self._feature_proba(extract_features(pd.DataFrame({"url": urls})))
        return pd.DataFrame({
            "url": urls,
            "phishing_probability": proba,
            "is_phishing": proba >= self.threshold,
        })


def main() -> None:
    """Command-line entry point: score URLs from arguments and/or --file, print a table."""
    parser = argparse.ArgumentParser(description="Score URLs as phishing or legitimate.")
    parser.add_argument("urls", nargs="*", help="URLs to score")
    parser.add_argument("--file", type=Path, help="text file with one URL per line")
    parser.add_argument("--model", choices=MODEL_NAMES, default="lightgbm")
    parser.add_argument("--threshold", type=float,
                        help="override the threshold saved with the model")
    args = parser.parse_args()

    urls = list(args.urls)
    if args.file:
        # utf-8-sig strips the BOM that Notepad/PowerShell put at the start.
        urls += args.file.read_text(encoding="utf-8-sig").splitlines()
    urls = [u for u in urls if u.strip()]
    if not urls:
        parser.error("give at least one URL or --file")

    detector = PhishingDetector(MODELS_DIR / f"{args.model}.joblib", args.threshold)
    results = detector.predict(urls)
    results["verdict"] = results.pop("is_phishing").map({True: "PHISHING", False: "legitimate"})

    print(f"model: {args.model}, threshold: {detector.threshold}", file=sys.stderr)
    print(results.to_string(index=False, float_format="{:.4f}".format))


if __name__ == "__main__":
    main()
