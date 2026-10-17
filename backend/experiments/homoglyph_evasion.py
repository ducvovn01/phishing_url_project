"""P2: Unicode look-alike (homoglyph) evasion of the A2 model, before and after a defence.

URLs are only ever scored as text: none is opened, fetched or resolved.

Conditions, all on the same verified A2 model:
  baseline    the A2 pipeline exactly as the API runs it
  naive_fold  NFKC + confusable map, then the A2 pipeline (brand mask decided on the
              folded text)
  defended    NFKC + confusable map, brand mask decided on the original host
              (app/services/normalization.py)

Attack cases (every variant is phishing by construction):
  A  16 synthetic brand-impersonation URLs, brand token rewritten by five strategies.
  B  8 official brand URLs turned into IDN homographs (pаypal.com with Cyrillic а): the
     attacker's domain, although its ASCII twin is the real site.
  C  phishing URLs from the A2 domain-grouped test split whose host contains a brand
     name, detected by the baseline (seeded sample); first brand occurrence in the host
     rewritten by the same five strategies.
Evasion rate = share of variants scored below the threshold, counted only over variants
whose ASCII base the baseline detects (A and C). B reports detection rate instead.

Benign sets (false positives): a seeded sample of legitimate test-split URLs, every
legitimate test-split URL with non-ASCII characters, and the legitimate rows of
data/test_urls.csv.

Run from the project root (needs backend/requirements-dev.txt):
    backend/.venv/Scripts/python backend/experiments/homoglyph_evasion.py
Writes backend/experiments/results/{cases.csv, benign.csv, summary.json}.
"""
import csv
import json
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path

import numpy as np
import pandas as pd

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))
from app.a2 import PROJECT_ROOT, preprocess_url_masked  # noqa: E402
from app.services.model_service import ModelService  # noqa: E402
from app.services.normalization import PreprocessedScorer, defended_model_input, fold  # noqa: E402

from train_model import split_by_domain  # noqa: E402  (scripts/ is on sys.path via app.a2)

RESULTS = BACKEND / "experiments" / "results"
SEED = 42
BENIGN_SAMPLE = 5000
DATASET_BASES = 200

BASES_A = [
    ("A01", "paypal.com-secure-login.info/verify", "paypal"),
    ("A02", "secure-paypal-account.com/signin", "paypal"),
    ("A03", "appleid.apple.com.verify-session.net/login", "apple"),
    ("A04", "apple-id-locked.support/unlock", "apple"),
    ("A05", "amazon-order-cancel.com/account", "amazon"),
    ("A06", "login.microsoftonline.com.auth-check.cc/oauth", "microsoft"),
    ("A07", "microsoft-office365-update.com/login", "microsoft"),
    ("A08", "netflix-billing-update.com/payment", "netflix"),
    ("A09", "www.chase-bank-alerts.com/verify", "chase"),
    ("A10", "wellsfargo-online-secure.com/signin", "wellsfargo"),
    ("A11", "dhl-parcel-tracking.com/redelivery", "dhl"),
    ("A12", "facebook-security-check.com/recover", "facebook"),
    ("A13", "instagram-copyright-appeal.com/form", "instagram"),
    ("A14", "google-docs-share.com/document", "google"),
    ("A15", "coinbase-wallet-verify.com/restore", "coinbase"),
    ("A16", "docusign-envelope-review.com/view", "docusign"),
]
BASES_B = [
    ("B01", "paypal.com/signin", "paypal"),
    ("B02", "google.com/accounts/login", "google"),
    ("B03", "apple.com/account", "apple"),
    ("B04", "microsoft.com/account/login", "microsoft"),
    ("B05", "amazon.com/gp/signin", "amazon"),
    ("B06", "netflix.com/login", "netflix"),
    ("B07", "facebook.com/login.php", "facebook"),
    ("B08", "coinbase.com/signin", "coinbase"),
]
# Brand names looked for in dataset hosts (category C), longest first so "wellsfargo"
# wins over shorter names it contains.
DATASET_BRANDS = sorted(["paypal", "apple", "amazon", "microsoft", "netflix", "google",
                         "facebook", "instagram", "chase", "wellsfargo", "coinbase",
                         "docusign", "outlook", "office", "yahoo", "dropbox", "linkedin",
                         "binance", "steam", "ebay"], key=len, reverse=True)

CYRILLIC = {"a": "а", "c": "с", "e": "е", "o": "о", "p": "р", "x": "х", "y": "у", "i": "і",
            "j": "ј", "s": "ѕ", "h": "һ", "d": "ԁ"}
GREEK = {"a": "α", "o": "ο", "v": "ν", "k": "κ", "i": "ι", "p": "ρ"}
# Latin letters with a dot below/above: real IDN homographs that neither NFKC (which keeps
# precomposed letters) nor the defence table folds, to measure what the defence misses.
UNCOVERED = {"a": "ạ", "b": "ḅ", "d": "ḍ", "e": "ẹ", "h": "ḥ", "i": "ị", "k": "ḳ", "l": "ḷ",
             "m": "ṃ", "n": "ṇ", "o": "ọ", "r": "ṛ", "s": "ṣ", "t": "ṭ", "u": "ụ", "v": "ṿ",
             "w": "ẉ", "y": "ỵ", "z": "ẓ", "c": "ċ", "f": "ḟ", "g": "ġ", "p": "ṗ", "x": "ẋ"}


def cyrillic_one(token: str) -> str:
    for i, ch in enumerate(token):
        if ch in CYRILLIC:
            return token[:i] + CYRILLIC[ch] + token[i + 1:]
    return token


def substitute(table: dict) -> Callable[[str], str]:
    return lambda token: "".join(table.get(ch, ch) for ch in token)


def fullwidth(token: str) -> str:
    return "".join(chr(ord(ch) + 0xFEE0) if "a" <= ch <= "z" else ch for ch in token)


STRATEGIES = {
    "cyrillic_one": cyrillic_one,
    "cyrillic_all": substitute(CYRILLIC),
    "greek_mixed": substitute(GREEK),
    "fullwidth": fullwidth,
    "dot_diacritics_uncovered": substitute(UNCOVERED),
}
STRATEGIES_B = ("cyrillic_one", "cyrillic_all")
_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


def host_span(url: str) -> tuple[int, int]:
    start = m.end() if (m := _SCHEME.match(url)) else 0
    end = len(url)
    for sep in "/?#":
        i = url.find(sep, start)
        if i != -1:
            end = min(end, i)
    return start, end


def rewrite_in_host(url: str, token: str, perturb: Callable[[str], str]) -> str:
    """Rewrite the first case-insensitive occurrence of `token` inside the URL's host."""
    start, end = host_span(url)
    i = url.lower().find(token, start, end)
    return url if i == -1 else url[:i] + perturb(token) + url[i + len(token):]


def synthetic_cases() -> list[dict]:
    cases = []
    for base_id, url, token in BASES_A:
        for name, perturb in STRATEGIES.items():
            cases.append({"category": "A", "base_id": base_id, "base_url": url, "brand": token,
                          "strategy": name, "variant_url": url.replace(token, perturb(token))})
    for base_id, url, token in BASES_B:
        for name in STRATEGIES_B:
            cases.append({"category": "B", "base_id": base_id, "base_url": url, "brand": token,
                          "strategy": name,
                          "variant_url": url.replace(token, STRATEGIES[name](token))})
    return cases


def dataset_cases(test: pd.DataFrame, service: ModelService) -> list[dict]:
    """Category C: detected test-split phishing URLs with a brand in the host."""
    phishing = test[(test["label"] == 1) & test["url"].map(str.isascii)]
    hosts = phishing["url"].map(lambda u: u[slice(*host_span(u))].lower())
    brand = hosts.map(lambda h: next((b for b in DATASET_BRANDS if b in h), None))
    pool = phishing[brand.notna()].assign(brand=brand[brand.notna()])
    pool = pool[service.phishing_probability(pool["url"].tolist()) >= service.threshold]
    sample = pool.sample(DATASET_BASES, random_state=SEED)
    cases = []
    for n, (url, token) in enumerate(zip(sample["url"], sample["brand"]), 1):
        for name, perturb in STRATEGIES.items():
            cases.append({"category": "C", "base_id": f"C{n:03d}", "base_url": url,
                          "brand": token, "strategy": name,
                          "variant_url": rewrite_in_host(url, token, perturb)})
    return cases


def benign_urls(test: pd.DataFrame) -> pd.DataFrame:
    legit = test[test["label"] == 0]
    non_ascii = legit[~legit["url"].map(str.isascii)]
    sample = legit.drop(non_ascii.index).sample(BENIGN_SAMPLE, random_state=SEED)
    with (PROJECT_ROOT / "data" / "test_urls.csv").open(encoding="utf-8", newline="") as f:
        hand = [r["url"] for r in csv.DictReader(f) if r["expected"] == "legitimate"]
    return pd.concat([
        pd.DataFrame({"set": "test_split_sample", "url": sample["url"]}),
        pd.DataFrame({"set": "test_split_non_ascii", "url": non_ascii["url"]}),
        pd.DataFrame({"set": "test_urls_csv_legit", "url": hand}),
    ], ignore_index=True)


class Conditions:
    """The three scoring conditions, one URL per call as the API would run them."""

    NAMES = ("baseline", "naive_fold", "defended")

    def __init__(self, service: ModelService):
        self.service = service
        self.scorer = PreprocessedScorer(service.pipeline)

    def baseline(self, url: str) -> float:
        return float(self.service.phishing_probability([url])[0])

    def naive_fold(self, url: str) -> float:
        return float(self.service.phishing_probability([fold(url)])[0])

    def defended(self, url: str) -> float:
        return float(self.scorer.phishing_probability([defended_model_input(url)])[0])


def score(conditions: Conditions, urls: list[str]) -> dict[str, tuple[np.ndarray, np.ndarray]]:
    """{condition: (probabilities, seconds per call)}, after one warm-up call each."""
    out = {}
    for name in Conditions.NAMES:
        fn = getattr(conditions, name)
        fn(urls[0])
        probs, secs = [], []
        for url in urls:
            started = time.perf_counter()
            probs.append(fn(url))
            secs.append(time.perf_counter() - started)
        out[name] = (np.array(probs), np.array(secs))
    return out


def rate(mask) -> dict:
    mask = np.asarray(mask, dtype=bool)
    return {"count": int(mask.sum()), "of": int(mask.size),
            "rate": round(float(mask.mean()), 4) if mask.size else None}


def evasion(frame: pd.DataFrame) -> dict:
    return {name: rate(~frame[f"detected_{name}"]) for name in Conditions.NAMES}


def main() -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    service = ModelService.from_manifest()
    threshold = service.threshold
    conditions = Conditions(service)
    assert all(fold(c) == c for c in UNCOVERED.values()), "uncovered strategy must be unfolded"

    df = pd.read_parquet(PROJECT_ROOT / "data" / "processed" / "features.parquet",
                         columns=["url", "label", "source", "domain"])
    _, test = split_by_domain(df)
    del df

    cases = pd.DataFrame(synthetic_cases() + dataset_cases(test, service))
    cases = cases[cases["variant_url"] != cases["base_url"]].drop_duplicates("variant_url")
    cases.insert(0, "case_id", cases["base_id"] + "-" + cases["strategy"])
    # The defence's scorer must reproduce the API's scores on ordinary masked inputs.
    bases = cases["base_url"].drop_duplicates().tolist()
    assert np.allclose(conditions.scorer.phishing_probability([preprocess_url_masked(u) for u in bases]),
                       service.phishing_probability(bases), rtol=0, atol=1e-12)
    base_p = dict(zip(bases, service.phishing_probability(bases)))
    cases["p_base_baseline"] = cases["base_url"].map(base_p)
    cases["base_detected"] = cases["p_base_baseline"] >= threshold
    case_scores = score(conditions, cases["variant_url"].tolist())
    for name in Conditions.NAMES:
        cases[f"p_{name}"] = case_scores[name][0]
        cases[f"detected_{name}"] = cases[f"p_{name}"] >= threshold
        cases[f"ms_{name}"] = (case_scores[name][1] * 1000).round(3)
    cases["expected"] = "phishing"
    cases["model_version"] = service.manifest.version

    benign = benign_urls(test)
    benign_scores = score(conditions, benign["url"].tolist())
    for name in Conditions.NAMES:
        benign[f"p_{name}"] = benign_scores[name][0]
        benign[f"flagged_{name}"] = benign[f"p_{name}"] >= threshold
    benign["changed_by_fold"] = benign["url"].map(lambda u: fold(u.strip()) != u.strip().lower())

    attack = {}
    for category in ("A", "C"):
        group = cases[cases["category"] == category]
        detected = group[group["base_detected"]]
        attack[category] = {
            "bases": int(group["base_id"].nunique()),
            "bases_detected_by_baseline": int(detected["base_id"].nunique()),
            "variants": len(group),
            "variants_of_detected_bases": len(detected),
            "evasion_rate": evasion(detected),
            "evasion_rate_by_strategy": {s: evasion(g) for s, g in detected.groupby("strategy")},
        }
    b = cases[cases["category"] == "B"]
    b_bases = cases[cases["category"] == "B"].drop_duplicates("base_id")
    attack["B"] = {
        "variants": len(b),
        "detection_rate": {name: rate(b[f"detected_{name}"]) for name in Conditions.NAMES},
        "ascii_official_twins_flagged_by_baseline": rate(b_bases["base_detected"]),
    }
    all_seconds = {name: np.concatenate([case_scores[name][1], benign_scores[name][1]])
                   for name in Conditions.NAMES}
    summary = {
        "model": {"name": service.manifest.name, "version": service.manifest.version,
                  "sha256": service.manifest.sha256, "threshold": threshold},
        "seed": SEED,
        "attack_cases_total": len(cases),
        "attack": attack,
        "benign_flagged_as_phishing": {
            set_name: {"urls": len(g), "changed_by_fold": int(g["changed_by_fold"].sum()),
                       **{name: rate(g[f"flagged_{name}"]) for name in Conditions.NAMES}}
            for set_name, g in benign.groupby("set")},
        "benign_label_changes_vs_baseline": {
            name: {"legit_to_phishing": int((~benign["flagged_baseline"]
                                             & benign[f"flagged_{name}"]).sum()),
                   "phishing_to_legit": int((benign["flagged_baseline"]
                                             & ~benign[f"flagged_{name}"]).sum())}
            for name in ("naive_fold", "defended")},
        "latency_ms_per_url": {
            name: {"mean": round(float(s.mean() * 1000), 3),
                   "p95": round(float(np.percentile(s, 95) * 1000), 3), "calls": len(s)}
            for name, s in all_seconds.items()},
    }

    cases.to_csv(RESULTS / "cases.csv", index=False, encoding="utf-8")
    benign.to_csv(RESULTS / "benign.csv", index=False, encoding="utf-8")
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                                          encoding="utf-8")
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
