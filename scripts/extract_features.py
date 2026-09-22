# Feature engineering over the combined, deduplicated dataset. Reads
# data/processed/combined_dataset.csv and writes a feature table to
# data/processed/features.parquet (+ a .csv for easy inspection).
#
# `domain` (registrable domain, e.g. "example.co.uk") is included in the
# output as a grouping key for train/test splitting, not as a model feature
# itself — combined_dataset.csv has heavy cross-source URL overlap (see
# eda_report.md), so a random row-level split would leak near-duplicate
# URLs between train and test. Group by `domain` when splitting.
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import tldextract
from rapidfuzz import fuzz, process

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

# brand_list.py lives under data/reference, not scripts/ — not a package,
# just a path insert like the rest of this file's flat script layout.
sys.path.insert(0, str(PROJECT_ROOT / "data" / "reference"))
from brand_list import load_brand_list  # noqa: E402

_PROTOCOL_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://")
_IP_HOSTNAME_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_PORT_RE = re.compile(r":\d+$")

# Words commonly stuffed into phishing URLs to impersonate login/verification
# flows. Not exhaustive — a coarse lexical signal, not a lookup table.
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "webscr", "ebayisapi", "password", "billing", "suspend",
]

# tldextract ships a bundled public-suffix-list snapshot. suffix_list_urls=()
# disables the live network fetch so this script is reproducible offline and
# doesn't silently depend on internet access at run time.
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# Brand/typosquat similarity (FR3). Loaded once at import time — see
# data/reference/brand_list.py for sources (curated list + Tranco top 1000).
BRAND_LIST = load_brand_list()
_BRAND_SET = set(BRAND_LIST)

# Unicode characters visually confusable with a Latin letter in a lowercased
# hostname (Cyrillic/Greek look-alikes seen in real typosquat domains). Kept
# as its own step from normalize_leetspeak() below: this catches
# lookalike-*script* substitution, leetspeak catches same-script
# digit-for-letter substitution — separating them keeps it clear in the code
# (and explainable in the report) which mechanism caught which typosquat.
_HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g",
    "ⅰ": "i", "ⅼ": "l", "０": "0", "１": "1",
    "α": "a", "ο": "o", "υ": "y", "ν": "v", "κ": "k",  # Greek
})


def normalize_homoglyphs(s: str) -> str:
    """Map Cyrillic/Greek look-alike characters to their Latin equivalent
    (e.g. Cyrillic "а" U+0430 -> Latin "a"), so a domain built from those
    characters compares against the brand list the way it visually reads."""
    return s.translate(_HOMOGLYPH_MAP)


# ASCII digit-for-letter substitutions common in typosquatting (paypa1,
# amaz0n, 5ecure). Applied after normalize_homoglyphs() as a separate step
# — see the comment above.
_LEETSPEAK_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a"})


def normalize_leetspeak(s: str) -> str:
    """Map common ASCII leetspeak substitutions (0->o, 1->l, 3->e, 5->s,
    7->t, 4->a) plus the "rn" -> "m" digraph used to fake a letter."""
    return s.translate(_LEETSPEAK_MAP).replace("rn", "m")


def _best_brand_match(labels: list[str], brands: list[str]) -> tuple[np.ndarray, list[str]]:
    """Best rapidfuzz.fuzz.ratio match (0-1) for each label against `brands`,
    via rapidfuzz.process.cdist — a vectorized all-pairs batch call.
    Benchmarked against a process.extractOne-per-row loop on a 10k-row
    sample of combined_dataset.csv: cdist was ~37x faster (1.3us/row vs
    48.3us/row) with identical top-match results on all 10k rows, so cdist
    is what runs on the full dataset."""
    if not labels:
        return np.array([]), []
    scores = process.cdist(labels, brands, scorer=fuzz.ratio, workers=-1)
    best_idx = scores.argmax(axis=1)
    best_score = scores[np.arange(len(labels)), best_idx] / 100.0
    best_brand = [brands[i] for i in best_idx]
    return best_score, best_brand


def compute_brand_similarity(domain_label: pd.Series) -> pd.DataFrame:
    """brand_similarity_score (float, 0-1), is_exact_brand_match (bool) and
    matched_brand (str) for each row's bare registrable-domain label
    (suffix already stripped by the caller).

    Matched once per *unique* label, not per row: combined_dataset.csv has
    heavy domain overlap (~770k unique domain labels for 1.6M rows, see
    eda_report.md), so matching every row separately would repeat identical
    work roughly twice over for no benefit — the result is joined back onto
    every row afterwards.

    Similarity is checked against both the raw label and the
    homoglyph+leetspeak-normalized variant (normalize_homoglyphs() then
    normalize_leetspeak()); whichever scores higher wins. is_exact_brand_match
    is checked against the raw label only, so a literal brand domain (e.g.
    "paypal.com") is flagged as an exact match — rather than a "typosquat of
    itself" — with brand_similarity_score at its natural value of 1.0 from
    matching itself in the fuzzy pass, not a separately special-cased 1.0.
    """
    uniq_labels = pd.Index(domain_label.unique())
    raw = uniq_labels.tolist()
    normalized = [normalize_leetspeak(normalize_homoglyphs(s)) for s in raw]

    raw_score, raw_brand = _best_brand_match(raw, BRAND_LIST)
    norm_score, norm_brand = _best_brand_match(normalized, BRAND_LIST)

    use_norm = norm_score > raw_score
    best_score = np.where(use_norm, norm_score, raw_score)
    best_brand = [nb if u else rb for u, rb, nb in zip(use_norm, raw_brand, norm_brand)]

    lookup = pd.DataFrame(
        {"brand_similarity_score": best_score, "matched_brand": best_brand},
        index=uniq_labels,
    )
    out = lookup.loc[domain_label.to_numpy()]
    out.index = domain_label.index
    out["is_exact_brand_match"] = domain_label.isin(_BRAND_SET)
    return out


def split_url(url: str):
    """Split a raw URL into (protocol, rest) without requiring a protocol
    to be present — many rows in this dataset have no scheme at all."""
    m = _PROTOCOL_RE.match(url)
    if m:
        return m.group(1).lower(), url[m.end():]
    return "", url


def preprocess_url(url: str) -> str:
    """URL text for models that read the raw string (train_char_ngram.py).
    Drops the scheme and lowercases: both mostly record how each source
    formatted its URLs - phiusiil rows never contain uppercase letters."""
    return _PROTOCOL_RE.sub("", url.strip()).lower()


def get_hostname(rest: str) -> str:
    return rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split("@")[-1]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    _, counts = np.unique(list(s), return_counts=True)
    probs = counts / len(s)
    return float(-(probs * np.log2(probs)).sum())


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    urls = df["url"].fillna("").astype(str)

    protocol, rest = zip(*urls.map(split_url))
    protocol = pd.Series(protocol, index=df.index)
    rest = pd.Series(rest, index=df.index)

    hostname_raw = rest.map(get_hostname)
    hostname = hostname_raw.str.lower().str.replace(_PORT_RE, "", regex=True)
    after_host = rest.str.slice(start=0).combine(
        hostname_raw, lambda full, host: full[len(host):] if full.startswith(host) else full
    )
    path = after_host.str.split("?", n=1).str[0].str.split("#", n=1).str[0]
    query = after_host.where(after_host.str.contains(r"\?"), "").str.split("?", n=1).str[1].fillna("")
    query = query.str.split("#", n=1).str[0]

    ext = [_EXTRACT(h) for h in hostname]
    subdomain = pd.Series([e.subdomain for e in ext], index=df.index)
    suffix = pd.Series([e.suffix for e in ext], index=df.index)
    domain = pd.Series(
        [e.top_domain_under_public_suffix or h for e, h in zip(ext, hostname)],
        index=df.index,
    )
    # Bare second-level label (suffix stripped, e.g. "paypal" from
    # "paypal.com") — the comparison base for brand-similarity matching
    # below, not a model feature or the grouping key (that's `domain`).
    domain_label = pd.Series([e.domain for e in ext], index=df.index)

    feats = pd.DataFrame(index=df.index)
    feats["url"] = urls
    # Absent when scoring new URLs (see predict.py).
    for col in ("label", "source"):
        if col in df:
            feats[col] = df[col]
    feats["domain"] = domain  # grouping key for splitting, not a model feature

    # Lexical counts / lengths. url_length is measured without the scheme:
    # whether a row carries "https://" depends on which source it came from
    # (see the protocol flags below), so counting it would let url_length
    # leak that source formatting into the model.
    feats["url_length"] = rest.str.len()
    feats["hostname_length"] = hostname.str.len()
    feats["path_length"] = path.str.len()
    feats["query_length"] = query.str.len()
    feats["dot_count"] = urls.str.count(r"\.")
    feats["hyphen_count"] = urls.str.count("-")
    feats["digit_count"] = urls.str.count(r"\d")
    feats["at_count"] = urls.str.count("@")
    feats["underscore_count"] = urls.str.count("_")
    feats["percent_count"] = urls.str.count("%")
    feats["equals_count"] = urls.str.count("=")
    feats["ampersand_count"] = urls.str.count("&")
    feats["digit_ratio"] = (feats["digit_count"] / feats["url_length"].replace(0, np.nan)).fillna(0.0)

    # Structural flags
    feats["subdomain_count"] = (subdomain.str.count(r"\.") + 1).where(subdomain != "", 0)
    feats["path_depth"] = path.str.count(r"[^/]+")  # non-empty path segments
    feats["is_ip_hostname"] = hostname.str.match(_IP_HOSTNAME_RE).astype(int)
    feats["has_port"] = hostname_raw.str.contains(_PORT_RE).astype(int)
    # Kept for analysis, but excluded from training (see train_model.py): in
    # this data they mostly record how each source formatted its URLs — e.g.
    # mitake/semihguner rows almost never have a scheme, and every phiusiil
    # legitimate row is https — rather than anything about phishing.
    feats["uses_https"] = (protocol == "https").astype(int)
    feats["has_protocol"] = (protocol != "").astype(int)
    feats["has_punycode"] = hostname.str.contains("xn--").astype(int)

    # Suspicious-keyword count (case-insensitive, over the full URL)
    lowered = urls.str.lower()
    kw_pattern = "|".join(re.escape(k) for k in SUSPICIOUS_KEYWORDS)
    feats["suspicious_keyword_count"] = lowered.str.count(kw_pattern)

    # Categorical
    feats["tld"] = suffix

    # Randomness signal — phishing domains often look more "random"
    feats["hostname_entropy"] = hostname.map(shannon_entropy)

    # Brand/typosquat similarity (FR3) — see compute_brand_similarity().
    brand = compute_brand_similarity(domain_label)
    feats["brand_similarity_score"] = brand["brand_similarity_score"]
    feats["is_exact_brand_match"] = brand["is_exact_brand_match"].astype(int)
    feats["matched_brand"] = brand["matched_brand"]  # not a model feature — see train_model.py

    return feats


def main() -> None:
    df = pd.read_csv(PROCESSED_DIR / "combined_dataset.csv")
    print(f"Loaded {len(df)} rows")

    feats = extract_features(df)

    out_parquet = PROCESSED_DIR / "features.parquet"
    out_csv = PROCESSED_DIR / "features.csv"
    feats.to_parquet(out_parquet, index=False)
    feats.to_csv(out_csv, index=False)

    print(f"Wrote {len(feats)} rows x {feats.shape[1]} columns")
    print(f"  {out_parquet}")
    print(f"  {out_csv}")
    print()
    print(f"Unique domains (grouping key for split): {feats['domain'].nunique()}")
    print()
    print(feats.drop(columns=["url", "domain"]).describe(include="all").transpose())


if __name__ == "__main__":
    main()
