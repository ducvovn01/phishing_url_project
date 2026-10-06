# Builds URL features from data/processed/combined_dataset.csv and writes
# data/processed/features.parquet (+ .csv for inspection).
# `domain` is a grouping key for train/test splits, not a feature: sources overlap
# heavily, so a row-level split would leak near-duplicate URLs.
import re
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import tldextract
from rapidfuzz import fuzz, process

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

# brand_list.py lives in data/reference, outside scripts/, so add it to the path.
sys.path.insert(0, str(PROJECT_ROOT / "data" / "reference"))
from brand_list import load_brand_list  # noqa: E402

_PROTOCOL_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+.-]*)://")
_IP_HOSTNAME_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_PORT_RE = re.compile(r":\d+$")

# Words common in phishing URLs that imitate login/verification pages (coarse signal).
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "secure", "account", "update", "confirm",
    "banking", "webscr", "ebayisapi", "password", "billing", "suspend",
]

# suffix_list_urls=() uses the bundled suffix list, so no network fetch (offline, reproducible).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

# Brand list for typosquat similarity (FR3); see data/reference/brand_list.py.
BRAND_LIST = load_brand_list()
_BRAND_SET = set(BRAND_LIST)

# Cyrillic/Greek look-alikes of Latin letters. Separate from leetspeak so the report
# can say which mechanism caught a typosquat (script swap vs digit-for-letter).
_HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g",
    "ⅰ": "i", "ⅼ": "l", "０": "0", "１": "1",
    "α": "a", "ο": "o", "υ": "y", "ν": "v", "κ": "k",  # Greek
})


def normalize_homoglyphs(s: str) -> str:
    """Map Cyrillic/Greek look-alikes to Latin letters so the domain reads as it looks."""
    return s.translate(_HOMOGLYPH_MAP)


# Digit-for-letter swaps common in typosquats (paypa1, amaz0n); applied after homoglyphs.
_LEETSPEAK_MAP = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a"})


def normalize_leetspeak(s: str) -> str:
    """Undo leetspeak digits (0->o, 1->l, ...) and the "rn" -> "m" look-alike."""
    return s.translate(_LEETSPEAK_MAP).replace("rn", "m")


def _best_brand_match(labels: list[str], brands: list[str]) -> tuple[np.ndarray, list[str]]:
    """Best fuzz.ratio match (0-1) per label against `brands`.
    Uses vectorized process.cdist, ~37x faster than extractOne per row (10k-row benchmark)."""
    if not labels:
        return np.array([]), []
    scores = process.cdist(labels, brands, scorer=fuzz.ratio, workers=-1)
    best_idx = scores.argmax(axis=1)
    best_score = scores[np.arange(len(labels)), best_idx] / 100.0
    best_brand = [brands[i] for i in best_idx]
    return best_score, best_brand


def compute_brand_similarity(domain_label: pd.Series) -> pd.DataFrame:
    """Return brand_similarity_score, matched_brand and is_exact_brand_match per domain label.
    Matches once per unique label (~770k unique of 1.6M rows), then joins back to rows.
    Score is the higher of the raw and homoglyph/leetspeak-normalized similarity.
    Exact match uses the raw label only, so a real brand domain is not a typosquat."""
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
    """Split a URL into (protocol, rest); the scheme is optional, many rows have none."""
    m = _PROTOCOL_RE.match(url)
    if m:
        return m.group(1).lower(), url[m.end():]
    return "", url


def preprocess_url(url: str) -> str:
    """URL text for train_char_ngram.py: scheme dropped and lowercased (source formatting)."""
    return _PROTOCOL_RE.sub("", url.strip()).lower()


def get_hostname(rest: str) -> str:
    """Host part of a scheme-less URL, without path, query, fragment or userinfo."""
    return rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0].split("@")[-1]


def shannon_entropy(s: str) -> float:
    """Shannon entropy of the characters in s, in bits."""
    if not s:
        return 0.0
    _, counts = np.unique(list(s), return_counts=True)
    probs = counts / len(s)
    return float(-(probs * np.log2(probs)).sum())


def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """Turn a frame with a `url` column into the feature table (one row per URL)."""
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
    # Bare label without suffix ("paypal"), used only for brand matching.
    domain_label = pd.Series([e.domain for e in ext], index=df.index)

    feats = pd.DataFrame(index=df.index)
    feats["url"] = urls
    # Absent when scoring new URLs (see predict.py).
    for col in ("label", "source"):
        if col in df:
            feats[col] = df[col]
    feats["domain"] = domain  # grouping key for splitting, not a model feature

    # Lexical counts / lengths. url_length excludes the scheme, which only reflects
    # source formatting (see protocol flags below).
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
    # Kept for analysis, excluded from training (see train_model.py): they mostly
    # record source formatting (e.g. every phiusiil legitimate row is https).
    feats["uses_https"] = (protocol == "https").astype(int)
    feats["has_protocol"] = (protocol != "").astype(int)
    feats["has_punycode"] = hostname.str.contains("xn--").astype(int)

    # Suspicious-keyword count (case-insensitive, over the full URL)
    lowered = urls.str.lower()
    kw_pattern = "|".join(re.escape(k) for k in SUSPICIOUS_KEYWORDS)
    feats["suspicious_keyword_count"] = lowered.str.count(kw_pattern)

    # Categorical
    feats["tld"] = suffix

    # Randomness signal: phishing domains often look more random.
    feats["hostname_entropy"] = hostname.map(shannon_entropy)

    # Brand/typosquat similarity (FR3); see compute_brand_similarity().
    brand = compute_brand_similarity(domain_label)
    feats["brand_similarity_score"] = brand["brand_similarity_score"]
    feats["is_exact_brand_match"] = brand["is_exact_brand_match"].astype(int)
    feats["matched_brand"] = brand["matched_brand"]  # not a model feature (see train_model.py)

    return feats


def main() -> None:
    """Extract features for the whole combined dataset and write parquet and csv."""
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
