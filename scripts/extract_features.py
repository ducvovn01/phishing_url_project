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
from pathlib import Path

import numpy as np
import pandas as pd
import tldextract

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

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


def split_url(url: str):
    """Split a raw URL into (protocol, rest) without requiring a protocol
    to be present — many rows in this dataset have no scheme at all."""
    m = _PROTOCOL_RE.match(url)
    if m:
        return m.group(1).lower(), url[m.end():]
    return "", url


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

    feats = pd.DataFrame(index=df.index)
    feats["url"] = urls
    feats["label"] = df["label"]
    feats["source"] = df["source"]
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
