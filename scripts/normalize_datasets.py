"""
Load the four raw datasets, standardize each to a common schema
(url, label, source), concatenate, and deduplicate.

label: 1 = phishing, 0 = legitimate.

Verified label directions by sampling raw URLs against each source's raw
label column (see fetch_datasets.py output / project chat log):
  - mitake:        label 0/1 already matches target (0=legit, 1=phishing).
                    Confirmed by sampling: label=0 rows are ordinary sites
                    (dow.com, berkeley.edu, ...), label=1 rows are phishing-
                    style domains (duckdns.org subdomains, typosquats, ...).
  - semihguner:     label 0=benign, 1=malignant/phishing per dataset card;
                    already matches target, no transform needed.
  - harisudhan411:  status is INVERTED relative to the other two sources.
                    Confirmed by sampling: status=0 rows are phishing-style
                    (IP hostnames, spoofed battle.net/coinbase paths),
                    status=1 rows are legitimate (facebook.com, imdb.com,
                    last.fm, ...). So label = 1 - status.
  - phiusiil:       label is INVERTED vs. our target (their docs state
                    1=legitimate, 0=phishing). Confirmed by sampling:
                    label=0 rows are phishing-style (spoofed OWA/metamask
                    login pages, tracking domains), label=1 rows are
                    legitimate (levelup.com, ringling.org, ...). So
                    label = 1 - original_label, matching the stated docs.
"""
import re
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

_PROTOCOL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")


def get_hostname(url: str) -> str:
    u = str(url).strip()
    u = _PROTOCOL_RE.sub("", u.lower())
    u = u.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":")[0]
    return u


def canonicalize(url: str) -> str:
    """Lowercase, strip protocol, strip trailing slash. Used ONLY for dedup
    matching — the original `url` column is left untouched since casing,
    protocol, and trailing slash may themselves be phishing signals for
    feature engineering later.

    Plain regex/string ops rather than urllib.parse.urlsplit: some raw URLs
    contain stray characters (e.g. an unescaped "[" in a query string) that
    urlsplit rejects as malformed IPv6 syntax even though they're not URLs
    we need to route anywhere — we only need consistent lowercased text for
    exact-match dedup, not a real parsed URL object."""
    if not isinstance(url, str):
        return ""
    u = url.strip().lower()
    u = _PROTOCOL_RE.sub("", u)
    u = u.rstrip("/")
    return u


def load_mitake() -> pd.DataFrame:
    df = pd.read_csv(RAW_DIR / "mitake.csv")
    return pd.DataFrame(
        {
            "url": df["url"],
            "label": df["label"].astype(int),
            "source": "mitake",
        }
    )


def load_semihguner() -> pd.DataFrame:
    df = pd.read_parquet(RAW_DIR / "semihguner.parquet")
    return pd.DataFrame(
        {
            "url": df["url"],
            "label": df["label"].astype(int),
            "source": "semihguner",
        }
    )


def load_harisudhan411() -> pd.DataFrame:
    df = pd.read_csv(RAW_DIR / "harisudhan411.csv")
    # status is inverted vs. our target label — see module docstring.
    label = 1 - df["status"].astype(int)
    return pd.DataFrame(
        {
            "url": df["url"],
            "label": label,
            "source": "harisudhan411",
        }
    )


def load_phiusiil() -> pd.DataFrame:
    df = pd.read_csv(RAW_DIR / "phiusiil.csv")
    # label is inverted vs. our target — see module docstring.
    label = 1 - df["label"].astype(int)
    return pd.DataFrame(
        {
            "url": df["URL"],
            "label": label,
            "source": "phiusiil",
        }
    )


def main() -> None:
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    frames = [
        load_mitake(),
        load_semihguner(),
        load_harisudhan411(),
        load_phiusiil(),
    ]
    combined = pd.concat(frames, ignore_index=True)

    # Drop null/empty urls and urls whose hostname has no dot (malformed
    # entries, e.g. binary garbage baked into the upstream mitake HF dataset
    # itself — confirmed byte-identical between the live HF load and our
    # saved data/raw/mitake.csv, so this is source data quality, not an
    # encoding bug in fetch/normalize). Small, fixed count — log and drop.
    is_empty = combined["url"].isna() | (combined["url"].astype(str).str.strip() == "")
    hostnames = combined["url"].map(get_hostname)
    is_no_dot_host = ~hostnames.str.contains(r"\.", regex=True)
    is_malformed = is_empty | is_no_dot_host

    print(f"Dropping malformed rows: {is_malformed.sum()} "
          f"(empty/null url: {is_empty.sum()}, no-dot hostname: {is_no_dot_host.sum()})")
    print(combined.loc[is_malformed, "source"].value_counts().to_string())
    print()

    combined = combined[~is_malformed].reset_index(drop=True)
    combined["url_canonical"] = combined["url"].map(canonicalize)

    total_in = len(combined)
    per_source_in = combined["source"].value_counts()

    is_dup = combined.duplicated(subset="url_canonical", keep="first")
    kept = combined[~is_dup].copy()
    dropped = combined[is_dup].copy()

    # For each dropped row, find which surviving row it duplicated.
    first_occurrence = (
        kept[["url_canonical", "url", "source"]]
        .rename(columns={"url": "kept_url", "source": "kept_source"})
    )
    dropped = dropped.merge(first_occurrence, on="url_canonical", how="left")
    dropped = dropped.rename(columns={"url": "dropped_url", "source": "dropped_source"})
    dropped = dropped[
        ["dropped_url", "dropped_source", "kept_url", "kept_source", "url_canonical", "label"]
    ]

    dropped.to_csv(PROCESSED_DIR / "duplicates_removed.csv", index=False)
    kept.drop(columns="url_canonical").to_csv(
        PROCESSED_DIR / "combined_dataset.csv", index=False
    )
    # Keep url_canonical in a companion file too? No — spec says combined_dataset.csv
    # is the final merged/deduped dataset; url_canonical was dedup-only scaffolding.

    print(f"Total rows in:  {total_in}")
    print(f"Total rows out: {len(kept)}")
    print(f"Duplicates removed: {len(dropped)}")
    print()
    print("Rows in per source:")
    print(per_source_in.to_string())
    print()
    print("Duplicates removed per source (the dropped copy's source):")
    print(dropped["dropped_source"].value_counts().to_string())
    print()
    print("Duplicates removed per source-pair (dropped_source -> kept_source):")
    pair_counts = dropped.groupby(["dropped_source", "kept_source"]).size()
    print(pair_counts.to_string())


if __name__ == "__main__":
    main()
