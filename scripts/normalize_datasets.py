"""
Merge the four raw datasets into (url, label, source), drop malformed rows and
duplicates. Writes combined_dataset.csv and duplicates_removed.csv to data/processed/.

label: 1 = phishing, 0 = legitimate. Label directions, checked by sampling raw URLs:
  - mitake: already 0=legit, 1=phishing.
  - semihguner: already 0=benign, 1=phishing (dataset card).
  - harisudhan411: status is inverted (0=phishing), so label = 1 - status.
  - phiusiil: label is inverted (1=legitimate), so label = 1 - label.
"""
import re
from pathlib import Path

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"
PROCESSED_DIR = PROJECT_ROOT / "data" / "processed"

_PROTOCOL_RE = re.compile(r"^[a-z][a-z0-9+.-]*://")


def get_hostname(url: str) -> str:
    """Return the lowercased hostname without scheme, path, query, userinfo or port."""
    u = str(url).strip()
    u = _PROTOCOL_RE.sub("", u.lower())
    u = u.split("/", 1)[0].split("?", 1)[0].split("@")[-1].split(":")[0]
    return u


def canonicalize(url: str) -> str:
    """Lowercase, strip protocol and trailing slash, for dedup matching only.

    String ops instead of urlsplit, which raises on stray characters such as
    an unescaped "[" in a query string."""
    if not isinstance(url, str):
        return ""
    u = url.strip().lower()
    u = _PROTOCOL_RE.sub("", u)
    u = u.rstrip("/")
    return u


def load_mitake() -> pd.DataFrame:
    """Load mitake.csv in the common schema."""
    df = pd.read_csv(RAW_DIR / "mitake.csv")
    return pd.DataFrame(
        {
            "url": df["url"],
            "label": df["label"].astype(int),
            "source": "mitake",
        }
    )


def load_semihguner() -> pd.DataFrame:
    """Load semihguner.parquet in the common schema."""
    df = pd.read_parquet(RAW_DIR / "semihguner.parquet")
    return pd.DataFrame(
        {
            "url": df["url"],
            "label": df["label"].astype(int),
            "source": "semihguner",
        }
    )


def load_harisudhan411() -> pd.DataFrame:
    """Load harisudhan411.csv in the common schema, flipping the label."""
    df = pd.read_csv(RAW_DIR / "harisudhan411.csv")
    # status is inverted (see module docstring).
    label = 1 - df["status"].astype(int)
    return pd.DataFrame(
        {
            "url": df["url"],
            "label": label,
            "source": "harisudhan411",
        }
    )


def load_phiusiil() -> pd.DataFrame:
    """Load phiusiil.csv in the common schema, flipping the label."""
    df = pd.read_csv(RAW_DIR / "phiusiil.csv")
    # label is inverted (see module docstring).
    label = 1 - df["label"].astype(int)
    return pd.DataFrame(
        {
            "url": df["URL"],
            "label": label,
            "source": "phiusiil",
        }
    )


def main() -> None:
    """Load, clean and deduplicate the sources, then write the CSVs and print counts."""
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    frames = [
        load_mitake(),
        load_semihguner(),
        load_harisudhan411(),
        load_phiusiil(),
    ]
    combined = pd.concat(frames, ignore_index=True)

    # Drop null/empty URLs and no-dot hostnames. The malformed rows (e.g. binary
    # garbage) come from the upstream mitake data, not from our fetch/normalize.
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

    # Map each dropped row to the kept row it duplicated.
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
    # url_canonical is dedup-only scaffolding, so it is not saved.

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
