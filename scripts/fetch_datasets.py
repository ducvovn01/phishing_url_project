"""Download the four raw datasets (HF, Kaggle, UCI) into data/raw/. Reads credentials from .env."""
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_DIR = PROJECT_ROOT / "data" / "raw"

load_dotenv(PROJECT_ROOT / ".env")


def _require_env(var_name: str, source_hint: str) -> str:
    """Return the env var, or exit with a hint on where to get it."""
    value = os.environ.get(var_name)
    if not value:
        sys.exit(
            f"Missing credential: {var_name}\n"
            f"Get it from: {source_hint}\n"
            f"Set it in .env at {PROJECT_ROOT / '.env'}"
        )
    return value


def fetch_mitake() -> None:
    """Fetch Mitake/PhishingURLsANDBenignURLs from Hugging Face to mitake.csv."""
    import pandas as pd
    from datasets import load_dataset

    ds = load_dataset("Mitake/PhishingURLsANDBenignURLs")
    split = ds["train"] if "train" in ds else ds[list(ds.keys())[0]]
    df = split.to_pandas()
    assert isinstance(df, pd.DataFrame)  # only an iterator when batched=True

    out_path = RAW_DIR / "mitake.csv"
    df.to_csv(out_path, index=False)

    print(f"[mitake] {len(df)} rows, columns: {list(df.columns)}")
    print(f"[mitake] saved to {out_path}")


def fetch_semihguner() -> None:
    """Fetch the gated semihGuner2002/PhishingURLsDataset (needs HF_TOKEN) to parquet."""
    import pandas as pd
    from datasets import load_dataset

    token = _require_env(
        "HF_TOKEN",
        "https://huggingface.co/settings/tokens (log in with the account that "
        "accepted semihGuner2002/PhishingURLsDataset's terms first)",
    )

    ds = load_dataset("semihGuner2002/PhishingURLsDataset", token=token)
    split = ds["train"] if "train" in ds else ds[list(ds.keys())[0]]
    df = split.to_pandas()
    assert isinstance(df, pd.DataFrame)  # only an iterator when batched=True

    out_path = RAW_DIR / "semihguner.parquet"
    df.to_parquet(out_path, index=False)

    print(f"[semihguner] {len(df)} rows, columns: {list(df.columns)}")
    print(f"[semihguner] saved to {out_path}")


def fetch_harisudhan411() -> None:
    """Fetch harisudhan411/phishing-and-legitimate-urls from Kaggle to a CSV."""
    import zipfile

    import pandas as pd

    _require_env(
        "KAGGLE_USERNAME",
        "https://www.kaggle.com/settings -> API -> Create New Token (kaggle.json)",
    )
    _require_env(
        "KAGGLE_KEY",
        "https://www.kaggle.com/settings -> API -> Create New Token (kaggle.json)",
    )

    from kaggle.api.kaggle_api_extended import KaggleApi

    api = KaggleApi()
    api.authenticate()

    download_dir = RAW_DIR / "_harisudhan411_tmp"
    download_dir.mkdir(exist_ok=True)
    api.dataset_download_files(
        "harisudhan411/phishing-and-legitimate-urls",
        path=str(download_dir),
        unzip=False,
    )

    zips = list(download_dir.glob("*.zip"))
    if not zips:
        sys.exit(f"[harisudhan411] no zip downloaded into {download_dir}")
    with zipfile.ZipFile(zips[0]) as zf:
        zf.extractall(download_dir)

    csvs = list(download_dir.glob("*.csv"))
    if not csvs:
        sys.exit(f"[harisudhan411] no CSV found after extracting {zips[0]}")

    df = pd.read_csv(csvs[0])
    out_path = RAW_DIR / "harisudhan411.csv"
    df.to_csv(out_path, index=False)

    print(f"[harisudhan411] {len(df)} rows, columns: {list(df.columns)}")
    print(f"[harisudhan411] saved to {out_path}")


def fetch_phiusiil() -> None:
    """Fetch the PhiUSIIL dataset (UCI id 967): URL, TLD and label columns."""
    import pandas as pd
    from ucimlrepo import fetch_ucirepo

    # Item access: attribute access on ucimlrepo's dotdict is typed as optional.
    data = fetch_ucirepo(id=967)["data"]
    df = pd.concat(
        [data["features"][["URL", "TLD"]], data["targets"][["label"]]], axis=1
    )

    out_path = RAW_DIR / "phiusiil.csv"
    df.to_csv(out_path, index=False)

    print(f"[phiusiil] {len(df)} rows, columns: {list(df.columns)}")
    print(f"[phiusiil] saved to {out_path}")


if __name__ == "__main__":
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    fetch_mitake()
    fetch_semihguner()
    fetch_harisudhan411()
    fetch_phiusiil()
