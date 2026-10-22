"""Bridge to the A2 code in scripts/, so the backend reuses it instead of copying it.

The pickled pipeline in models/char_ngram.joblib refers to
`extract_features.preprocess_url_masked` by module name, so scripts/ has to be importable
as top-level modules before the model is unpickled. Everything the backend needs from A2
is re-exported here.
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = PROJECT_ROOT / "scripts"
# brand_list.load_brand_list() downloads the Tranco list when this cache is missing.
# The API must never make outbound requests, so refuse to import without it.
BRAND_CACHE = PROJECT_ROOT / "data" / "reference" / "tranco_top1000.csv"

if not BRAND_CACHE.is_file():
    raise RuntimeError(f"{BRAND_CACHE.relative_to(PROJECT_ROOT)} is missing; importing the A2 "
                       "feature code would download it. Restore it from the repository.")
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import extract_features  # noqa: E402

BRAND_MASK: str = extract_features.BRAND_MASK
BRAND_SET: set[str] = extract_features._BRAND_SET
EXTRACT = extract_features._EXTRACT  # tldextract with the bundled suffix list (offline)
IP_HOSTNAME_RE = extract_features._IP_HOSTNAME_RE
PORT_RE = extract_features._PORT_RE
normalize_homoglyphs = extract_features.normalize_homoglyphs
normalize_leetspeak = extract_features.normalize_leetspeak
preprocess_url = extract_features.preprocess_url
preprocess_url_masked = extract_features.preprocess_url_masked
