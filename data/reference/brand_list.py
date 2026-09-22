# Combined brand/domain list for typosquat similarity matching (FR3 —
# brand-lookalike detection). Two sources, merged and deduped:
#
#   - CURATED_BRANDS: ~130 hand-picked names for payment platforms, banks,
#     tech giants and other frequent phishing-impersonation targets that
#     don't reliably show up in a global top-1000-by-traffic list (regional
#     banks, crypto exchanges, government agencies).
#   - Tranco top 1,000 registrable domains (https://tranco-list.eu/) — a
#     research-oriented "top sites" ranking designed to resist the list
#     manipulation that plain Alexa/Majestic rankings are vulnerable to.
#     List ID 8P4GV, generated 2026-09-21T22:00:01Z (30-day window,
#     2026-08-23 to 2026-09-21; sources: Chrome UX Report, Farsight,
#     Majestic, Cloudflare Radar, Umbrella; dowdall rank combination;
#     filterPLD=on so the list is already deduplicated to one row per
#     registrable/public-label domain). Cached at
#     data/reference/tranco_top1000.csv (fetched once via
#     https://tranco-list.eu/download/8P4GV/1000) so normal runs don't hit
#     the network — delete the cache file to force a re-download of
#     whatever the current daily list is.
#
# Both sources are reduced to the bare second-level label (TLD/public suffix
# stripped, lowercased — e.g. "paypal.com" -> "paypal") so they compare
# directly against the `domain_label` computed in extract_features.py
# (also suffix-stripped). This is what lets an exact-match check
# ("paypal.com" vs brand "paypal") be a plain string equality rather than a
# fuzzy one.
import csv
from pathlib import Path

import tldextract

REFERENCE_DIR = Path(__file__).resolve().parent
TRANCO_CACHE = REFERENCE_DIR / "tranco_top1000.csv"
TRANCO_LIST_URL = "https://tranco-list.eu/download/8P4GV/1000"

# tldextract ships a bundled public-suffix-list snapshot; suffix_list_urls=()
# disables the live fetch so this stays reproducible offline (see the same
# pattern in extract_features.py).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

CURATED_BRANDS = [
    # Payment / fintech
    "paypal", "stripe", "venmo", "square", "cashapp", "zelle", "wise",
    "revolut", "westernunion", "moneygram", "skrill", "payoneer", "klarna",
    "affirm", "afterpay",
    # Banks (major US / UK / AU / global)
    "chase", "wellsfargo", "bankofamerica", "boa", "citibank", "citi",
    "hsbc", "barclays", "lloydsbank", "natwest", "santander", "usbank",
    "capitalone", "pnc", "tdbank", "regions", "truist", "ally",
    "americanexpress", "amex", "discover", "goldmansachs", "morganstanley",
    "commonwealthbank", "nab", "anz", "westpac",
    # Crypto / exchanges (frequent phishing targets, thin traffic rank)
    "coinbase", "binance", "kraken", "blockchain", "metamask", "gemini",
    "bitfinex", "kucoin", "crypto",
    # Tech giants / major platforms
    "google", "microsoft", "apple", "amazon", "facebook", "meta",
    "instagram", "whatsapp", "twitter", "linkedin", "netflix", "youtube",
    "yahoo", "outlook", "office365", "icloud", "dropbox", "adobe",
    "spotify", "zoom", "slack", "github", "gitlab", "salesforce", "oracle",
    "ibm", "intuit", "quickbooks", "turbotax",
    # Shipping / delivery ("package delayed" phishing)
    "fedex", "ups", "dhl", "usps", "auspost", "royalmail",
    # E-commerce / marketplaces
    "ebay", "etsy", "walmart", "target", "bestbuy", "alibaba", "aliexpress",
    "shopify",
    # Telecom / ISP
    "att", "verizon", "tmobile", "sprint", "comcast", "xfinity", "vodafone",
    "telstra", "optus",
    # Government / official (tax / benefits phishing)
    "irs", "ssa", "medicare", "ato", "hmrc",
    # Streaming / gaming
    "steam", "playstation", "xbox", "nintendo", "disneyplus", "hulu",
    # Ride-share / travel
    "uber", "lyft", "airbnb", "booking", "expedia", "delta", "united",
    "americanairlines",
    # Other frequent phishing lures
    "docusign", "wetransfer", "dhlparcel",
]


def _download_tranco_top1000() -> str:
    """Fetch the cached list's source page fresh. Only runs when the cache
    file is missing — normal runs read TRANCO_CACHE and never touch the
    network (dataset *sourcing* may use live APIs per CLAUDE.md; this just
    avoids re-fetching the same list every run)."""
    import urllib.request

    with urllib.request.urlopen(TRANCO_LIST_URL, timeout=30) as resp:
        text = resp.read().decode("utf-8")
    TRANCO_CACHE.write_text(text, encoding="utf-8")
    return text


def _load_tranco_domains() -> list[str]:
    if not TRANCO_CACHE.exists():
        _download_tranco_top1000()
    with TRANCO_CACHE.open(newline="", encoding="utf-8") as f:
        return [domain for _rank, domain in csv.reader(f) if domain]


def _strip_suffix(domain: str) -> str:
    return _EXTRACT(domain).domain


def load_brand_list() -> list[str]:
    """Curated brands + Tranco top 1000, merged, deduped, as bare
    second-level labels (suffix stripped, lowercased). See module comment
    for source details."""
    tranco_labels = [_strip_suffix(d) for d in _load_tranco_domains()]
    combined = {b.strip().lower() for b in CURATED_BRANDS + tranco_labels if b.strip()}
    return sorted(combined)


if __name__ == "__main__":
    brands = load_brand_list()
    print(f"{len(CURATED_BRANDS)} curated + Tranco top 1000 -> {len(brands)} unique brand labels")
