"""Rule signals: simple checks on analysed_url that run alongside the model.

The rules never change the model's score, so their weight is null and every explanation
says so. Each one quotes the A2 dataset count behind it from app/data/rule_stats.json
(built by backend/scripts/build_rule_stats.py), so the claims stay about that dataset
rather than about websites in general. Host parsing mirrors preprocess_url_masked().
"""
import json
from dataclasses import dataclass
from pathlib import Path

from app.a2 import (
    BRAND_SET,
    EXTRACT,
    IP_HOSTNAME_RE,
    PORT_RE,
    normalize_homoglyphs,
    normalize_leetspeak,
)

STATS_PATH = Path(__file__).resolve().parents[1] / "data" / "rule_stats.json"
STATS = json.loads(STATS_PATH.read_text(encoding="utf-8"))
TLD_STATS: dict[str, dict] = STATS["tld"]["suffixes"]
LONG_URL_CUTOFF: int = STATS["long_url"]["max_typical_length"]
LOOKALIKE_MIN_LABEL_LENGTH: int = STATS["brand_lookalike"]["min_label_length"]

PREFIX = "Rule check, separate from the model score: "


@dataclass(frozen=True)
class Host:
    """Host of analysed_url without port or userinfo, at analysed[start:end]."""
    start: int
    end: int
    text: str


def find_host(analysed: str) -> Host | None:
    """Same host split as preprocess_url_masked(): authority up to / ? #, after the last @."""
    authority = analysed.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    host = authority.split("@")[-1]
    host_no_port = PORT_RE.sub("", host)
    if not host_no_port:
        return None
    start = len(authority) - len(host)
    return Host(start, start + len(host_no_port), host_no_port)


def brand_lookalike(label: str) -> str | None:
    """The brand `label` imitates by character swaps (paypa1 -> paypal), or None.

    Uses the A2 homoglyph and leetspeak maps and brand list; a label that is itself a
    brand, or is shorter than the minimum length, is never a look-alike.
    """
    if len(label) < LOOKALIKE_MIN_LABEL_LENGTH or label in BRAND_SET:
        return None
    normalized = normalize_leetspeak(normalize_homoglyphs(label))
    return normalized if normalized != label and normalized in BRAND_SET else None


def _pct(share: float) -> str:
    """Percentage that never rounds a share below 1 up to "100.0%"."""
    text = f"{share:.1%}"
    return f"{share:.2%}" if share < 1 and text == "100.0%" else text


def _span(analysed: str, start: int, text: str) -> tuple[int | None, int | None, str | None]:
    """(start, end, text) if `text` really sits at `start` in analysed, else all None."""
    end = start + len(text)
    if text and analysed[start:end] == text:
        return start, end, text
    return None, None, None


def _rule(rule_id: str, title: str, explanation: str,
          span: tuple[int | None, int | None, str | None]) -> dict:
    start, end, text = span
    return {
        "id": rule_id,
        "kind": "rule",
        "title": title,
        "direction": "phishing",
        "weight": None,
        "start": start,
        "end": end,
        "text": text,
        "explanation": PREFIX + explanation,
    }


def rule_signals(analysed: str) -> list[dict]:
    """Rule signals that apply to analysed_url, in a fixed order."""
    signals = []
    host = find_host(analysed)
    if host is not None:
        host_span = _span(analysed, host.start, host.text)
        ext = EXTRACT(host.text)
        if IP_HOSTNAME_RE.match(host.text):
            s = STATS["ip_host"]
            signals.append(_rule(
                "rule-ip-host", "IP address used as host",
                f"in the A2 dataset, {_pct(s['phishing_share'])} of the {s['rows']:,} URLs with a "
                "raw IP address as host were phishing.", host_span))
        if "xn--" in host.text:
            s = STATS["punycode_host"]
            signals.append(_rule(
                "rule-punycode", "Punycode (xn--) host",
                "punycode can hide look-alike characters, and in the A2 dataset "
                f"{_pct(s['phishing_share'])} of the {s['rows']:,} URLs with a punycode host "
                "were phishing.", host_span))
        if ext.suffix in TLD_STATS:
            s = TLD_STATS[ext.suffix]
            signals.append(_rule(
                "rule-unusual-tld", "Domain ending common in phishing data",
                f"in the A2 dataset, {_pct(s['phishing_share'])} of the {s['rows']:,} URLs "
                f"ending in .{ext.suffix} were phishing.",
                _span(analysed, host.end - len(ext.suffix), ext.suffix)))
        brand = brand_lookalike(ext.domain) if ext.domain else None
        if brand is not None:
            s = STATS["brand_lookalike"]
            label_start = host.start + (len(ext.subdomain) + 1 if ext.subdomain else 0)
            signals.append(_rule(
                "rule-brand-lookalike", "Brand look-alike domain",
                f"this domain name reads as the brand name \"{brand}\" once look-alike "
                "characters are swapped back (for example 0 to o, or Cyrillic а to a), and "
                f"in the A2 dataset {_pct(s['phishing_share'])} of the {s['rows']} such URLs "
                "were phishing.", _span(analysed, label_start, ext.domain)))
    if len(analysed) > LONG_URL_CUTOFF:
        s = STATS["long_url"]
        signals.append(_rule(
            "rule-long-url", "Unusually long URL",
            f"it is longer than {s['legit_quantile']:.0%} of legitimate URLs in the A2 dataset "
            f"(over {LONG_URL_CUTOFF} characters without the scheme), and "
            f"{_pct(s['phishing_share'])} of the {s['rows']:,} URLs that long there were "
            "phishing.", (None, None, None)))
    return signals
