"""URL input policy for POST /analyze (pure functions, no HTTP).

- Outer whitespace is trimmed with str.strip(), as scripts/predict.py does.
- 1 to 2048 Unicode code points after trimming.
- No whitespace, control (Cc), invisible formatting (Cf, e.g. zero-width and bidi
  override characters) or surrogate (Cs) code points anywhere.
- Scheme optional; if present it must be http:// or https://. "host:port" and
  "host.tld:user@..." prefixes are not schemes. Other schemes (javascript:, data:, ftp://,
  file:, mailto: ...) are rejected rather than analysed as if they were web links.
- Unicode hostnames and "§" are accepted: the text is only analysed, never fetched.
"""
import re
import unicodedata

from pydantic_core import PydanticCustomError

from app.config import MAX_URL_LENGTH

ALLOWED_SCHEMES = frozenset({"http", "https"})
REJECTED_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp", "Zs"})
_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*):")


def _has_scheme(url: str) -> re.Match | None:
    """The scheme match, unless the prefix is really a host ("example.com:443", "localhost:80")."""
    match = _SCHEME_RE.match(url)
    if match is None:
        return None
    after = url[match.end():match.end() + 1]
    if after.isdigit() or "." in match.group(1):
        return None
    return match


def check_url(value: str) -> str:
    """Return the trimmed URL or raise PydanticCustomError with a user-facing message."""
    url = value.strip()
    if not 1 <= len(url) <= MAX_URL_LENGTH:
        raise PydanticCustomError("url_length", f"Must be 1 to {MAX_URL_LENGTH} characters.")
    if any(ch.isspace() or unicodedata.category(ch) in REJECTED_CATEGORIES for ch in url):
        raise PydanticCustomError(
            "url_characters",
            "Must not contain spaces, control characters or invisible formatting characters.")
    match = _has_scheme(url)
    if match is not None:
        rest = url[match.end():]
        if match.group(1).lower() not in ALLOWED_SCHEMES or not rest.startswith("//"):
            raise PydanticCustomError(
                "url_scheme", "Only http:// and https:// URLs, or URLs without a scheme, "
                              "are supported.")
        if not rest[2:]:
            raise PydanticCustomError("url_empty", "Must contain more than the scheme.")
    return url
