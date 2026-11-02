"""Runtime settings, read once from environment variables at startup.

No secrets are needed by this service. Invalid values stop startup instead of falling back
to something permissive (an empty or "*" CORS list is rejected, for example).
"""
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

BACKEND_DIR = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = BACKEND_DIR / "model_manifest.json"

# Fixed by the API contract (v1 draft), so not configurable.
MAX_BODY_BYTES = 8192
MAX_URL_LENGTH = 2048
MAX_SIGNALS = 10
RETRY_AFTER_SECONDS = 1


class ConfigError(ValueError):
    """An environment variable holds a value the service refuses to run with."""


@dataclass(frozen=True)
class Settings:
    manifest_path: Path = DEFAULT_MANIFEST
    cors_origins: tuple[str, ...] = ("http://localhost:5173",)
    # In-flight /analyze requests per worker process; more are refused with 503. The default
    # of 2 comes from the real-inference cap sweep (README, "Concurrency cap sweep").
    max_concurrency: int = 2
    docs_enabled: bool = True
    # Per-client limit on /analyze (contract section 5.1): a burst of up to
    # rate_limit_requests, given back at rate_limit_requests per rate_limit_window_seconds.
    # Over it a request gets 429. Turning it off is for the before/after demo only.
    rate_limit_enabled: bool = True
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    # Demo only, for the before/after denial of service evidence. Off, the 503 cap never
    # refuses (in-flight requests are still counted) and the 413 body limit is not installed.
    concurrency_cap_enabled: bool = True
    body_limit_enabled: bool = True
    # Demo only: every /analyze sleeps this long in its worker thread while holding its
    # concurrency slot, a stand-in for an expensive model call.
    demo_analyze_delay_ms: int = 0
    # Detection evasion defence (P2, experiments/FINDINGS.md): score the folded look-alike
    # text instead of the raw one. Turning it off is for the before/after demo only.
    homoglyph_defence: bool = True


def _parse_origins(raw: str) -> tuple[str, ...]:
    origins = tuple(o.strip() for o in raw.split(",") if o.strip())
    if not origins:
        raise ConfigError("CORS_ALLOW_ORIGINS is empty")
    for origin in origins:
        parts = urlsplit(origin)
        if (origin == "*" or parts.scheme not in ("http", "https") or not parts.hostname
                or parts.path or parts.query or parts.fragment or "*" in origin):
            raise ConfigError(f"CORS_ALLOW_ORIGINS entry {origin!r} is not an exact "
                              "scheme://host[:port] origin")
    return origins


def _parse_bool(name: str, raw: str) -> bool:
    value = raw.strip().lower()
    if value in ("1", "true", "yes"):
        return True
    if value in ("0", "false", "no"):
        return False
    raise ConfigError(f"{name} must be true or false")


def _parse_int(name: str, raw: str, low: int, high: int) -> int:
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer") from None
    if not low <= value <= high:
        raise ConfigError(f"{name} must be between {low} and {high}")
    return value


def load_settings(env: dict[str, str] | None = None) -> Settings:
    """Settings from `env` (default os.environ); unset variables keep the defaults."""
    env = os.environ if env is None else env
    settings = Settings()
    kwargs = {}
    if "MODEL_MANIFEST" in env:
        kwargs["manifest_path"] = Path(env["MODEL_MANIFEST"])
    if "CORS_ALLOW_ORIGINS" in env:
        kwargs["cors_origins"] = _parse_origins(env["CORS_ALLOW_ORIGINS"])
    if "ANALYZE_MAX_CONCURRENCY" in env:
        kwargs["max_concurrency"] = _parse_int("ANALYZE_MAX_CONCURRENCY",
                                               env["ANALYZE_MAX_CONCURRENCY"], 1, 64)
    if "API_DOCS_ENABLED" in env:
        kwargs["docs_enabled"] = _parse_bool("API_DOCS_ENABLED", env["API_DOCS_ENABLED"])
    if "RATE_LIMIT_ENABLED" in env:
        kwargs["rate_limit_enabled"] = _parse_bool("RATE_LIMIT_ENABLED", env["RATE_LIMIT_ENABLED"])
    if "RATE_LIMIT_REQUESTS" in env:
        kwargs["rate_limit_requests"] = _parse_int("RATE_LIMIT_REQUESTS",
                                                   env["RATE_LIMIT_REQUESTS"], 1, 10000)
    if "RATE_LIMIT_WINDOW_SECONDS" in env:
        kwargs["rate_limit_window_seconds"] = _parse_int("RATE_LIMIT_WINDOW_SECONDS",
                                                         env["RATE_LIMIT_WINDOW_SECONDS"], 1, 3600)
    if "CONCURRENCY_CAP_ENABLED" in env:
        kwargs["concurrency_cap_enabled"] = _parse_bool("CONCURRENCY_CAP_ENABLED",
                                                        env["CONCURRENCY_CAP_ENABLED"])
    if "BODY_LIMIT_ENABLED" in env:
        kwargs["body_limit_enabled"] = _parse_bool("BODY_LIMIT_ENABLED", env["BODY_LIMIT_ENABLED"])
    if "DEMO_ANALYZE_DELAY_MS" in env:
        kwargs["demo_analyze_delay_ms"] = _parse_int("DEMO_ANALYZE_DELAY_MS",
                                                     env["DEMO_ANALYZE_DELAY_MS"], 0, 5000)
    if "HOMOGLYPH_DEFENCE" in env:
        kwargs["homoglyph_defence"] = _parse_bool("HOMOGLYPH_DEFENCE", env["HOMOGLYPH_DEFENCE"])
    return Settings(**{**settings.__dict__, **kwargs})
