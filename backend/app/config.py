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
    # In-flight /analyze requests per worker process; more are refused with 503.
    max_concurrency: int = 4
    docs_enabled: bool = True


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
        try:
            limit = int(env["ANALYZE_MAX_CONCURRENCY"])
        except ValueError:
            raise ConfigError("ANALYZE_MAX_CONCURRENCY must be an integer") from None
        if not 1 <= limit <= 64:
            raise ConfigError("ANALYZE_MAX_CONCURRENCY must be between 1 and 64")
        kwargs["max_concurrency"] = limit
    if "API_DOCS_ENABLED" in env:
        kwargs["docs_enabled"] = _parse_bool("API_DOCS_ENABLED", env["API_DOCS_ENABLED"])
    return Settings(**{**settings.__dict__, **kwargs})
