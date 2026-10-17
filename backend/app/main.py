"""FastAPI app: verified model loaded once at startup, then shared by all requests.

Run from backend/:  uvicorn app.main:app --host 127.0.0.1 --port 8000
"""
import logging
from collections.abc import Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import MAX_BODY_BYTES, Settings, load_settings
from app.errors import install_error_handlers
from app.middleware import BodySizeLimitMiddleware, RequestContextMiddleware
from app.routes import ConcurrencyGuard, router
from app.services.model_service import ModelService

logger = logging.getLogger("phishing_api")

DESCRIPTION = """
Scores URL **text** as phishing or legitimate with the A2 char n-gram + logistic regression
model, and explains the score. Nothing is ever fetched: no HTTP request, DNS or WHOIS
lookup is made for a submitted URL.

All errors share one shape: `{"error": {"code", "message", "details", "request_id"}}`.
"""


def _configure_logging() -> None:
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False


def _load_model(settings: Settings) -> ModelService:
    return ModelService.from_manifest(settings.manifest_path)


def create_app(settings: Settings | None = None,
               load_model: Callable[[Settings], ModelService] = _load_model) -> FastAPI:
    """Build the app. `load_model` runs at startup; if it raises, startup fails."""
    _configure_logging()
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        service = load_model(settings)
        app.state.model_service = service
        manifest = getattr(service, "manifest", None)
        if manifest is not None:
            logger.info("model %s %s loaded, sha256 %s verified, threshold %s",
                        manifest.name, manifest.version, manifest.sha256[:12],
                        service.threshold)
        yield
        app.state.model_service = None

    app = FastAPI(
        title="Phishing URL Detector API",
        version="1.0.0",
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
    )
    app.state.settings = settings
    app.state.guard = ConcurrencyGuard(settings.max_concurrency)
    app.state.model_service = None
    install_error_handlers(app)
    app.include_router(router)
    # Added innermost first: CORS wraps everything, so error responses get CORS headers too.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=MAX_BODY_BYTES)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_origins),
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        expose_headers=["Retry-After", "X-Request-ID"],
        allow_credentials=False,
        max_age=600,
    )
    return app


app = create_app()
