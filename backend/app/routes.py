"""GET /health and POST /analyze."""
import threading
from dataclasses import asdict

from fastapi import APIRouter, Depends, Request
from starlette.concurrency import run_in_threadpool

from app.config import MAX_BODY_BYTES, RETRY_AFTER_SECONDS
from app.errors import INVALID_BODY, INVALID_URL, INTERNAL, RATE_LIMITED, ApiError
from app.schemas import AnalyzeRequest, AnalyzeResponse, ErrorResponse, HealthResponse, error_example

router = APIRouter()


class ConcurrencyGuard:
    """Non-blocking cap on in-flight analyses in this process. Over the cap a request is
    refused at once (503) instead of queueing, so a burst cannot pile up work. With several
    worker processes the total capacity is workers x limit."""

    def __init__(self, limit: int):
        self.limit = limit
        self._in_flight = 0
        self._lock = threading.Lock()

    @property
    def in_flight(self) -> int:
        return self._in_flight

    def try_acquire(self) -> bool:
        with self._lock:
            if self._in_flight >= self.limit:
                return False
            self._in_flight += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._in_flight -= 1


def _error_doc(description: str, code: str, message: str, details: list[dict] | None = None,
               headers: dict | None = None) -> dict:
    doc = {"model": ErrorResponse, "description": description,
           "content": {"application/json": {"example": error_example(code, message, details)}}}
    if headers:
        doc["headers"] = headers
    return doc


INTERNAL_DOC = _error_doc("Unexpected server failure; generic message only.",
                          "internal_error", INTERNAL)
NOT_FOUND_DOC = _error_doc("Unknown path.", "not_found", "No such endpoint.")
METHOD_DOC = _error_doc("Wrong HTTP method for this path.", "method_not_allowed",
                        "This endpoint does not support that HTTP method.")


def require_json(request: Request) -> None:
    """POST /analyze takes application/json only (charset parameter allowed)."""
    media_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if media_type != "application/json":
        raise ApiError(422, "validation_error", INVALID_BODY,
                       [{"field": "body", "message": "Content-Type must be application/json."}])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health",
    description="`{\"status\": \"ok\", \"model_loaded\": true}` while the API is serving. The "
                "API only starts after the model's SHA-256 has been verified and the model "
                "loaded, so there is no degraded mode: if this does not answer, the backend "
                "is unavailable.",
    responses={404: NOT_FOUND_DOC, 405: METHOD_DOC, 500: INTERNAL_DOC},
)
async def health(request: Request) -> HealthResponse:
    if getattr(request.app.state, "model_service", None) is None:
        raise ApiError(500, "internal_error", INTERNAL)
    return HealthResponse(status="ok", model_loaded=True)


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    dependencies=[Depends(require_json)],
    summary="Score a URL as phishing or legitimate",
    description=(
        "Scores the URL **text** with the verified A2 char n-gram model. The URL is never "
        "fetched, resolved or looked up anywhere.\n\n"
        "- Body: exactly `{\"url\": string}`, `Content-Type: application/json`, at most "
        f"{MAX_BODY_BYTES} bytes.\n"
        "- `label` is `phishing` when `phishing_probability >= threshold`; `confidence` is the "
        "probability of the returned label; `trust_score` is "
        "`round(100 * (1 - phishing_probability))`.\n"
        "- `signals` (0-10): `ngram` items first, by descending absolute `weight` (net "
        "log-odds of the n-grams inside the span), then `rule` items (`weight` null). "
        "`start`/`end` are Unicode code-point offsets into `analysed_url`.\n"
        "- The example values are real model output for the example input."
    ),
    responses={
        404: NOT_FOUND_DOC,
        405: METHOD_DOC,
        413: _error_doc(f"Body larger than {MAX_BODY_BYTES} bytes (checked before parsing).",
                        "payload_too_large",
                        f"The request body is larger than {MAX_BODY_BYTES} bytes."),
        422: _error_doc("Missing, empty, wrong-type, too long or otherwise invalid URL; "
                        "extra fields; malformed JSON; non-JSON Content-Type.",
                        "validation_error", INVALID_URL,
                        [{"field": "url", "message": "Must be 1 to 2048 characters."}]),
        429: _error_doc("This client sent too many requests (checked before the body is "
                        "read, so every request counts); retry after `Retry-After` seconds.",
                        "rate_limited", RATE_LIMITED,
                        headers={"Retry-After": {"description": "Whole seconds to wait, "
                                                                "at least 1.",
                                                 "schema": {"type": "integer"}}}),
        503: _error_doc("Too many analyses in progress; retry after `Retry-After` seconds.",
                        "service_busy", "The service is busy. Please try again in a moment.",
                        headers={"Retry-After": {"description": "Seconds to wait.",
                                                 "schema": {"type": "integer"}}}),
        500: INTERNAL_DOC,
    },
)
async def analyze(payload: AnalyzeRequest, request: Request) -> AnalyzeResponse:
    state = request.app.state
    if not state.guard.try_acquire():
        raise ApiError(503, "service_busy", "The service is busy. Please try again in a moment.",
                       headers={"Retry-After": str(RETRY_AFTER_SECONDS)})
    try:
        # run_in_threadpool waits for the worker thread even if the client disconnects, so
        # the slot is released only once the analysis has really finished.
        analysis = await run_in_threadpool(state.model_service.analyze, payload.url)
    finally:
        state.guard.release()
    fields = asdict(analysis)
    fields.pop("model_input")
    return AnalyzeResponse(**fields)
