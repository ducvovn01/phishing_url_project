"""One error shape for every failure: {"error": {code, message, details, request_id}}.

Messages are fixed strings; exception text, tracebacks and paths never reach a response.
"""
import logging
import secrets
from collections.abc import Iterable

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("phishing_api")

INVALID_URL = "That doesn't look like a valid URL."
INVALID_BODY = "The request body must be a JSON object with a single \"url\" field."
INTERNAL = "Something went wrong while analysing the URL. Please try again."
MAX_DETAILS = 10
MAX_FIELD_LENGTH = 64


class ApiError(Exception):
    """Raised by the app for a contract error response."""

    def __init__(self, status: int, code: str, message: str,
                 details: Iterable[dict] = (), headers: dict[str, str] | None = None):
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.details = list(details)
        self.headers = headers


def new_request_id() -> str:
    return secrets.token_hex(4)


def request_id_from_scope(scope) -> str:
    state = scope.setdefault("state", {})
    if "request_id" not in state:
        state["request_id"] = new_request_id()
    return state["request_id"]


def error_response(scope, status: int, code: str, message: str,
                   details: Iterable[dict] = (), headers: dict[str, str] | None = None
                   ) -> JSONResponse:
    body = {"error": {"code": code, "message": message, "details": list(details),
                      "request_id": request_id_from_scope(scope)}}
    return JSONResponse(body, status_code=status, headers=headers)


_PYDANTIC_MESSAGES = {
    "missing": "Field required.",
    "string_type": "Must be a string.",
    "extra_forbidden": "Unexpected field.",
    "json_invalid": "Request body must be valid JSON.",
    "model_attributes_type": "Must be a JSON object.",
    "dict_type": "Must be a JSON object.",
}


def validation_details(errors: Iterable[dict]) -> list[dict]:
    """Contract details from Pydantic/FastAPI errors; custom URL errors keep their message."""
    details = []
    for err in errors:
        loc = [str(part) for part in err.get("loc", ())]
        names = loc[1:] if loc[:1] == ["body"] else loc
        etype = err.get("type", "")
        if etype == "json_invalid" or not names:
            field = "body"
        else:
            field = ".".join(names)[:MAX_FIELD_LENGTH]
        if etype.startswith("url_"):
            message = err.get("msg", "Invalid value.")
        elif field == "body" and etype == "missing":
            message = "Request body is required."
        else:
            message = _PYDANTIC_MESSAGES.get(etype, "Invalid value.")
        details.append({"field": field, "message": message})
    return details[:MAX_DETAILS]


async def _api_error(request: Request, exc: ApiError) -> JSONResponse:
    return error_response(request.scope, exc.status, exc.code, exc.message, exc.details,
                          exc.headers)


async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
    details = validation_details(exc.errors())
    message = INVALID_URL if any(d["field"] == "url" for d in details) else INVALID_BODY
    return error_response(request.scope, 422, "validation_error", message, details)


async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    if exc.status_code == 404:
        return error_response(request.scope, 404, "not_found", "No such endpoint.")
    if exc.status_code == 405:
        allow = (exc.headers or {}).get("Allow")
        return error_response(request.scope, 405, "method_not_allowed",
                              "This endpoint does not support that HTTP method.",
                              headers={"Allow": allow} if allow else None)
    if exc.status_code == 400:
        # FastAPI raises 400 when the body cannot be decoded at all (bad UTF-8, nesting).
        return error_response(request.scope, 422, "validation_error", INVALID_BODY,
                              [{"field": "body", "message": "Request body must be valid JSON."}])
    if exc.status_code == 413:
        return error_response(request.scope, 413, "payload_too_large",
                              "The request body is too large.")
    logger.error("unexpected HTTP %s rid=%s", exc.status_code,
                 request_id_from_scope(request.scope))
    return error_response(request.scope, 500, "internal_error", INTERNAL)


def install_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(ApiError, _api_error)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
