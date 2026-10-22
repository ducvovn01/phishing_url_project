"""Pure ASGI middleware: request IDs, security headers, logging, body-size limit."""
import logging
import time

from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.errors import INTERNAL, error_response, request_id_from_scope

logger = logging.getLogger("phishing_api")

DOCS_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/redoc"})
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}
# The API serves JSON only; Swagger UI needs its CDN script, so /docs is left out.
API_ONLY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Frame-Options": "DENY",
}


class RequestContextMiddleware:
    """Gives each request an ID, adds security headers, logs one sanitized line and turns
    any unhandled exception into the contract's 500 response.

    The log line has method, matched route (never the raw path or query), status and
    duration; submitted URLs are in the body and are never logged.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = request_id_from_scope(scope)
        started = time.perf_counter()
        status = 0
        extra = {} if scope["path"] in DOCS_PATHS else API_ONLY_HEADERS

        async def send_with_headers(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = MutableHeaders(scope=message)
                headers["X-Request-ID"] = request_id
                for name, value in {**SECURITY_HEADERS, **extra}.items():
                    headers.setdefault(name, value)
            await send(message)

        try:
            await self.app(scope, receive, send_with_headers)
        except Exception as exc:
            logger.error("unhandled %s rid=%s", type(exc).__name__, request_id, exc_info=exc)
            if status:  # response already started; nothing safe left to send
                raise
            await error_response(scope, 500, "internal_error", INTERNAL)(
                scope, receive, send_with_headers)
        finally:
            route = scope.get("route")
            logger.info("%s %s %s %.1fms rid=%s", scope["method"],
                        getattr(route, "path", "(unmatched)"), status or 500,
                        (time.perf_counter() - started) * 1000, request_id)


class BodySizeLimitMiddleware:
    """Rejects request bodies over `max_bytes` with 413 before anything parses them.

    A declared Content-Length over the limit is refused without reading. Otherwise the body
    is read chunk by chunk (this also covers chunked uploads with no Content-Length) and
    reading stops as soon as the running total passes the limit, so at most
    max_bytes + one chunk is ever held. The buffered body is then replayed to the app.
    """

    def __init__(self, app: ASGIApp, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    declared = None
                if declared is not None and declared > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return

        chunks = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body = message.get("body", b"")
            total += len(body)
            if total > self.max_bytes:
                await self._reject(scope, receive, send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": b"".join(chunks), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = error_response(scope, 413, "payload_too_large",
                                  f"The request body is larger than {self.max_bytes} bytes.")
        await response(scope, receive, send)
