"""Per-client rate limit on /analyze: 429 rate_limited with Retry-After (contract 5.1).

This is the first layer. The 503 concurrency cap in routes.py stays behind it as the
second: 429 means "this client asked too often", 503 means "busy for everyone".
"""
import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable

from starlette.types import ASGIApp, Receive, Scope, Send

from app.errors import RATE_LIMITED, error_response

LIMITED_PATHS = frozenset({"/analyze"})
# Bound on the client store. At about 250 bytes an entry this is a few MB at most.
MAX_CLIENTS = 10_000


class RateLimiter:
    """Token bucket per client key. A client may send up to `requests` at once and gets
    them back at `requests` per `window_seconds`, so a steady flood is held to that rate.

    The store is an LRU of at most `max_clients` keys. Each request moves its client to the
    most recent end, so a client that keeps sending is never the one evicted. The evicted
    client is the one idle longest. If it was idle a whole window its bucket was full again,
    so forgetting it changes nothing. A limit is only lost when more than `max_clients`
    different addresses arrive within one window, and the 503 cap still bounds that case.
    """

    def __init__(self, requests: int, window_seconds: float, max_clients: int = MAX_CLIENTS,
                 clock: Callable[[], float] = time.monotonic):
        self.capacity = float(requests)
        self.rate = requests / window_seconds  # tokens given back per second
        self.max_clients = max_clients
        self._clock = clock
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()  # (tokens, at)
        self._lock = threading.Lock()

    def __len__(self) -> int:
        return len(self._buckets)

    def check(self, key: str) -> int | None:
        """Spend one request for `key`. Returns None if it is allowed, otherwise the whole
        seconds until the next one will be (always at least 1), for Retry-After."""
        with self._lock:
            now = self._clock()
            tokens, at = self._buckets.pop(key, (self.capacity, now))
            tokens = min(self.capacity, tokens + (now - at) * self.rate)
            if tokens >= 1:
                tokens -= 1
                retry_after = None
            else:
                # Rounded up, so a client that waits this long is sure to get in.
                retry_after = math.ceil((1 - tokens) / self.rate)
            self._buckets[key] = (tokens, now)  # re-inserted at the most recent end
            if len(self._buckets) > self.max_clients:
                self._buckets.popitem(last=False)
            return retry_after


class RateLimitMiddleware:
    """Applies `limiter` to LIMITED_PATHS before the body is read. Every request counts
    whatever its body (malformed or oversized too), and a limited client costs no parsing
    or model time.

    The client key is the socket peer address in the ASGI scope (the port is dropped, it
    changes per connection). No header such as X-Forwarded-For is read here. Uvicorn by
    default rewrites the peer address from X-Forwarded-For when the peer is 127.0.0.1, so
    the server is run with --no-proxy-headers (README). A scope with no client (a Unix
    socket) falls into one shared "unknown" bucket.
    """

    def __init__(self, app: ASGIApp, limiter: RateLimiter):
        self.app = app
        self.limiter = limiter

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] not in LIMITED_PATHS:
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        retry_after = self.limiter.check(client[0] if client else "unknown")
        if retry_after is None:
            await self.app(scope, receive, send)
            return
        response = error_response(scope, 429, "rate_limited", RATE_LIMITED,
                                  headers={"Retry-After": str(retry_after)})
        await response(scope, receive, send)
