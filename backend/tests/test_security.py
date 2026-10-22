"""Body limit, overload guard, CORS, config hygiene, no outbound calls, sanitized logs."""
import asyncio
import logging
import socket
import subprocess
import threading
import time
import urllib.request
from dataclasses import replace

import httpx2 as httpx
import pytest
import uvicorn

from app.config import ConfigError, Settings, load_settings
from app.main import create_app
from conftest import FakeService, assert_error, make_client

ALLOWED_ORIGIN = "http://localhost:5173"


def body_of_size(size: int) -> bytes:
    """A valid {"url": ...} JSON body padded with trailing whitespace to exactly `size` bytes."""
    body = b'{"url": "example.com"}'
    return body + b" " * (size - len(body))


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ---- body size limit -------------------------------------------------------------------

@pytest.fixture(scope="module")
def fake_client():
    with make_client(FakeService()) as c:
        yield c


def test_limit_boundary_with_content_length(fake_client):
    headers = {"Content-Type": "application/json"}
    ok = fake_client.post("/analyze", content=body_of_size(8192), headers=headers)
    assert ok.status_code == 200, ok.text
    assert_error(fake_client.post("/analyze", content=body_of_size(8193), headers=headers),
                 413, "payload_too_large")


def test_oversized_body_on_any_path_is_413(fake_client):
    assert_error(fake_client.post("/nope", content=b"x" * 9000), 413, "payload_too_large")


@pytest.mark.anyio
async def test_limit_boundary_chunked_without_content_length():
    seen_headers = []
    app = create_app(Settings(), load_model=lambda _: FakeService())

    async def recording(scope, receive, send):
        if scope["type"] == "http":
            seen_headers.append({k.lower() for k, _ in scope["headers"]})
        await app(scope, receive, send)

    async def chunks(size: int):
        body = body_of_size(size)
        for i in range(0, len(body), 1000):
            yield body[i:i + 1000]

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=recording)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            headers = {"Content-Type": "application/json"}
            ok = await c.post("/analyze", content=chunks(8192), headers=headers)
            too_big = await c.post("/analyze", content=chunks(8193), headers=headers)
    assert all(b"content-length" not in h for h in seen_headers)
    assert ok.status_code == 200, ok.text
    assert_error(too_big, 413, "payload_too_large")


def raw_request(port: int, head: str, body_parts: list[bytes]) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(head.encode("ascii"))
        for part in body_parts:
            s.sendall(part)
        data = b""
        try:
            while chunk := s.recv(65536):
                data += chunk
        except ConnectionResetError:
            pass
    return data


def chunked(body: bytes, size: int = 1000) -> list[bytes]:
    parts = [b"%x\r\n%s\r\n" % (len(body[i:i + size]), body[i:i + size])
             for i in range(0, len(body), size)]
    return parts + [b"0\r\n\r\n"]


def test_limit_on_real_uvicorn_server():
    """End to end over a real socket: chunked bodies and a huge declared Content-Length."""
    app = create_app(Settings(), load_model=lambda _: FakeService())
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=0, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started:
            assert time.monotonic() < deadline, "uvicorn did not start"
            time.sleep(0.05)
        port = server.servers[0].sockets[0].getsockname()[1]
        head = ("POST /analyze HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
                "Content-Type: application/json\r\n")

        ok = raw_request(port, head + "Transfer-Encoding: chunked\r\n\r\n", chunked(body_of_size(8192)))
        assert ok.startswith(b"HTTP/1.1 200"), ok[:200]
        big = raw_request(port, head + "Transfer-Encoding: chunked\r\n\r\n", chunked(body_of_size(8193)))
        assert big.startswith(b"HTTP/1.1 413") and b"payload_too_large" in big, big[:200]

        started = time.monotonic()
        declared = raw_request(port, head + "Content-Length: 100000000\r\n\r\n", [])
        assert declared.startswith(b"HTTP/1.1 413")
        assert time.monotonic() - started < 5  # refused without waiting for the body
    finally:
        server.should_exit = True
        thread.join(timeout=10)


# ---- overload guard --------------------------------------------------------------------

@pytest.mark.anyio
async def test_burst_over_limit_gets_503_with_retry_after():
    gate = threading.Event()
    fake = FakeService(gate=gate)
    app = create_app(replace(Settings(), max_concurrency=2), load_model=lambda _: fake)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            tasks = [asyncio.create_task(c.post("/analyze", json={"url": f"a{i}.com"}))
                     for i in range(5)]
            for _ in range(500):
                if sum(t.done() for t in tasks) == 3:
                    break
                await asyncio.sleep(0.01)
            assert app.state.guard.in_flight == 2
            gate.set()
            responses = await asyncio.gather(*tasks)
            assert app.state.guard.in_flight == 0
            after = await c.post("/analyze", json={"url": "after.com"})
    statuses = sorted(r.status_code for r in responses)
    assert statuses == [200, 200, 503, 503, 503]
    for r in responses:
        if r.status_code == 503:
            assert_error(r, 503, "service_busy")
            assert r.headers["retry-after"] == "1"
    assert after.status_code == 200
    assert fake.calls == 3  # refused requests never reached the model


def test_failed_analysis_releases_its_slot():
    fake = FakeService(error=RuntimeError("model failed"))
    with make_client(fake, max_concurrency=1) as c:
        for _ in range(3):
            assert_error(c.post("/analyze", json={"url": "a.com"}), 500, "internal_error")
        assert c.app.state.guard.in_flight == 0


def test_health_is_not_limited():
    gate = threading.Event()
    with make_client(FakeService(gate=gate), max_concurrency=1) as c:
        c.app.state.guard.try_acquire()  # simulate a stuck analysis holding the only slot
        assert c.get("/health").status_code == 200
        assert_error(c.post("/analyze", json={"url": "a.com"}), 503, "service_busy")
        c.app.state.guard.release()
        gate.set()


# ---- CORS ------------------------------------------------------------------------------

def test_cors_allows_only_the_frontend_origin(fake_client):
    ok = fake_client.get("/health", headers={"Origin": ALLOWED_ORIGIN})
    assert ok.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    for origin in ["http://127.0.0.1:5173", "https://localhost:5173", "http://localhost:5174",
                   "https://evil.example", "null"]:
        response = fake_client.get("/health", headers={"Origin": origin})
        assert "access-control-allow-origin" not in response.headers, origin


def test_cors_preflight(fake_client):
    headers = {"Origin": ALLOWED_ORIGIN, "Access-Control-Request-Method": "POST",
               "Access-Control-Request-Headers": "content-type"}
    ok = fake_client.options("/analyze", headers=headers)
    assert ok.status_code == 200
    assert ok.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
    assert "POST" in ok.headers["access-control-allow-methods"]
    assert "access-control-allow-credentials" not in ok.headers
    bad = fake_client.options("/analyze", headers={**headers, "Origin": "https://evil.example"})
    assert bad.status_code == 400
    assert "access-control-allow-origin" not in bad.headers


def test_error_responses_carry_cors_for_the_frontend(fake_client):
    headers = {"Origin": ALLOWED_ORIGIN, "Content-Type": "application/json"}
    for response in [fake_client.post("/analyze", content=body_of_size(9000), headers=headers),
                     fake_client.post("/analyze", content=b"{}", headers=headers)]:
        assert response.headers["access-control-allow-origin"] == ALLOWED_ORIGIN
        assert "x-request-id" in response.headers["access-control-expose-headers"].lower()


@pytest.mark.parametrize("env", [
    {"CORS_ALLOW_ORIGINS": "*"},
    {"CORS_ALLOW_ORIGINS": ""},
    {"CORS_ALLOW_ORIGINS": "http://localhost:5173/app"},
    {"CORS_ALLOW_ORIGINS": "localhost:5173"},
    {"CORS_ALLOW_ORIGINS": "http://*.example.com"},
    {"ANALYZE_MAX_CONCURRENCY": "0"},
    {"ANALYZE_MAX_CONCURRENCY": "abc"},
    {"ANALYZE_MAX_CONCURRENCY": "1000"},
    {"API_DOCS_ENABLED": "maybe"},
])
def test_misconfiguration_is_refused(env):
    with pytest.raises(ConfigError):
        load_settings(env)


def test_valid_configuration():
    settings = load_settings({"CORS_ALLOW_ORIGINS": "http://localhost:5173, https://app.example.com",
                              "ANALYZE_MAX_CONCURRENCY": "8", "API_DOCS_ENABLED": "false"})
    assert settings.cors_origins == ("http://localhost:5173", "https://app.example.com")
    assert settings.max_concurrency == 8 and settings.docs_enabled is False
    assert load_settings({}) == Settings()


# ---- no outbound activity, sanitized logs ------------------------------------------------

@pytest.mark.model
def test_analysis_makes_no_network_or_subprocess_calls(service, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("outbound call attempted")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    for url in ["https://example.com/", "http://127.0.0.1:8000/health", "localhost:22",
                "xn--pypal-4ve.com", "http://169.254.169.254/latest/meta-data/",
                "file.example/../../etc/passwd"]:
        service.analyze(url)


class ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(self.format(record))


def test_logs_never_contain_the_submitted_url():
    handler = ListHandler()
    logger = logging.getLogger("phishing_api")
    logger.addHandler(handler)
    marker = "very-secret-token-0451"
    try:
        with make_client(FakeService()) as c:
            c.post("/analyze", json={"url": f"example.com/?session={marker}"})
            c.post("/analyze", json={"url": f"bad url {marker}"})
            c.get(f"/{marker}?q={marker}")
        with make_client(FakeService(error=RuntimeError("x"))) as c:
            c.post("/analyze", json={"url": f"example.com/{marker}"})
    finally:
        logger.removeHandler(handler)
    assert handler.lines
    assert not any(marker in line for line in handler.lines)
    assert any("(unmatched)" in line for line in handler.lines)
