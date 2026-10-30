"""HTTP contract: success shapes, uniform errors, headers and /docs."""
import pytest

from app.schemas import ANALYZE_EXAMPLE
from conftest import FakeService, assert_error, make_client

RESPONSE_FIELDS = {"submitted_url", "analysed_url", "label", "confidence",
                   "phishing_probability", "trust_score", "threshold", "signals", "model"}
SIGNAL_FIELDS = {"id", "kind", "title", "direction", "weight", "start", "end", "text",
                 "explanation"}


@pytest.fixture(scope="module")
def fake_client():
    with make_client(FakeService(probability=0.25)) as c:
        yield c


def test_health_exact_shape(fake_client):
    response = fake_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "model_loaded": True}


def test_analyze_shape_with_fake_model(fake_client):
    response = fake_client.post("/analyze", json={"url": "Example.com"})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == RESPONSE_FIELDS
    assert body["label"] == "legitimate"
    assert body["confidence"] == 0.75 and body["trust_score"] == 75
    assert body["model"] == {"name": "fake", "version": "test"}


@pytest.mark.model
def test_analyze_with_real_model(client, service):
    url = "paypa1-secure-login.top/verify"
    response = client.post("/analyze", json={"url": url})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == RESPONSE_FIELDS
    assert body["phishing_probability"] == pytest.approx(
        float(service.phishing_probability([url])[0]), abs=1e-12)
    assert body["threshold"] == service.threshold
    assert body["label"] == ("phishing" if body["phishing_probability"] >= body["threshold"]
                             else "legitimate")
    assert body["trust_score"] == round(100 * (1 - body["phishing_probability"]))
    assert isinstance(body["trust_score"], int)
    assert body["model"]["name"] == "char_ngram_logreg"
    assert 1 <= len(body["signals"]) <= 10
    for signal in body["signals"]:
        assert set(signal) == SIGNAL_FIELDS


@pytest.mark.model
@pytest.mark.parametrize("url", ["[::1]", "http://[2001:db8::1]:8080/a", "localhost",
                                 "LOCALHOST:8000", "http://[::1:8080/a", "[", "http://[]/"])
def test_real_model_analyses_ipv6_and_localhost_hosts(client, url):
    # The last three are malformed IPv6 that the form refuses but a script can send. They must
    # still be analysed, not crash: nothing on the model path parses the host.
    response = client.post("/analyze", json={"url": url})
    assert response.status_code == 200
    assert response.json()["submitted_url"] == url


@pytest.mark.model
def test_docs_example_is_real_model_output(client):
    response = client.post("/analyze", json={"url": ANALYZE_EXAMPLE["submitted_url"]})
    assert response.json() == ANALYZE_EXAMPLE


@pytest.mark.model
def test_real_health(client):
    assert client.get("/health").json() == {"status": "ok", "model_loaded": True}


def test_unknown_path_is_404(fake_client):
    assert_error(fake_client.get("/nope"), 404, "not_found")
    assert_error(fake_client.post("/analyze/extra", json={"url": "a.com"}), 404, "not_found")


@pytest.mark.parametrize("method, path", [("GET", "/analyze"), ("PUT", "/analyze"),
                                          ("DELETE", "/analyze"), ("POST", "/health")])
def test_wrong_method_is_405(fake_client, method, path):
    response = fake_client.request(method, path)
    assert_error(response, 405, "method_not_allowed")
    assert "allow" in response.headers


def test_unexpected_failure_is_generic_500():
    secret = RuntimeError(r"boom at C:\secret\path\model.py line 42")
    with make_client(FakeService(error=secret)) as c:
        response = c.post("/analyze", json={"url": "a.com"})
    error = assert_error(response, 500, "internal_error")
    assert "boom" not in response.text and "secret" not in response.text
    assert "Traceback" not in response.text
    assert error["details"] == []


def test_request_ids_are_unique(fake_client):
    ids = {fake_client.get("/health").headers["x-request-id"] for _ in range(20)}
    assert len(ids) == 20


def test_security_headers(fake_client):
    headers = fake_client.post("/analyze", json={"url": "a.com"}).headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["cache-control"] == "no-store"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert headers["x-frame-options"] == "DENY"
    error_headers = fake_client.get("/nope").headers
    assert error_headers["x-content-type-options"] == "nosniff"


def test_docs_and_openapi(fake_client):
    assert fake_client.get("/docs").status_code == 200
    spec = fake_client.get("/openapi.json").json()
    analyze = spec["paths"]["/analyze"]["post"]
    assert analyze["description"] and analyze["summary"]
    assert set(analyze["responses"]) >= {"200", "404", "405", "413", "422", "429", "500",
                                         "503"}
    for status in ("429", "503"):
        assert "Retry-After" in analyze["responses"][status]["headers"]
    for status in ("413", "422", "429", "500", "503"):
        example = analyze["responses"][status]["content"]["application/json"]["example"]
        assert set(example["error"]) == {"code", "message", "details", "request_id"}
    schemas = spec["components"]["schemas"]
    assert schemas["AnalyzeRequest"]["examples"] == [{"url": "paypa1-secure-login.top/verify"}]
    assert schemas["AnalyzeResponse"]["examples"][0]["model"]["name"] == "char_ngram_logreg"
    health = spec["paths"]["/health"]["get"]
    assert health["description"] and set(health["responses"]) >= {"200", "500"}


def test_docs_can_be_disabled():
    with make_client(docs_enabled=False) as c:
        assert_error(c.get("/docs"), 404, "not_found")
        assert_error(c.get("/openapi.json"), 404, "not_found")
        assert c.get("/health").status_code == 200
