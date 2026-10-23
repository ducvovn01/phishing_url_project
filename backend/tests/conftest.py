import threading
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from app.services.model_service import Analysis, ModelService, decide

FAKE_MODEL = {"name": "fake", "version": "test"}


@pytest.fixture(scope="session")
def service() -> ModelService:
    """The real, digest-verified A2 model, loaded once for the whole run."""
    return ModelService.from_manifest()


@pytest.fixture(scope="session")
def client(service):
    """TestClient over the real model."""
    app = create_app(Settings(), load_model=lambda _: service)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class FakeService:
    """Stands in for ModelService in HTTP tests: fixed probability, optional gate/failure."""

    threshold = 0.5

    def __init__(self, probability: float = 0.25, gate: threading.Event | None = None,
                 error: Exception | None = None):
        self.probability = probability
        self.gate = gate
        self.error = error
        self.calls = 0

    def analyze(self, url: str) -> Analysis:
        self.calls += 1
        if self.gate is not None:
            assert self.gate.wait(timeout=10), "test gate was never opened"
        if self.error is not None:
            raise self.error
        label, confidence, trust = decide(self.probability, self.threshold)
        return Analysis(submitted_url=url, analysed_url=url.lower(), label=label,
                        confidence=confidence, phishing_probability=self.probability,
                        trust_score=trust, threshold=self.threshold, signals=[],
                        model=FAKE_MODEL, model_input=url.lower())


def make_client(fake=None, **settings) -> TestClient:
    """TestClient over a FakeService; use as a context manager so startup runs."""
    fake = fake or FakeService()
    app = create_app(replace(Settings(), **settings), load_model=lambda _: fake)
    return TestClient(app, raise_server_exceptions=False)


def assert_error(response, status: int, code: str) -> dict:
    """The response is the contract's error shape with this status and code."""
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) == {"code", "message", "details", "request_id"}
    assert error["code"] == code
    assert isinstance(error["message"], str) and error["message"]
    assert isinstance(error["details"], list)
    for detail in error["details"]:
        assert set(detail) == {"field", "message"}
    assert error["request_id"] == response.headers["x-request-id"]
    assert len(error["request_id"]) == 8
    return error
