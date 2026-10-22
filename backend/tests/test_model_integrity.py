"""SHA-256 check before deserialization, bundle checks, and startup failure."""
import copy
import hashlib
import json

import joblib
import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.config import DEFAULT_MANIFEST, Settings
from app.main import create_app
from app.services import model_service
from app.services.model_service import ModelIntegrityError, ModelManifest, check_bundle

pytestmark = pytest.mark.model


def write_manifest(tmp_path, **overrides):
    data = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    data.update(overrides)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_artefact_matches_pinned_digest():
    manifest = ModelManifest.load()
    assert hashlib.sha256(manifest.artefact.read_bytes()).hexdigest() == manifest.sha256


def test_tampered_artefact_is_never_unpickled(tmp_path, monkeypatch):
    original = ModelManifest.load().artefact.read_bytes()
    tampered = tmp_path / "char_ngram.joblib"
    tampered.write_bytes(original[:-1] + bytes([original[-1] ^ 0xFF]))
    manifest = ModelManifest.load(write_manifest(tmp_path, artefact=str(tampered)))

    def no_load(*args, **kwargs):
        raise AssertionError("joblib.load ran before the digest check")

    monkeypatch.setattr(model_service.joblib, "load", no_load)
    with pytest.raises(ModelIntegrityError, match="does not match"):
        model_service.load_verified_bundle(manifest)


def test_wrong_expected_digest_fails(tmp_path):
    path = write_manifest(tmp_path, sha256="0" * 64)
    with pytest.raises(ModelIntegrityError, match="does not match"):
        model_service.ModelService.from_manifest(path)


@pytest.mark.parametrize("digest", ["", "abc", "g" * 64, "0" * 63])
def test_malformed_digest_fails(tmp_path, digest):
    with pytest.raises(ModelIntegrityError, match="hex digest"):
        ModelManifest.load(write_manifest(tmp_path, sha256=digest))


def test_missing_artefact_fails(tmp_path):
    path = write_manifest(tmp_path, artefact=str(tmp_path / "missing.joblib"))
    with pytest.raises(ModelIntegrityError, match="cannot read"):
        model_service.ModelService.from_manifest(path)


def test_missing_manifest_field_fails(tmp_path):
    data = json.loads(DEFAULT_MANIFEST.read_text(encoding="utf-8"))
    del data["sha256"]
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ModelIntegrityError, match="manifest"):
        ModelManifest.load(path)


def test_sklearn_version_mismatch_fails(tmp_path):
    path = write_manifest(tmp_path, sklearn_version="0.0.1")
    with pytest.raises(ModelIntegrityError, match="scikit-learn"):
        model_service.ModelService.from_manifest(path)


def test_bad_model_stops_startup(tmp_path):
    settings = Settings(manifest_path=write_manifest(tmp_path, sha256="0" * 64))
    app = create_app(settings)
    with pytest.raises(ModelIntegrityError):
        with TestClient(app):
            pass


def test_real_bundle_passes_checks():
    bundle = joblib.load(ModelManifest.load().artefact)
    check_bundle(bundle, phishing_class=1)
    assert list(bundle["model"].named_steps["model"].classes_) == [0, 1]


@pytest.mark.parametrize("mutate, message", [
    (lambda b: b.pop("threshold"), "threshold"),
    (lambda b: b.update(threshold=1.5), "threshold"),
    (lambda b: b.update(threshold="0.5"), "threshold"),
    (lambda b: setattr(b["model"].named_steps["model"], "classes_", np.array([1, 0])), "classes"),
    (lambda b: b["model"].named_steps["ngrams"].set_params(preprocessor=None), "preprocess"),
])
def test_unexpected_bundle_is_rejected(mutate, message):
    bundle = copy.deepcopy(joblib.load(ModelManifest.load().artefact))
    mutate(bundle)
    with pytest.raises(ModelIntegrityError, match=message):
        check_bundle(bundle, phishing_class=1)
