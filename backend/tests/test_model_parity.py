"""The API's scores must match the genuine A2 scripts/predict.py on the same URLs."""
import csv

import numpy as np
import pytest

from app.a2 import PROJECT_ROOT, preprocess_url, preprocess_url_masked
from app.services.model_service import decide

pytestmark = pytest.mark.model

# scripts/predict.py imports train_model.py, which needs lightgbm and matplotlib.
pytest.importorskip("lightgbm", reason="parity tests import scripts/predict.py; "
                                       "install backend/requirements-dev.txt")
pytest.importorskip("matplotlib", reason="install backend/requirements-dev.txt")
from predict import PhishingDetector  # noqa: E402  (scripts/ is on sys.path via app.a2)

EXTRA_URLS = [
    "  paypa1-secure-login.top/verify  ",
    "HTTPS://WWW.PAYPAL.COM:443/signin",
    "docs.google.com/forms/x",
    "user@google.com.",
    "http://192.168.0.1/login.php",
    "xn--pypal-4ve.com",
    "pаypal.com/signin",            # Cyrillic а
    "straße.de/ß?q=ü#frag",
    "😀😀😀.example.com/🙂",
    "İstanbul.com",                 # lowercases to two code points
    "a.b",
    "§.com/login",
    "login.login.login.xyz",
    "x" * 2048,
]


@pytest.fixture(scope="module")
def urls() -> list[str]:
    with (PROJECT_ROOT / "data" / "test_urls.csv").open(encoding="utf-8", newline="") as f:
        rows = [row["url"] for row in csv.DictReader(f)]
    assert len(rows) >= 200
    return rows + EXTRA_URLS


@pytest.fixture(scope="module")
def detector(service):
    return PhishingDetector(service.manifest.artefact)


def test_threshold_is_the_saved_one(service, detector):
    assert service.threshold == detector.threshold == detector.bundle["threshold"]


def test_probabilities_match_predict_py(service, detector, urls):
    expected = detector.predict(urls)
    actual = service.phishing_probability(urls)
    np.testing.assert_allclose(actual, expected["phishing_probability"].to_numpy(),
                               rtol=0, atol=1e-12)
    assert ((actual >= service.threshold) == expected["is_phishing"].to_numpy()).all()


def test_analyze_matches_predict_py(service, detector, urls):
    expected = detector.predict(urls)
    for url, row in zip(urls, expected.itertuples()):
        analysis = service.analyze(url)
        assert analysis.phishing_probability == pytest.approx(row.phishing_probability,
                                                              abs=1e-12)
        assert (analysis.label == "phishing") == bool(row.is_phishing)
        trimmed = url.strip()
        assert analysis.submitted_url == trimmed
        assert analysis.analysed_url == preprocess_url(trimmed)
        assert analysis.model_input == preprocess_url_masked(trimmed)


def test_both_classes_occur(service, urls):
    labels = {service.analyze(u).label for u in urls}
    assert labels == {"phishing", "legitimate"}


def test_threshold_boundary():
    t = 0.5
    assert decide(t, t) == ("phishing", t, 50)
    below = np.nextafter(t, 0)
    label, confidence, _ = decide(below, t)
    assert label == "legitimate" and confidence == pytest.approx(1 - below)
    assert decide(0.0, t) == ("legitimate", 1.0, 100)
    assert decide(1.0, t) == ("phishing", 1.0, 0)
    assert decide(0.93, t)[2] == 7
    assert decide(0.3, 0.25)[0] == "phishing"  # a different saved threshold is honoured


def test_model_identity(service):
    analysis = service.analyze("example.com")
    assert analysis.model == {"name": "char_ngram_logreg", "version": service.manifest.version}
    assert analysis.threshold == service.threshold
