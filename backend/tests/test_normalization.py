"""The P2 homoglyph defence, and how the API uses it (HOMOGLYPH_DEFENCE, default on)."""
from dataclasses import replace

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app.a2 import BRAND_MASK, preprocess_url, preprocess_url_masked
from app.config import Settings
from app.main import create_app
from app.services.normalization import PreprocessedScorer, defended_model_input, fold

pytestmark = pytest.mark.model


def test_fold_handles_compatibility_forms_and_listed_confusables():
    assert fold("ｐａｙｐａｌ．ｃｏｍ") == "paypal.com"      # NFKC: fullwidth letters and dot
    assert fold("𝐩𝐚𝐲𝐩𝐚𝐥") == "paypal"                      # NFKC: mathematical bold
    assert fold("pаypаl") == "paypal"                      # Cyrillic а via the table
    assert fold("gοοgle") == "google"                      # Greek ο via the table
    assert fold("PАYPAL") == "paypal"                      # uppercase Cyrillic А lowercases first


def test_fold_leaves_unlisted_look_alikes_alone():
    assert fold("pạypạl") == "pạypạl"                      # dot below: not folded
    assert fold("ᴘaypal") == "ᴘaypal"                      # small capital: not folded


def test_homograph_of_official_domain_is_not_given_the_brand_mask():
    assert defended_model_input("pаypal.com/signin") == "paypal.com/signin"
    assert preprocess_url_masked("pаypal.com/signin") == "pаypal.com/signin"


def test_real_official_domain_keeps_the_mask():
    assert defended_model_input("https://www.paypal.com/signin") == f"www.{BRAND_MASK}.com/signin"
    assert defended_model_input("docs.google.com/fοrms") == f"docs.{BRAND_MASK}.com/forms"


def test_ascii_urls_are_unchanged(service):
    for url in ["paypa1-secure-login.top/verify", "example.com/a?b=c", "192.168.0.1/x"]:
        assert defended_model_input(url) == preprocess_url_masked(url)


def test_preprocessed_scorer_matches_the_pipeline(service):
    urls = ["paypa1-secure-login.top/verify", "docs.google.com/forms/x", "example.com",
            "пример.рф/путь", "user@google.com.", "http://192.168.0.1/login.php"]
    scorer = PreprocessedScorer(service.pipeline)
    np.testing.assert_allclose(scorer.phishing_probability([preprocess_url_masked(u) for u in urls]),
                               service.phishing_probability(urls), rtol=0, atol=1e-12)


def test_analyze_is_undefended_unless_asked(service):
    # The A2 parity path; the API passes HOMOGLYPH_DEFENCE in explicitly.
    analysis = service.analyze("pаypal.com/signin")
    assert analysis.model_input == preprocess_url_masked("pаypal.com/signin")


ASCII_URLS = [
    "paypa1-secure-login.top/verify", "docs.google.com/forms/x", "example.com/a?b=c",
    "http://192.168.0.1/login.php", "https://www.paypal.com/signin", "user@google.com.",
    "xn--pypal-4ve.com", "wellsfarg0.com/login", "login.login.login.xyz", "x" * 2048,
]
BASE = "paypal.com-secure-login.info/verify"
CYRILLIC_ONE = "рaypal.com-secure-login.info/verify"  # first p -> Cyrillic р, as cyrillic_one
FULLWIDTH = "ｐａｙｐａｌ.com-secure-login.info/verify"     # brand token in fullwidth Latin


def assert_ngram_offsets_follow_the_contract(analysis, folded: bool):
    for s in analysis.signals:
        offsets = (s["start"], s["end"], s["text"])
        assert offsets == (None, None, None) or None not in offsets, s  # null together
        if folded and s["kind"] == "ngram":
            assert offsets == (None, None, None), s


def test_ascii_urls_give_the_same_analysis_with_the_defence_on_and_off(service):
    for url in ASCII_URLS:
        assert service.analyze(url, homoglyph_defence=True) == service.analyze(url), url


def test_look_alikes_score_like_their_ascii_base_with_the_defence(service):
    base = service.analyze(BASE).phishing_probability
    for name, url in [("cyrillic_one", CYRILLIC_ONE), ("fullwidth", FULLWIDTH)]:
        off = service.analyze(url).phishing_probability
        on = service.analyze(url, homoglyph_defence=True).phishing_probability
        print(f"{name}: base {base!r}, defence off {off!r}, defence on {on!r}")
        assert on == pytest.approx(base, abs=1e-12)
        assert off <= base


def test_homograph_of_an_official_domain_is_scored_without_the_brand_mask(service):
    url = "pаypal.com/signin"  # Cyrillic а
    on = service.analyze(url, homoglyph_defence=True)
    twin = service.analyze("paypal.com/signin")
    print(f"homograph: defence off {service.analyze(url).phishing_probability!r}, defence on "
          f"{on.phishing_probability!r} on {on.model_input!r}; ASCII twin "
          f"{twin.phishing_probability!r} on {twin.model_input!r}")
    assert on.model_input == "paypal.com/signin" and BRAND_MASK not in on.model_input
    assert twin.model_input == f"{BRAND_MASK}.com/signin"
    assert on.analysed_url == preprocess_url(url)  # unfolded text
    assert on.phishing_probability > twin.phishing_probability


def test_null_offsets_only_when_folding_changed_the_text(service):
    for url in ASCII_URLS + [CYRILLIC_ONE, FULLWIDTH, "pаypal.com/signin", "gοοgle.com/login",
                             "пример.рф/путь", "straße.de/ß?q=ü", "İstanbul.com"]:
        folded = defended_model_input(url) != preprocess_url_masked(url)
        on = service.analyze(url, homoglyph_defence=True)
        assert_ngram_offsets_follow_the_contract(on, folded)
        if folded:
            off = service.analyze(url)
            assert on.analysed_url == off.analysed_url == preprocess_url(url)
            assert ([s for s in on.signals if s["kind"] == "rule"]
                    == [s for s in off.signals if s["kind"] == "rule"])  # original text
        else:
            assert on == service.analyze(url), url


@pytest.fixture(scope="module")
def api(service):
    def client(defence: bool) -> TestClient:
        settings = replace(Settings(), rate_limit_enabled=False, homoglyph_defence=defence)
        return TestClient(create_app(settings, load_model=lambda _: service))
    with client(True) as on, client(False) as off:
        yield on, off


def test_http_defence_on_and_off(api, service):
    on, off = api

    def post(client: TestClient, url: str) -> dict:
        return client.post("/analyze", json={"url": url}).json()

    base = post(on, BASE)
    assert base == post(off, BASE)  # ASCII: identical response
    defended, raw = post(on, CYRILLIC_ONE), post(off, CYRILLIC_ONE)
    assert defended["phishing_probability"] == pytest.approx(base["phishing_probability"],
                                                             abs=1e-12)
    assert raw["phishing_probability"] == pytest.approx(
        float(service.phishing_probability([CYRILLIC_ONE])[0]), abs=1e-12)
    assert defended["analysed_url"] == raw["analysed_url"] == preprocess_url(CYRILLIC_ONE)
    ngrams = [s for s in defended["signals"] if s["kind"] == "ngram"]
    assert ngrams and all((s["start"], s["end"], s["text"]) == (None, None, None)
                          for s in ngrams)
    assert any(s["start"] is not None for s in raw["signals"] if s["kind"] == "ngram")
