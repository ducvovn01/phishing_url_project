"""The P2 homoglyph defence (not used by the API)."""
import numpy as np
import pytest

from app.a2 import BRAND_MASK, preprocess_url_masked
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


def test_api_path_does_not_use_the_defence(service):
    analysis = service.analyze("pаypal.com/signin")
    assert analysis.model_input == preprocess_url_masked("pаypal.com/signin")
