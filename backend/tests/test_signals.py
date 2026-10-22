"""Explanation signals: exact attribution, ordering, offsets, brand masking, rules."""
import csv
import math

import pytest

from app.a2 import BRAND_MASK, PROJECT_ROOT
from app.schemas import AnalyzeResponse
from app.services.explanations import align, map_span, merge_overlapping

pytestmark = pytest.mark.model

EDGE_URLS = [
    "paypa1-secure-login.top/verify",
    "docs.google.com/forms/x",
    "https://mail.google.com:443/mail/u/0/#inbox",
    "user@google.com.",
    "google。com/login",            # ideographic full stop: tldextract treats it as a dot
    "google.com/§x",                 # user-typed mask character
    "§.com/login.php?id=1",
    "http://192.168.0.1/login.php",
    "xn--pypal-4ve.com",
    "wellsfarg0.com/login",
    "pаypal.com/signin",             # Cyrillic а
    "пример.рф/путь",
    "😀😀😀.example.com/🙂",
    "straße.de/ß?q=ü#frag",
    "İstanbul.com",
    "login.login.login.xyz",
    "a.b",
    "ab",
    "secure-paypal.com.account-verify.xyz/webscr?cmd=login&" + "a=1&" * 40,
    "x" * 2048,
]


def corpus() -> list[str]:
    with (PROJECT_ROOT / "data" / "test_urls.csv").open(encoding="utf-8", newline="") as f:
        return [row["url"] for row in csv.DictReader(f)] + EDGE_URLS


@pytest.fixture(scope="module")
def analyses(service):
    return [service.analyze(u) for u in corpus()]


def test_signal_structure_and_order(analyses):
    for a in analyses:
        AnalyzeResponse(**{k: v for k, v in a.__dict__.items() if k != "model_input"})
        signals = a.signals
        assert len(signals) <= 10
        ids = [s["id"] for s in signals]
        assert len(ids) == len(set(ids))
        kinds = [s["kind"] for s in signals]
        assert kinds == sorted(kinds, key=lambda k: k != "ngram"), "ngram before rule"
        weights = [abs(s["weight"]) for s in signals if s["kind"] == "ngram"]
        assert weights == sorted(weights, reverse=True)
        for s in signals:
            if s["kind"] == "rule":
                assert s["weight"] is None and s["direction"] == "phishing"
            else:
                assert s["direction"] == ("phishing" if s["weight"] > 0 else "legitimate")
                assert s["id"].startswith("ngram-")


def test_offsets_are_code_points_into_analysed_url(analyses):
    for a in analyses:
        for s in a.signals:
            if s["start"] is None:
                assert s["end"] is None and s["text"] is None
                continue
            assert 0 <= s["start"] < s["end"] <= len(a.analysed_url)
            assert s["text"] == "".join(list(a.analysed_url)[s["start"]:s["end"]])


def test_same_direction_ngram_segments_never_overlap(analyses):
    for a in analyses:
        for direction in ("phishing", "legitimate"):
            spans = sorted((s["start"], s["end"]) for s in a.signals
                           if s["kind"] == "ngram" and s["direction"] == direction
                           and s["start"] is not None)
            for (_, end), (start, _) in zip(spans, spans[1:]):
                assert end <= start


def test_attribution_is_exact(service):
    model = service.pipeline.named_steps["model"]
    explainer = service.explainer
    for url in corpus():
        analysis = service.analyze(url)
        occurrences, logit = explainer.occurrences(url, analysis.model_input)
        x = service.pipeline[:-1].transform([url])
        assert logit == pytest.approx(model.decision_function(x)[0], abs=1e-6)
        assert explainer.intercept + sum(o.share for o in occurrences) == pytest.approx(
            logit, abs=1e-6)
        assert 1 / (1 + math.exp(-logit)) == pytest.approx(analysis.phishing_probability,
                                                           abs=1e-9)


def test_ngram_weight_is_net_contribution_inside_span(service):
    """Recompute each weight independently where model input == analysed_url."""
    for url in corpus():
        analysis = service.analyze(url)
        if analysis.model_input != analysis.analysed_url:
            continue
        occurrences, _ = service.explainer.occurrences(url, analysis.model_input)
        for s in analysis.signals:
            if s["kind"] != "ngram":
                continue
            net = sum(o.share for o in occurrences
                      if s["start"] <= o.start and o.end <= s["end"])
            assert s["weight"] == pytest.approx(net, abs=1e-4)


def test_masked_brand_maps_to_the_real_label(service):
    analysis = service.analyze("docs.google.com/forms/x")
    assert analysis.model_input == f"docs.{BRAND_MASK}.com/forms/x"
    branded = [s for s in analysis.signals if s["text"] and "google" in s["text"]]
    assert branded, analysis.signals
    for s in analysis.signals:
        assert s["text"] is None or BRAND_MASK not in s["text"]
        if s["text"] and "google" in s["text"]:
            assert "official brand domain" in s["explanation"]


def test_unmappable_mask_region_gets_null_offsets(service):
    analysis = service.analyze("user@google.com.")
    assert analysis.model_input == f"user@{BRAND_MASK}.com"  # trailing dot dropped by A2
    alignment = align(analysis.analysed_url, analysis.model_input)
    assert alignment.mask_index is None
    assert alignment.spans[:5] == [(i, i + 1) for i in range(5)]
    assert all(span is None for span in alignment.spans[5:])
    assert any(s["start"] is None for s in analysis.signals if s["kind"] == "ngram")


def test_align_cases():
    identity = align("abc.com", "abc.com")
    assert identity.mask_index is None and identity.spans == [(i, i + 1) for i in range(7)]

    masked = align("docs.google.com/x", f"docs.{BRAND_MASK}.com/x")
    assert masked.mask_index == 5
    assert masked.spans[5] == (5, 11)
    assert map_span(masked, 4, 7) == (4, 12)  # ".§." -> ".google."
    assert map_span(masked, 7, 11) == (12, 16)

    typed = align("google.com/§x", f"{BRAND_MASK}.com/{BRAND_MASK}x")
    assert typed.mask_index == 0 and typed.spans[0] == (0, 6)
    assert map_span(typed, 5, 7) == (10, 12)  # the user's own "§x" in the path

    dots = align("google。com/x", f"{BRAND_MASK}.com/x")
    assert dots.mask_index is None
    assert map_span(dots, 0, 2) is None
    assert map_span(dots, 5, 7) == (10, 12)


def test_merge_overlapping():
    assert merge_overlapping([(5, 8), (0, 3), (2, 4), (8, 9)]) == [(0, 4), (5, 8), (8, 9)]
    assert merge_overlapping([]) == []


def test_unicode_offsets(service):
    for url in ["😀😀😀.example.com/🙂", "İstanbul.com", "пример.рф/путь"]:
        analysis = service.analyze(url)
        assert analysis.signals
        for s in analysis.signals:
            if s["start"] is not None:
                assert analysis.analysed_url[s["start"]:s["end"]] == s["text"]
    assert len(service.analyze("İstanbul.com").analysed_url) == len("İstanbul.com") + 1


def test_deterministic(service):
    for url in EDGE_URLS:
        assert service.analyze(url).signals == service.analyze(url).signals


def rule_ids(service, url):
    return {s["id"]: s for s in service.analyze(url).signals if s["kind"] == "rule"}


def test_rules(service):
    ip = rule_ids(service, "http://192.168.0.1:8080/login.php")["rule-ip-host"]
    assert (ip["start"], ip["end"], ip["text"]) == (0, 11, "192.168.0.1")

    tld = rule_ids(service, "paypa1-secure-login.top/verify")["rule-unusual-tld"]
    assert (tld["start"], tld["end"], tld["text"]) == (20, 23, "top")
    assert "34,581" in tld["explanation"]

    puny = rule_ids(service, "login.xn--pypal-4ve.com/a")["rule-punycode"]
    assert puny["text"] == "login.xn--pypal-4ve.com"

    look = rule_ids(service, "secure.wellsfarg0.com/login")["rule-brand-lookalike"]
    assert look["text"] == "wellsfarg0" and '"wellsfargo"' in look["explanation"]
    cyrillic = rule_ids(service, "pаypal.com/signin")["rule-brand-lookalike"]
    assert cyrillic["text"] == "pаypal" and '"paypal"' in cyrillic["explanation"]

    long = rule_ids(service, "example.com/" + "a" * 200)["rule-long-url"]
    assert long["start"] is None and long["text"] is None

    for url in ["google.com", "www.paypal.com/signin", "example.com", "wikipedia.org"]:
        assert rule_ids(service, url) == {}, url
    for s in rule_ids(service, "http://192.168.0.1/" + "a" * 200).values():
        assert s["explanation"].startswith("Rule check, separate from the model score")
