"""URL input policy, as a pure function and through POST /analyze."""
import json

import pytest
from pydantic_core import PydanticCustomError

from app.validation import check_url
from conftest import FakeService, assert_error, make_client

ACCEPTED = {
    "  example.com  ": "example.com",
    "\texample.com\n": "example.com",
    "http://example.com": "http://example.com",
    "HTTPS://EXAMPLE.COM/A": "HTTPS://EXAMPLE.COM/A",
    "example.com:8080/x": "example.com:8080/x",
    "localhost:8000": "localhost:8000",
    "paypal.com:login@evil.tk": "paypal.com:login@evil.tk",
    "http://user:pass@host.com": "http://user:pass@host.com",
    "пример.рф/путь": "пример.рф/путь",
    "§.com": "§.com",
    "a": "a",
    "😀" * 2048: "😀" * 2048,  # 2048 code points (8192 UTF-8 bytes) is the maximum
}

REJECTED = {
    "": "url_length",
    "   ": "url_length",
    "x" * 2049: "url_length",
    "😀" * 2049: "url_length",
    "exa mple.com": "url_characters",
    "example.com/a\tb": "url_characters",
    "example.com/a\nb": "url_characters",
    "example.com/\x00": "url_characters",
    "example.com/\x7f": "url_characters",
    "exa​mple.com": "url_characters",      # zero-width space (Cf)
    "example.com/‮gpj.exe": "url_characters",  # right-to-left override (Cf)
    "example.com/　x": "url_characters",    # ideographic space
    "example.com/\ud800": "url_characters",     # lone surrogate
    "javascript:alert(1)": "url_scheme",
    "JavaScript:alert(1)": "url_scheme",
    "data:text/html,<script>alert(1)</script>": "url_scheme",
    "ftp://example.com": "url_scheme",
    "file:///etc/passwd": "url_scheme",
    "mailto:a@b.com": "url_scheme",
    "http:example.com": "url_scheme",
    "http://": "url_empty",
}


@pytest.mark.parametrize("raw, expected", ACCEPTED.items(), ids=lambda v: repr(v)[:30])
def test_accepted(raw, expected):
    assert check_url(raw) == expected


@pytest.mark.parametrize("raw, error_type", REJECTED.items(), ids=lambda v: repr(v)[:30])
def test_rejected(raw, error_type):
    with pytest.raises(PydanticCustomError) as info:
        check_url(raw)
    assert info.value.type == error_type


@pytest.fixture(scope="module")
def fake_client():
    with make_client(FakeService()) as c:
        yield c


def post_raw(client, body: bytes, content_type: str | None = "application/json"):
    headers = {"Content-Type": content_type} if content_type else {}
    return client.post("/analyze", content=body, headers=headers)


# json.dumps escapes non-ASCII (the lone surrogate becomes \ud800, which the JSON parser
# accepts). 2049 emoji cannot fit in 8192 bytes at all, so that case stops at the body limit.
FITS_IN_BODY = [raw for raw in REJECTED if len(json.dumps({"url": raw}).encode()) <= 8192]


@pytest.mark.parametrize("raw", FITS_IN_BODY, ids=lambda v: repr(v)[:30])
def test_api_rejects_invalid_url(fake_client, raw):
    error = assert_error(post_raw(fake_client, json.dumps({"url": raw}).encode()), 422,
                         "validation_error")
    assert error["details"][0]["field"] == "url"
    assert error["message"] == "That doesn't look like a valid URL."


def test_api_overlong_unicode_url_hits_body_limit_first(fake_client):
    body = json.dumps({"url": "😀" * 2049}, ensure_ascii=False).encode()
    assert len(body) > 8192
    assert_error(post_raw(fake_client, body), 413, "payload_too_large")


def test_api_returns_trimmed_url(fake_client):
    response = fake_client.post("/analyze", json={"url": "  Example.com/X \n"})
    assert response.status_code == 200
    assert response.json()["submitted_url"] == "Example.com/X"


@pytest.mark.parametrize("body, field, message", [
    (b'{}', "url", "Field required."),
    (b'{"url": null}', "url", "Must be a string."),
    (b'{"url": 123}', "url", "Must be a string."),
    (b'{"url": ["a.com"]}', "url", "Must be a string."),
    (b'{"url": {"a": 1}}', "url", "Must be a string."),
    (b'{"url": "a.com", "extra": 1}', "extra", "Unexpected field."),
    (b'["a.com"]', "body", "Must be a JSON object."),
    (b'"a.com"', "body", "Must be a JSON object."),
    (b'{"url": "a.com"', "body", "Request body must be valid JSON."),
    (b'{"url": "a.com"} trailing', "body", "Request body must be valid JSON."),
    (b'', "body", "Request body is required."),
    (b'\xff\xfe\x00{', "body", "Request body must be valid JSON."),
    (b'[' * 4000 + b']' * 4000, "body", "Request body must be valid JSON."),
])
def test_api_rejects_bad_body(fake_client, body, field, message):
    error = assert_error(post_raw(fake_client, body), 422, "validation_error")
    assert {"field": field, "message": message} in error["details"]


@pytest.mark.parametrize("content_type", [None, "text/plain", "application/x-www-form-urlencoded",
                                          "multipart/form-data; boundary=x"])
def test_api_requires_json_content_type(fake_client, content_type):
    error = assert_error(post_raw(fake_client, b'{"url": "a.com"}', content_type), 422,
                         "validation_error")
    assert error["details"] == [{"field": "body",
                                 "message": "Content-Type must be application/json."}]


def test_api_accepts_json_charset(fake_client):
    response = post_raw(fake_client, b'{"url": "a.com"}', "application/json; charset=utf-8")
    assert response.status_code == 200


def test_long_extra_field_name_is_truncated(fake_client):
    error = assert_error(post_raw(fake_client, json.dumps({"url": "a.com", "k" * 500: 1}).encode()),
                         422, "validation_error")
    assert all(len(d["field"]) <= 64 for d in error["details"])
