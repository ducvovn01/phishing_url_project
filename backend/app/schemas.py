"""Pydantic request, response and error models (API contract v1, draft)."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictStr, field_validator, model_validator

from app.config import MAX_SIGNALS
from app.validation import check_url

# Real output of the A2 model for this input; tests/test_api.py checks it still matches.
ANALYZE_EXAMPLE = {
    "submitted_url": "paypa1-secure-login.top/verify",
    "analysed_url": "paypa1-secure-login.top/verify",
    "label": "phishing",
    "confidence": 0.9999999990083821,
    "phishing_probability": 0.9999999990083821,
    "trust_score": 0,
    "threshold": 0.5,
    "signals": [
        {
            "id": "ngram-1",
            "kind": "ngram",
            "title": "Pattern linked to phishing",
            "direction": "phishing",
            "weight": 6.5542,
            "start": 14,
            "end": 23,
            "text": "login.top",
            "explanation": "The model learned to associate these characters with phishing URLs, so they pushed the score toward phishing."
        },
        {
            "id": "ngram-2",
            "kind": "ngram",
            "title": "Pattern linked to phishing",
            "direction": "phishing",
            "weight": 2.7993,
            "start": 23,
            "end": 29,
            "text": "/verif",
            "explanation": "The model learned to associate these characters with phishing URLs, so they pushed the score toward phishing."
        },
        {
            "id": "ngram-3",
            "kind": "ngram",
            "title": "Pattern linked to phishing",
            "direction": "phishing",
            "weight": 2.7636,
            "start": 0,
            "end": 5,
            "text": "paypa",
            "explanation": "The model learned to associate these characters with phishing URLs, so they pushed the score toward phishing."
        },
        {
            "id": "ngram-4",
            "kind": "ngram",
            "title": "Pattern linked to phishing",
            "direction": "phishing",
            "weight": 1.5529,
            "start": 6,
            "end": 11,
            "text": "-secu",
            "explanation": "The model learned to associate these characters with phishing URLs, so they pushed the score toward phishing."
        },
        {
            "id": "rule-unusual-tld",
            "kind": "rule",
            "title": "Domain ending common in phishing data",
            "direction": "phishing",
            "weight": None,
            "start": 20,
            "end": 23,
            "text": "top",
            "explanation": "Rule check, separate from the model score: in the A2 dataset, 99.96% of the 34,581 URLs ending in .top were phishing."
        }
    ],
    "model": {
        "name": "char_ngram_logreg",
        "version": "a2-3fa96dd"
    }
}


class AnalyzeRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        json_schema_extra={"examples": [{"url": "paypa1-secure-login.top/verify"}]},
    )

    url: StrictStr = Field(
        description="URL text to analyse; it is never fetched or resolved. Trimmed, then "
                    "1-2048 characters with no whitespace, control or invisible formatting "
                    "characters. Scheme optional; only http:// and https:// are accepted.",
    )

    @field_validator("url")
    @classmethod
    def _check_url(cls, value: str) -> str:
        return check_url(value)


class Signal(BaseModel):
    id: str = Field(description="Unique within this response, e.g. ngram-1, rule-ip-host.")
    kind: Literal["ngram", "rule"]
    title: str
    direction: Literal["phishing", "legitimate"]
    weight: float | None = Field(
        description="ngram: net log-odds contribution of the n-grams inside the span "
                    "(positive = phishing). rule: always null, rules do not change the score.")
    start: int | None = Field(description="Inclusive Unicode code-point offset into "
                                          "analysed_url, or null.")
    end: int | None = Field(description="Exclusive code-point offset, or null.")
    text: str | None = Field(description="analysed_url[start:end], or null.")
    explanation: str = Field(description="Plain text, one sentence.")

    @model_validator(mode="after")
    def _offsets_together(self) -> "Signal":
        if (self.start is None) != (self.end is None) or (self.start is None) != (self.text is None):
            raise ValueError("start, end and text must be all null or all set")
        return self


class ModelInfo(BaseModel):
    name: str
    version: str


class AnalyzeResponse(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [ANALYZE_EXAMPLE]})

    submitted_url: str = Field(description="The trimmed input. Show as plain text, never as a link.")
    analysed_url: str = Field(description="Input with the scheme removed and lowercased, as "
                                          "the model saw it before brand masking. Signal "
                                          "offsets index into this string.")
    label: Literal["phishing", "legitimate"] = Field(
        description="phishing if phishing_probability >= threshold.")
    confidence: float = Field(ge=0, le=1, description="Probability of the returned label.")
    phishing_probability: float = Field(ge=0, le=1)
    trust_score: int = Field(ge=0, le=100, description="round(100 * (1 - phishing_probability)); "
                                                       "not a safety guarantee.")
    threshold: float = Field(ge=0, le=1, description="Decision threshold saved with the model.")
    signals: list[Signal] = Field(max_length=MAX_SIGNALS,
                                  description="N-gram signals by descending |weight|, then rules.")
    model: ModelInfo


class HealthResponse(BaseModel):
    model_config = ConfigDict(json_schema_extra={"examples": [{"status": "ok",
                                                               "model_loaded": True}]})

    status: Literal["ok"]
    model_loaded: bool


class ErrorDetail(BaseModel):
    field: str
    message: str


class ErrorBody(BaseModel):
    code: str = Field(description="validation_error, payload_too_large, rate_limited, "
                                  "service_busy, not_found, method_not_allowed or "
                                  "internal_error.")
    message: str = Field(description="Safe to show to the user.")
    details: list[ErrorDetail]
    request_id: str = Field(description="Matches the server log line for this request.")


class ErrorResponse(BaseModel):
    error: ErrorBody


def error_example(code: str, message: str, details: list[dict] | None = None) -> dict:
    return {"error": {"code": code, "message": message, "details": details or [],
                      "request_id": "9f3c1a2b"}}
