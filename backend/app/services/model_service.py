"""Loads the verified A2 model once and scores URLs exactly as scripts/predict.py does.

Usable without HTTP:

    from app.services.model_service import ModelService
    service = ModelService.from_manifest()
    service.analyze("paypa1-secure-login.top/verify")
"""
import hashlib
import hmac
import io
import json
import math
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import sklearn
from sklearn.feature_extraction.text import HashingVectorizer, TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from app.a2 import PROJECT_ROOT, preprocess_url, preprocess_url_masked
from app.config import DEFAULT_MANIFEST, MAX_SIGNALS
from app.services.explanations import NgramExplainer
from app.services.rules import rule_signals

MAX_NGRAM_SIGNALS = 5
PIPELINE_STEPS = ["ngrams", "tfidf", "model"]


class ModelIntegrityError(RuntimeError):
    """The model artefact or its manifest cannot be trusted or used; startup must stop."""


@dataclass(frozen=True)
class ModelManifest:
    """Version-controlled description of the one artefact the API may load."""
    artefact: Path
    sha256: str
    name: str
    version: str
    sklearn_version: str
    phishing_class: int

    @classmethod
    def load(cls, path: Path = DEFAULT_MANIFEST) -> "ModelManifest":
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            artefact = Path(data["artefact"])
            manifest = cls(
                artefact=artefact if artefact.is_absolute() else PROJECT_ROOT / artefact,
                sha256=str(data["sha256"]).lower(),
                name=str(data["name"]),
                version=str(data["version"]),
                sklearn_version=str(data["sklearn_version"]),
                phishing_class=int(data["phishing_class"]),
            )
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ModelIntegrityError(f"cannot read model manifest {Path(path).name}: "
                                      f"{type(exc).__name__}") from exc
        if not re.fullmatch(r"[0-9a-f]{64}", manifest.sha256):
            raise ModelIntegrityError("manifest sha256 is not a 64-character hex digest")
        return manifest


def load_verified_bundle(manifest: ModelManifest) -> dict:
    """Read the artefact, check its SHA-256 against the manifest, then unpickle it.

    The digest is checked on the bytes in memory and the same bytes are unpickled, so the
    file cannot change between the check and the load. joblib/pickle runs code while
    loading, which is why nothing is deserialized before the digest matches.
    """
    if sklearn.__version__ != manifest.sklearn_version:
        raise ModelIntegrityError(f"scikit-learn {sklearn.__version__} is installed but the "
                                  f"model was saved with {manifest.sklearn_version}; install "
                                  "backend/requirements.txt")
    try:
        data = manifest.artefact.read_bytes()
    except OSError as exc:
        raise ModelIntegrityError(f"cannot read {manifest.artefact.name}") from exc
    digest = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(digest, manifest.sha256):
        raise ModelIntegrityError(f"SHA-256 of {manifest.artefact.name} does not match the "
                                  "manifest; refusing to load it")
    bundle = joblib.load(io.BytesIO(data))
    check_bundle(bundle, manifest.phishing_class)
    return bundle


def check_bundle(bundle, phishing_class: int) -> None:
    """Fail unless the bundle is the A2 char n-gram pipeline this service was written for."""
    if not isinstance(bundle, dict) or not {"model", "threshold"} <= bundle.keys():
        raise ModelIntegrityError("model bundle must be a dict with 'model' and 'threshold'")
    pipeline = bundle["model"]
    if not isinstance(pipeline, Pipeline) or [n for n, _ in pipeline.steps] != PIPELINE_STEPS:
        raise ModelIntegrityError(f"model must be a Pipeline with steps {PIPELINE_STEPS}")
    vectorizer, tfidf, model = (pipeline.named_steps[n] for n in PIPELINE_STEPS)
    if not (isinstance(vectorizer, HashingVectorizer) and isinstance(tfidf, TfidfTransformer)
            and isinstance(model, LogisticRegression)):
        raise ModelIntegrityError("unexpected pipeline step types")
    if vectorizer.preprocessor is not preprocess_url_masked:
        raise ModelIntegrityError("vectorizer does not use extract_features.preprocess_url_masked")
    # Binary LogisticRegression: predict_proba column 1 and coef_ both refer to classes_[1].
    if list(model.classes_) != [0, 1] or model.classes_[1] != phishing_class:
        raise ModelIntegrityError(f"expected classes [0, 1] with phishing = {phishing_class}, "
                                  f"got {list(model.classes_)}")
    if model.coef_.shape != (1, vectorizer.n_features):
        raise ModelIntegrityError("coefficient shape does not match the vectorizer")
    threshold = bundle["threshold"]
    if not isinstance(threshold, float) or not 0.0 <= threshold <= 1.0:
        raise ModelIntegrityError("threshold must be a float between 0 and 1")


def decide(phishing_probability: float, threshold: float) -> tuple[str, float, int]:
    """(label, confidence, trust_score) as defined by the API contract."""
    phishing = phishing_probability >= threshold
    confidence = phishing_probability if phishing else 1.0 - phishing_probability
    return ("phishing" if phishing else "legitimate", confidence,
            round(100 * (1 - phishing_probability)))


@dataclass(frozen=True)
class Analysis:
    submitted_url: str
    analysed_url: str
    label: str
    confidence: float
    phishing_probability: float
    trust_score: int
    threshold: float
    signals: list[dict]
    model: dict
    # What the model actually saw (brand label masked); not part of the API response.
    model_input: str = field(repr=False)


class ModelService:
    """The verified A2 pipeline plus its threshold, metadata and explainer."""

    def __init__(self, pipeline: Pipeline, threshold: float, manifest: ModelManifest):
        self.pipeline = pipeline
        self.threshold = threshold
        self.manifest = manifest
        self._phishing_column = list(pipeline.named_steps["model"].classes_).index(
            manifest.phishing_class)
        self._explainer = NgramExplainer(pipeline)

    @classmethod
    def from_manifest(cls, manifest_path: Path = DEFAULT_MANIFEST) -> "ModelService":
        manifest = ModelManifest.load(manifest_path)
        bundle = load_verified_bundle(manifest)
        return cls(bundle["model"], bundle["threshold"], manifest)

    @property
    def explainer(self) -> NgramExplainer:
        return self._explainer

    def phishing_probability(self, urls: Sequence[str]) -> np.ndarray:
        """The scripts/predict.py path: strip each URL, then the pipeline's phishing column."""
        urls = [str(u).strip() for u in urls]
        if not urls:
            return np.empty(0)
        return np.asarray(self.pipeline.predict_proba(urls))[:, self._phishing_column]

    def analyze(self, url: str) -> Analysis:
        """Score one URL and explain the score; `url` is the validated, trimmed input."""
        submitted = url.strip()
        analysed = preprocess_url(submitted)
        model_input = preprocess_url_masked(submitted)
        probability = float(self.phishing_probability([submitted])[0])
        if not math.isfinite(probability) or not 0.0 <= probability <= 1.0:
            raise RuntimeError("model returned an invalid probability")
        label, confidence, trust_score = decide(probability, self.threshold)

        rules = rule_signals(analysed)
        ngram_limit = min(MAX_NGRAM_SIGNALS, MAX_SIGNALS - len(rules))
        ngrams = self._explainer.signals(submitted, analysed, model_input, ngram_limit)
        signals = [{"id": f"ngram-{i}", **s} for i, s in enumerate(ngrams, 1)] + rules

        return Analysis(
            submitted_url=submitted,
            analysed_url=analysed,
            label=label,
            confidence=confidence,
            phishing_probability=probability,
            trust_score=trust_score,
            threshold=self.threshold,
            signals=signals[:MAX_SIGNALS],
            model={"name": self.manifest.name, "version": self.manifest.version},
            model_input=model_input,
        )
