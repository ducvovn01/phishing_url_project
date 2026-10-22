"""N-gram explanation signals for the char n-gram logistic regression.

How a weight is computed
------------------------
The model's log-odds for a URL is ``intercept + sum_j coef[j] * x[j]``, where ``x`` is the
TF-IDF row of hashed 3-5 character n-gram counts. ``coef[j] * x[j]`` is the exact
contribution of hashed column ``j`` (positive pushes toward phishing, class 1). A column
can be hit more than once in one URL (a repeated n-gram, or two n-grams that hash to the
same column); its contribution is split equally between those occurrences, so the
occurrence shares still add up exactly to ``log-odds - intercept``.

Segments shown to the user:

1. Candidates are the ``CANDIDATES`` occurrences with the largest absolute share (ties
   broken by position) that reach ``MIN_CANDIDATE_SHARE``.
2. Candidates of the same sign whose spans share at least one character are merged.
3. A segment's ``weight`` is the summed share of *every* n-gram occurrence, of either sign,
   lying entirely inside its span: the net log-odds the model drew from that text. Segments
   whose net weight is below ``MIN_SEGMENT_WEIGHT`` or has the opposite sign to the
   candidates that formed it are dropped.
4. Largest absolute weight first, at most ``limit`` segments. Segments of opposite
   direction may overlap (both are real), segments of the same direction never do.

Offsets are found on the model input (brand label masked to "§") and mapped back to
``analysed_url`` with ``align()``; a span that cannot be mapped faithfully gets null offsets.
"""
import logging
from collections import Counter
from dataclasses import dataclass

from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.pipeline import Pipeline

from app.a2 import BRAND_MASK

logger = logging.getLogger("phishing_api.explanations")

CANDIDATES = 12
MIN_CANDIDATE_SHARE = 0.1
MIN_SEGMENT_WEIGHT = 0.1
WEIGHT_DECIMALS = 4

Span = tuple[int, int]


@dataclass(frozen=True)
class Occurrence:
    """One n-gram at model_input[start:end] and its share of the log-odds."""
    start: int
    end: int
    share: float


@dataclass(frozen=True)
class Alignment:
    """spans[i] is the analysed_url span that model-input character i came from (None if
    unknown); mask_index is the position of the brand mask in the model input, if any."""
    spans: list[Span | None]
    mask_index: int | None


def align(analysed: str, model_input: str) -> Alignment:
    """Map each model-input code point back to analysed_url.

    preprocess_url_masked() only ever replaces the brand label of the host with "§", so the
    two strings share a prefix and a suffix and differ in one middle region. When that region
    is exactly "§" in the model input, it stands for the whole brand label in analysed_url.
    Anything else (tldextract also rewrites dot variants and drops a trailing dot) is not a
    faithful one-to-one mapping and is marked unknown.
    """
    if model_input == analysed:
        return Alignment([(i, i + 1) for i in range(len(analysed))], None)
    limit = min(len(analysed), len(model_input))
    prefix = 0
    while prefix < limit and analysed[prefix] == model_input[prefix]:
        prefix += 1
    suffix = 0
    while (suffix < limit - prefix
           and analysed[-1 - suffix] == model_input[-1 - suffix]):
        suffix += 1
    middle = model_input[prefix:len(model_input) - suffix]
    analysed_middle_end = len(analysed) - suffix

    spans: list[Span | None] = [(i, i + 1) for i in range(prefix)]
    mask_index = None
    if middle == BRAND_MASK and analysed_middle_end > prefix:
        spans.append((prefix, analysed_middle_end))
        mask_index = prefix
    else:
        spans.extend([None] * len(middle))
    shift = len(analysed) - len(model_input)
    spans.extend((i + shift, i + shift + 1)
                 for i in range(len(model_input) - suffix, len(model_input)))
    return Alignment(spans, mask_index)


def map_span(alignment: Alignment, start: int, end: int) -> Span | None:
    """analysed_url span covering model_input[start:end], or None if any part is unknown."""
    pieces = alignment.spans[start:end]
    if not pieces or any(p is None for p in pieces):
        return None
    return pieces[0][0], pieces[-1][1]


def merge_overlapping(spans: list[Span]) -> list[Span]:
    """Union of spans that share at least one character (touching spans stay separate)."""
    merged: list[list[int]] = []
    for start, end in sorted(spans):
        if merged and start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(s, e) for s, e in merged]


def _single_token(text: str) -> list[str]:
    return [text]


class NgramExplainer:
    """Exact per-n-gram log-odds contributions for a fitted A2 char n-gram pipeline."""

    def __init__(self, pipeline: Pipeline):
        self._vectorizer = pipeline.named_steps["ngrams"]
        self._tfidf = pipeline.named_steps["tfidf"]
        model = pipeline.named_steps["model"]
        # classes_ == [0, 1] is checked at load time, so coef_[0] points toward phishing.
        self._coef = model.coef_[0]
        self.intercept = float(model.intercept_[0])
        self._ngram_range = self._vectorizer.ngram_range
        # Hashes one n-gram per document, giving the column the pipeline uses for it.
        self._token_hasher = HashingVectorizer(
            analyzer=_single_token,
            n_features=self._vectorizer.n_features,
            alternate_sign=False,
            norm=None,
            dtype=self._vectorizer.dtype,
        )

    def occurrences(self, url: str, model_input: str) -> tuple[list[Occurrence], float] | None:
        """Every n-gram occurrence in model_input with its share, plus the total log-odds.

        Returns None when the n-grams generated here do not reproduce the pipeline's own
        counts for `url`, so that no explanation is shown rather than a wrong one.
        """
        min_n, max_n = self._ngram_range
        spans = [(i, i + n) for n in range(min_n, max_n + 1)
                 for i in range(len(model_input) - n + 1)]
        grams = [model_input[s:e] for s, e in spans]
        counts = self._vectorizer.transform([url])
        if not grams:
            return ([], self.intercept) if counts.nnz == 0 else None
        unique = sorted(set(grams))
        columns = dict(zip(unique, self._token_hasher.transform(unique).indices.tolist()))
        hits = Counter(columns[g] for g in grams)
        if dict(zip(counts.indices.tolist(), counts.data.tolist())) != hits:
            return None
        x = self._tfidf.transform(counts)
        contribution = dict(zip(x.indices.tolist(), (self._coef[x.indices] * x.data).tolist()))
        occurrences = [Occurrence(s, e, contribution[columns[g]] / hits[columns[g]])
                       for (s, e), g in zip(spans, grams)]
        return occurrences, self.intercept + sum(contribution.values())

    def signals(self, url: str, analysed: str, model_input: str, limit: int) -> list[dict]:
        """Up to `limit` merged n-gram segments as signal dicts (without ids)."""
        if limit <= 0:
            return []
        result = self.occurrences(url, model_input)
        if result is None:
            logger.warning("n-gram counts did not match the pipeline; no n-gram signals")
            return []
        occurrences, _ = result
        ranked = sorted(occurrences, key=lambda o: (-abs(o.share), o.start, o.end))
        candidates = [o for o in ranked[:CANDIDATES] if abs(o.share) >= MIN_CANDIDATE_SHARE]

        segments: list[tuple[int, int, float]] = []
        for sign in (1, -1):
            same_sign = [(o.start, o.end) for o in candidates if o.share * sign > 0]
            for start, end in merge_overlapping(same_sign):
                weight = sum(o.share for o in occurrences if start <= o.start and o.end <= end)
                if weight * sign >= MIN_SEGMENT_WEIGHT:
                    segments.append((start, end, weight))
        segments.sort(key=lambda t: (-abs(t[2]), t[0], t[1]))

        alignment = align(analysed, model_input)
        return [self._signal(alignment, analysed, start, end, weight)
                for start, end, weight in segments[:limit]]

    @staticmethod
    def _signal(alignment: Alignment, analysed: str, start: int, end: int,
                weight: float) -> dict:
        phishing = weight > 0
        mapped = map_span(alignment, start, end)
        has_brand = (mapped is not None and alignment.mask_index is not None
                     and start <= alignment.mask_index < end)
        leaning = "phishing" if phishing else "legitimate"
        if has_brand:
            explanation = ("This part includes an official brand domain, which the model reads "
                           "as one placeholder symbol; together these characters pushed the "
                           f"score toward {leaning}.")
        else:
            explanation = ("The model learned to associate these characters with "
                           f"{leaning} URLs, so they pushed the score toward {leaning}.")
        return {
            "kind": "ngram",
            "title": "Pattern linked to phishing" if phishing else "Pattern linked to legitimate URLs",
            "direction": leaning,
            "weight": round(weight, WEIGHT_DECIMALS),
            "start": mapped[0] if mapped else None,
            "end": mapped[1] if mapped else None,
            "text": analysed[mapped[0]:mapped[1]] if mapped else None,
            "explanation": explanation,
        }
