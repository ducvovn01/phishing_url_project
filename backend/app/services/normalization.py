"""Homoglyph defence for the P2 evasion experiment. NOT used by the v1 API.

The defence is preprocessing only (no retraining): before the A2 model sees a URL,

1. ``unicodedata.normalize("NFKC")`` folds compatibility forms: fullwidth letters
   (ｐａｙｐａｌ), mathematical alphanumerics (𝐩𝐚𝐲), ligatures, roman numerals (ⅼ) and
   fullwidth punctuation (． ／ ＠). NFKC does NOT fold cross-script look-alikes such as
   Cyrillic "а" or Greek "ο" - they are different letters, not compatibility variants.
2. Lowercase, as A2 does anyway.
3. ``CONFUSABLES``: the A2 homoglyph map from extract_features.py plus a few lowercase
   Cyrillic/Greek/Armenian/Latin letters that Unicode's confusables.txt lists as look-alikes
   of an ASCII letter. Anything not in this table (small capitals, Cherokee, most of
   confusables.txt) passes through unchanged.
4. Brand mask, decided on the ORIGINAL host. A2 masks the brand label of official brand
   domains to "§", which the model learned as a strong legitimate signal. Folding
   "pаypal.com" (Cyrillic а) gives "paypal.com"; masking that would hand an attacker's
   domain the official-domain placeholder. So when the folded host is an official domain
   but the original host was not, the folded text is scored WITHOUT the mask.

Folding rewrites the URL (the Cyrillic word "сор" becomes Latin "cop"), so legitimate
non-Latin URLs can change meaning for the model; the experiment measures that on benign
URLs. Folded text can also differ in length, so these model inputs have no offset mapping
to analysed_url, which is one reason the defence is not wired into the API.
"""
import unicodedata

from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.pipeline import Pipeline

from app.a2 import extract_features, preprocess_url, preprocess_url_masked

# A2's own map (Cyrillic/Greek letters and two fullwidth digits), then additions from
# confusables.txt that A2 lacks. Keys are lowercase: folding lowercases first.
CONFUSABLES: dict[int, str] = {
    **extract_features._HOMOGLYPH_MAP,
    **str.maketrans({
        "ԛ": "q", "ԝ": "w", "ӏ": "l", "ѵ": "v",            # Cyrillic
        "ι": "i", "ρ": "p", "ϲ": "c", "ϳ": "j",            # Greek
        "օ": "o", "ս": "u", "հ": "h", "ո": "n", "ց": "g",  # Armenian
        "ı": "i", "ɩ": "i", "ɑ": "a",                      # Latin extensions
    }),
}


def fold(url: str) -> str:
    """NFKC, lowercase, then map listed confusables to ASCII."""
    return unicodedata.normalize("NFKC", url).lower().translate(CONFUSABLES)


def defended_model_input(url: str) -> str:
    """Model input under the defence (steps 1-4 in the module docstring)."""
    folded = fold(url.strip())
    masked = preprocess_url_masked(folded)
    folded_is_official = masked != preprocess_url(folded)
    original_is_official = preprocess_url_masked(url.strip()) != preprocess_url(url.strip())
    if folded_is_official and not original_is_official:
        return preprocess_url(folded)
    return masked


def _identity(text: str) -> str:
    return text


class PreprocessedScorer:
    """Scores strings that are already model input, with the A2 pipeline's own fitted
    steps (same n-grams, TF-IDF and classifier; only the built-in preprocessor is skipped)."""

    def __init__(self, pipeline: Pipeline):
        params = pipeline.named_steps["ngrams"].get_params()
        params["preprocessor"] = _identity
        self._vectorizer = HashingVectorizer(**params)
        self._tfidf = pipeline.named_steps["tfidf"]
        self._model = pipeline.named_steps["model"]

    def phishing_probability(self, model_inputs: list[str]):
        x = self._tfidf.transform(self._vectorizer.transform(model_inputs))
        return self._model.predict_proba(x)[:, 1]
