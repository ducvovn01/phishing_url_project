# API contract (v1, draft)

Status: draft for Duc (backend) and Vinh (frontend) to agree. Once agreed, any change goes through a pull request that edits this file, so both sides see it.

This file is the single source of truth for what the frontend sends and what the backend returns. The Pydantic models and the mock data used by the frontend must both match it.

## 1. Conventions

| Item | Value |
|---|---|
| Backend (dev) | `http://localhost:8000` |
| Frontend (dev) | `http://localhost:5173` (Vite default). This is the only origin CORS allows. |
| Format | JSON in both directions, `Content-Type: application/json` |
| Interactive docs | `http://localhost:8000/docs` (FastAPI). Every endpoint needs a description and an example request and response. |
| Analysis | From the URL text only. The backend never fetches the URL, does no WHOIS or DNS lookups, and calls no external service. |

## 2. Shared limits

These numbers are used in three places: the backend validation, the frontend form validation, and the backend size-limit defence. Change them here first.

| Limit | Value |
|---|---|
| URL length (after trimming) | 1 to 2048 characters |
| Request body size | 8 KB maximum, enforced by the backend before parsing |
| Signals returned | at most 10 |

## 3. `POST /analyze`

Scores one URL.

### 3.1 Request

```json
{ "url": "paypa1-secure-login.top/verify" }
```

| Field | Type | Rules |
|---|---|---|
| `url` | string, required | Trimmed. 1 to 2048 characters. No whitespace inside and no control characters. A scheme such as `https://` is optional. |

No other fields are accepted.

### 3.2 Success response (200)

```json
{
  "submitted_url": "paypa1-secure-login.top/verify",
  "analysed_url": "paypa1-secure-login.top/verify",
  "label": "phishing",
  "confidence": 0.93,
  "phishing_probability": 0.93,
  "trust_score": 7,
  "threshold": 0.5,
  "signals": [
    {
      "id": "ngram-1",
      "kind": "ngram",
      "title": "Pattern linked to phishing",
      "direction": "phishing",
      "weight": 37.1,
      "start": 19,
      "end": 23,
      "text": ".top",
      "explanation": "URLs containing this pattern were mostly phishing in the training data."
    },
    {
      "id": "rule-unusual-tld",
      "kind": "rule",
      "title": "Unusual top-level domain",
      "direction": "phishing",
      "weight": null,
      "start": 20,
      "end": 23,
      "text": "top",
      "explanation": "This ending is far more common in phishing links than in legitimate ones."
    }
  ],
  "model": { "name": "char_ngram_logreg", "version": "a2-final" }
}
```

Values in the examples are illustrative.

### 3.3 Field reference

| Field | Type | Meaning |
|---|---|---|
| `submitted_url` | string | The trimmed URL exactly as received. The frontend shows it as plain text only. |
| `analysed_url` | string | The text the model analysed: scheme removed and lowercased (the same preprocessing as training). All `start` and `end` offsets refer to this string. |
| `label` | `"phishing"` or `"legitimate"` | `phishing` when `phishing_probability` is at or above `threshold`. |
| `confidence` | number, 0 to 1 | Probability of the predicted label: `phishing_probability` for `phishing`, `1 - phishing_probability` for `legitimate`. This is the number shown beside the label. |
| `phishing_probability` | number, 0 to 1 | Raw model output. |
| `trust_score` | integer, 0 to 100 | `round(100 * (1 - phishing_probability))`. High means safer. Computed only in the backend. |
| `threshold` | number, 0 to 1 | The decision threshold saved with the model. |
| `signals` | array, 0 to 10 items | Why the score came out as it did (section 3.4). |
| `model.name`, `model.version` | strings | Identify the model in use. |

### 3.4 Signals

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Stable within one response. Used as the React key and to link a chart bar to its highlight. |
| `kind` | `"ngram"` or `"rule"` | `ngram`: a text pattern with a learned model weight. `rule`: a check computed by the feature code (IP address host, punycode, unusual top-level domain, very long URL, brand look-alike). |
| `title` | string | Short plain-language name for the user. |
| `direction` | `"phishing"` or `"legitimate"` | Which way the signal pushes. |
| `weight` | number or `null` | Contribution to the model's log-odds. Positive pushes towards phishing, negative towards legitimate. `null` for rules, which have no learned weight. Feeds chart 1. |
| `start`, `end` | integer or `null` | Position of the signal in `analysed_url`. `start` inclusive, `end` exclusive. Counted in Unicode code points, not UTF-16 units. `null` when the signal has no position. |
| `text` | string or `null` | The substring at `start:end`, or `null` with the offsets. |
| `explanation` | string | One sentence for non-technical users. Plain text, never HTML. |

Ordering: `ngram` signals first, sorted by absolute `weight`, largest first. `rule` signals follow.

Overlapping n-grams are merged by the backend into a few clear segments before being returned, so the highlighted URL stays readable.

### 3.5 Legitimate example

```json
{
  "submitted_url": "https://www.wikipedia.org/wiki/Phishing",
  "analysed_url": "www.wikipedia.org/wiki/phishing",
  "label": "legitimate",
  "confidence": 0.96,
  "phishing_probability": 0.04,
  "trust_score": 96,
  "threshold": 0.5,
  "signals": [
    {
      "id": "ngram-1",
      "kind": "ngram",
      "title": "Pattern linked to legitimate sites",
      "direction": "legitimate",
      "weight": -29.4,
      "start": 0,
      "end": 4,
      "text": "www.",
      "explanation": "URLs starting like this were mostly legitimate in the training data."
    },
    {
      "id": "ngram-2",
      "kind": "ngram",
      "title": "Pattern linked to legitimate sites",
      "direction": "legitimate",
      "weight": -16.6,
      "start": 13,
      "end": 17,
      "text": ".org",
      "explanation": "URLs ending like this were mostly legitimate in the training data."
    }
  ],
  "model": { "name": "char_ngram_logreg", "version": "a2-final" }
}
```

## 4. `GET /health`

Tells the frontend whether the backend is up and the model is loaded.

```json
{ "status": "ok", "model_loaded": true }
```

If the model cannot be loaded (for example the file hash does not match), the server refuses to start. So a failed request to `/health` means "backend unavailable" and the frontend shows an offline state.

## 5. Errors

Every error from every endpoint uses this one shape, including unexpected ones. No stack traces, file paths or other internal details ever appear in it.

```json
{
  "error": {
    "code": "validation_error",
    "message": "That doesn't look like a valid URL.",
    "details": [{ "field": "url", "message": "Must be 1 to 2048 characters." }],
    "request_id": "9f3c1a"
  }
}
```

| Field | Type | Meaning |
|---|---|---|
| `code` | string | Stable machine-readable code (table below). The frontend branches on this. |
| `message` | string | Safe to show to the user as is. |
| `details` | array, may be empty | Per-field problems: `{ "field": string, "message": string }`. |
| `request_id` | string | Short random id, so a problem can be matched to a backend log line. |

| Situation | Status | `code` | Notes |
|---|---|---|---|
| Missing, empty, wrong-type or too-long URL, malformed JSON | 422 | `validation_error` | Replaces FastAPI's default 422 body. |
| Request body over the size limit | 413 | `payload_too_large` | |
| Server busy (concurrency cap reached) | 503 | `service_busy` | Includes a `Retry-After` header in seconds. |
| Unknown path | 404 | `not_found` | |
| Wrong HTTP method for the path | 405 | `method_not_allowed` | |
| Model call fails or anything unexpected | 500 | `internal_error` | Generic message only. |

Example (busy):

```json
{
  "error": {
    "code": "service_busy",
    "message": "The service is busy. Please try again in a few seconds.",
    "details": [],
    "request_id": "c41b7e"
  }
}
```

## 6. Rules for the frontend

1. Render every string from the API as plain text. Never use `dangerouslySetInnerHTML`, never turn `submitted_url` into a clickable link, and never pass it to `window.open` or `window.location`.
2. Build the highlighted URL by cutting `analysed_url` at the signal offsets and wrapping segments in React elements. Cut by code point, for example `Array.from(analysed_url).slice(start, end).join("")`, not with `String.slice`.
3. Show `error.message` to the user. Choose the page or state from `error.code`, and treat an unknown code like `internal_error`.
4. If a request fails with no response at all (network error, timeout), show the same "backend unavailable" state.
5. The session comparison chart keeps responses in browser memory only. Nothing is saved, so it resets on refresh.

## 7. Open questions to settle before this is agreed

1. **Threshold.** What value is saved with `char_ngram.joblib`? If it is not 0.5, the `confidence` definition above still holds, but the example values need updating.
2. **Offsets and the brand mask.** The model reads text where official brand names are replaced by `§`, so its n-gram positions do not match what the user typed. Proposal: the backend maps positions back to `analysed_url` before returning them.
3. **Merging n-grams.** How overlapping 3 to 5 character patterns are merged into segments (for example: sum the weights over each character and report contiguous runs above a cut-off).
4. **Rule list.** Which rule signals ship in v1. Suggested: IP address host, punycode, unusual top-level domain, very long URL, brand look-alike.

## 8. Change log

| Date | Change | By |
|---|---|---|
| 2026-10-16 | First draft | |
