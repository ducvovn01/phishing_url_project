# API contract (v1)

Status: v1, implemented by the backend in PR #2. Section 5 also describes one behaviour that is agreed but not built in the backend yet (`429 rate_limited`); it is marked there. The frontend already handles it. Any change to this file goes through a pull request, so both sides see it.

This file is the single source of truth for what the frontend sends and what the backend returns. The Pydantic models and the mock data used by the frontend must both match it.

## 1. Conventions

| Item | Value |
|---|---|
| Backend (dev) | `http://localhost:8000` |
| Frontend (dev) | `http://localhost:5173` (Vite). This is the only origin CORS allows by default. The backend can be told other exact origins with `CORS_ALLOW_ORIGINS`; `*` is refused at startup. Allowed methods: `GET`, `POST`. |
| Format | JSON in both directions, `Content-Type: application/json` |
| Interactive docs | `http://localhost:8000/docs` (FastAPI), on by default and switched off with `API_DOCS_ENABLED=false`. The Swagger page loads its script from a CDN, so it is blank without internet access. The API itself works offline. |
| Analysis | From the URL text only. The backend never fetches the URL, does no WHOIS or DNS lookups, and calls no external service. |
| Response headers | Every response carries `X-Request-ID` (the same value as `error.request_id` on errors), `Cache-Control: no-store`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`. API responses also carry a strict `Content-Security-Policy` and `X-Frame-Options: DENY`. |

## 2. Shared limits

These numbers are used in three places: the backend validation, the frontend form validation, and the backend size-limit defence. Change them here first.

| Limit | Value |
|---|---|
| URL length (after trimming) | 1 to 2048 Unicode code points |
| Request body size | 8192 bytes maximum, enforced by the backend before parsing (also for chunked uploads with no `Content-Length`) |
| Signals returned | at most 10 in total (n-gram and rule signals together) |
| Concurrent analyses | 4 per worker process by default (`ANALYZE_MAX_CONCURRENCY`, 1 to 64). Over the cap a request is refused at once with 503, not queued. |

## 3. `POST /analyze`

Scores one URL.

### 3.1 Request

```json
{ "url": "paypa1-secure-login.top/verify" }
```

| Field | Type | Rules |
|---|---|---|
| `url` | string, required | Trimmed (outer whitespace removed). 1 to 2048 code points. No whitespace inside. No control characters (category Cc), invisible formatting characters (Cf, for example zero-width and bidi override characters), surrogates (Cs) or line, paragraph and space separators (Zl, Zp, Zs). |

Scheme rules:

- A scheme is optional. `example.com/page` and `https://example.com/page` are both accepted.
- If a scheme is present it must be `http://` or `https://`. Other schemes (`javascript:`, `data:`, `ftp://`, `file:`, `mailto:` and so on) are rejected with `validation_error`, not analysed as if they were web links.
- A prefix such as `example.com:443` or `localhost:80` is a host and port, not a scheme.
- The scheme must be followed by something (`https://` alone is rejected).
- Unicode host names are accepted. The text is only analysed, never fetched.

Other rules:

- The body is exactly one JSON object with the single field `url`. Extra fields are rejected.
- `Content-Type` must be `application/json` (a `charset` parameter is allowed). Anything else gets `422 validation_error`.
- Malformed JSON, or a body that cannot be decoded, also gets `422 validation_error` (never 400).

### 3.2 Success response (200)

This is real output of the A2 model for the example input.

```json
{
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
      "weight": null,
      "start": 20,
      "end": 23,
      "text": "top",
      "explanation": "Rule check, separate from the model score: in the A2 dataset, 99.96% of the 34,581 URLs ending in .top were phishing."
    }
  ],
  "model": { "name": "char_ngram_logreg", "version": "a2-3fa96dd" }
}
```

### 3.3 Field reference

| Field | Type | Meaning |
|---|---|---|
| `submitted_url` | string | The trimmed URL exactly as received. The frontend shows it as plain text only. |
| `analysed_url` | string | The text the model analysed: scheme removed and lowercased (the same preprocessing as training), before the model's brand masking. All `start` and `end` offsets refer to this string. |
| `label` | `"phishing"` or `"legitimate"` | `phishing` when `phishing_probability` is at or above `threshold`. |
| `confidence` | number, 0 to 1 | Probability of the predicted label: `phishing_probability` for `phishing`, `1 - phishing_probability` for `legitimate`. It can be extremely close to 1 (for example 0.9999999990), so the frontend must not round it up to "100%" (section 6). |
| `phishing_probability` | number, 0 to 1 | Raw model output. |
| `trust_score` | integer, 0 to 100 | `round(100 * (1 - phishing_probability))`. High means safer. Computed only in the backend. It is not a safety guarantee. |
| `threshold` | number, 0 to 1 | The decision threshold saved with the model. Currently 0.5. |
| `signals` | array, 0 to 10 items | Why the score came out as it did (section 3.4). |
| `model.name`, `model.version` | strings | Identify the model in use. Currently `char_ngram_logreg`, `a2-3fa96dd`. |

### 3.4 Signals

| Field | Type | Meaning |
|---|---|---|
| `id` | string | Unique within one response (`ngram-1`, `ngram-2`, ... and fixed rule ids). Used as the React key and to link a chart bar to its highlight. |
| `kind` | `"ngram"` or `"rule"` | `ngram`: a text pattern with a learned model weight. `rule`: a check computed from the URL text that does not change the model score. |
| `title` | string | Short plain-language name for the user. |
| `direction` | `"phishing"` or `"legitimate"` | Which way the signal pushes. |
| `weight` | number or `null` | `ngram`: the net contribution to the model's log-odds from the n-grams inside the span. Positive pushes towards phishing, negative towards legitimate. `null` for rules. Feeds the weight chart. The values are the model's own scores, not percentages. |
| `start`, `end` | integer or `null` | Position of the signal in `analysed_url`. `start` inclusive, `end` exclusive. Counted in Unicode code points, not UTF-16 units. |
| `text` | string or `null` | The substring at `start:end`. |
| `explanation` | string | One sentence for non-technical users. Plain text, never HTML. |

`start`, `end` and `text` are either all set or all `null`. They are `null` when the backend cannot map a span faithfully back to `analysed_url` (this can happen for an n-gram that touches the model's brand mask). The frontend must cope with a signal that has no position: it is still listed, and the weight chart still shows it if it has a weight.

Ordering: `ngram` signals first, sorted by absolute `weight`, largest first. `rule` signals follow.

How n-gram signals are built: the model scores hashed 3 to 5 character n-grams. Each n-gram occurrence has an exact contribution to the log-odds. The backend takes the strongest occurrences, merges same-direction ones that share a character into segments, and reports each segment with the net contribution of all n-grams inside it. Segments with a net weight below 0.1, or with the opposite sign to the candidates that formed them, are dropped. Do not assume segments never overlap: the frontend gives each character to the signal with the largest absolute weight.

Rule signals shipped in v1 (all with `weight: null`; every explanation starts "Rule check, separate from the model score:" and quotes the A2 dataset count behind it):

| `id` | `title` |
|---|---|
| `rule-ip-host` | IP address used as host |
| `rule-punycode` | Punycode (xn--) host |
| `rule-unusual-tld` | Domain ending common in phishing data |
| `rule-brand-lookalike` | Brand look-alike domain |
| `rule-long-url` | Unusually long URL |

### 3.5 Legitimate example

The shape and the field values are real. The weights are rounded from a run of the real backend and the example is illustrative; the backend's output is the authority.

```json
{
  "submitted_url": "https://en.wikipedia.org/wiki/Phishing",
  "analysed_url": "en.wikipedia.org/wiki/phishing",
  "label": "legitimate",
  "confidence": 0.99,
  "phishing_probability": 0.01,
  "trust_score": 99,
  "threshold": 0.5,
  "signals": [
    {
      "id": "ngram-1",
      "kind": "ngram",
      "title": "Pattern linked to legitimate URLs",
      "direction": "legitimate",
      "weight": -4.5,
      "start": 7,
      "end": 16,
      "text": "pedia.org",
      "explanation": "The model learned to associate these characters with legitimate URLs, so they pushed the score toward legitimate."
    },
    {
      "id": "ngram-2",
      "kind": "ngram",
      "title": "Pattern linked to legitimate URLs",
      "direction": "legitimate",
      "weight": -2.8,
      "start": 16,
      "end": 21,
      "text": "/wiki",
      "explanation": "The model learned to associate these characters with legitimate URLs, so they pushed the score toward legitimate."
    },
    {
      "id": "ngram-3",
      "kind": "ngram",
      "title": "Pattern linked to legitimate URLs",
      "direction": "legitimate",
      "weight": -0.7,
      "start": 0,
      "end": 3,
      "text": "en.",
      "explanation": "The model learned to associate these characters with legitimate URLs, so they pushed the score toward legitimate."
    },
    {
      "id": "ngram-4",
      "kind": "ngram",
      "title": "Pattern linked to phishing",
      "direction": "phishing",
      "weight": 0.6,
      "start": 23,
      "end": 28,
      "text": "hishi",
      "explanation": "The model learned to associate these characters with phishing URLs, so they pushed the score toward phishing."
    }
  ],
  "model": { "name": "char_ngram_logreg", "version": "a2-3fa96dd" }
}
```

## 4. `GET /health`

Tells the frontend whether the backend is up and the model is loaded.

```json
{ "status": "ok", "model_loaded": true }
```

The server only starts after the model file's SHA-256 matches `backend/model_manifest.json` and the model has loaded. If it cannot, the server refuses to start. So a failed request to `/health` means "backend unavailable" and the frontend shows an offline state. There is no degraded mode.

## 5. Errors

Every error from every endpoint uses this one shape, including unexpected ones. No stack traces, file paths, exception text or submitted URLs ever appear in it.

```json
{
  "error": {
    "code": "validation_error",
    "message": "That doesn't look like a valid URL.",
    "details": [{ "field": "url", "message": "Must be 1 to 2048 characters." }],
    "request_id": "9f3c1a2b"
  }
}
```

| Field | Type | Meaning |
|---|---|---|
| `code` | string | Stable machine-readable code (table below). The frontend branches on this. |
| `message` | string | Safe to show to the user as is. |
| `details` | array, may be empty, at most 10 | Per-field problems: `{ "field": string, "message": string }`. `field` is `url` for the URL, or `body` for problems with the body as a whole. |
| `request_id` | string | 8 random hexadecimal characters. Also sent as the `X-Request-ID` header, so a problem can be matched to a backend log line. |

| Situation | Status | `code` | Notes |
|---|---|---|---|
| Missing, empty, wrong-type or too-long URL, forbidden characters or scheme, extra fields, malformed JSON, wrong `Content-Type` | 422 | `validation_error` | Replaces FastAPI's default 422 body. Message is "That doesn't look like a valid URL." when the problem is the URL, otherwise "The request body must be a JSON object with a single \"url\" field." |
| Request body over 8192 bytes | 413 | `payload_too_large` | Checked before the body is parsed. |
| Server busy (concurrency cap reached) | 503 | `service_busy` | `Retry-After: 1` (seconds). |
| Unknown path | 404 | `not_found` | |
| Wrong HTTP method for the path | 405 | `method_not_allowed` | Includes an `Allow` header. |
| Model call fails or anything unexpected | 500 | `internal_error` | Generic message only. |
| Too many requests from one client (planned in the backend; handled by the frontend) | 429 | `rate_limited` | Must include `Retry-After` in seconds. See below. |

Example (busy):

```json
{
  "error": {
    "code": "service_busy",
    "message": "The service is busy. Please try again in a moment.",
    "details": [],
    "request_id": "c41b7e90"
  }
}
```

### 5.1 Planned: per-client rate limit (`429 rate_limited`)

Status: agreed as the target, not implemented in PR #2. Until it ships, the backend never returns 429 and the frontend code for it is not exercised by the real server. The frontend handles it already, and the mock (`ratelimit.mock`) simulates it.

- A limiter per client returns `429` with `code: "rate_limited"`, a fixed safe message such as "Too many requests. Please wait a moment and try again.", and a `Retry-After` header in whole seconds.
- The client is the socket address of the connection, unless a trusted proxy is explicitly configured. The limiter's store of clients must be bounded, so new clients cannot exhaust it.
- The limit (requests per window) is set in backend configuration. The chosen default is recorded here once the backend sets it.
- The existing 503 concurrency cap stays as a second layer: 429 means "this client asked too often", 503 means "the service is busy for everyone".
- The frontend maps any `429` to `rate_limited`, also when the body is missing or not in the error shape (then it uses the default message above). It shows the title "Too many requests", the message, and "Please wait about N seconds, then try again." from `Retry-After`, the same wait line as `service_busy`. A missing or unreadable `Retry-After` (not whole seconds) shows no wait line.

## 6. Rules for the frontend

1. Render every string from the API as plain text. Never use `dangerouslySetInnerHTML`, never turn `submitted_url` into a clickable link, and never pass it to `window.open` or `window.location`.
2. Build the highlighted URL by cutting `analysed_url` at the signal offsets and wrapping segments in React elements. Cut by code point, for example `Array.from(analysed_url).slice(start, end).join("")`, not with `String.slice`. Ignore any signal whose offsets are `null` or out of range for highlighting.
3. Show `error.message` to the user. Choose the page or state from `error.code`, and treat an unknown code like `internal_error`.
4. If a request fails with no response at all (network error, timeout), show the same "backend unavailable" state.
5. The session comparison charts keep responses in browser memory only. Nothing is saved, so it resets on refresh.
6. Never display a confidence that rounds to 100%. A value of 99.5% or more reads "Over 99%". `trust_score` is a separate integer and is shown as is.
7. For `503` and `429`, read `Retry-After` (whole seconds) and show the wait. The wording is singular for 1 second. A missing or unreadable header shows no wait.
8. The form checks the same rules as section 3.1 (scheme, hidden characters, length) so the user gets the answer without a request. The backend stays the authority. The form also asks for a host with a "." in it, a bracketed IPv6 literal (`[2001:db8::1]`) or `localhost` (any case), each with an optional port. This host check is a frontend usability check only; the backend does not apply it.

## 7. Decisions (open questions from the draft, now settled)

| Question | Answer |
|---|---|
| Threshold | 0.5, saved with the model and returned as `threshold`. |
| Offsets and the brand mask | The backend finds offsets on the masked model input and maps them back to `analysed_url`. If a span cannot be mapped faithfully, `start`, `end` and `text` are `null`. |
| Merging n-grams | As described in section 3.4: strongest occurrences, same-direction overlaps merged, net weight reported, weak segments dropped. |
| Rule list | The five rules in section 3.4. |

## 8. Change log

| Date | Change | By |
|---|---|---|
| 2026-10-16 | First draft | |
| 2026-10-23 | Updated to the implemented v1 (PR #2): scheme and character rules, real example, null offsets, rule list, error details, `Retry-After`, security headers; added the planned `429 rate_limited`; settled the open questions; added frontend rules 6 to 8 | Vinh |
| 2026-10-24 | Frontend now handles `429 rate_limited` (section 5.1, rule 7); the form accepts bracketed IPv6 literals and `localhost` (rule 8) | Vinh |
