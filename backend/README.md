# Backend: Phishing URL Detector API (Assignment 3)

FastAPI service around the A2 model (`models/char_ngram.joblib`, char n-gram TF-IDF +
logistic regression). It scores URL **text** only: it never fetches the URL, resolves
DNS, runs WHOIS or calls any external service.

## 1. Setup

Tested with Python 3.12.10 on Windows 11. Run everything from `backend/`.

```bash
cd backend
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
python -m pip install -r requirements.txt        # runtime only
python -m pip install -r requirements-dev.txt    # + tests and experiments
```

`requirements.txt` pins `scikit-learn==1.9.1`, the version the model was saved with.
The API refuses to start with any other version.

## 2. Run

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
```

- Docs: <http://localhost:8000/docs>
- Health: `curl http://localhost:8000/health` returns `{"status":"ok","model_loaded":true}`
- Analyze:

  ```bash
  curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" \
       -d '{"url": "paypa1-secure-login.top/verify"}'
  ```

`--no-access-log` turns off uvicorn's access log, which would log raw paths and query
strings. The app logs its own sanitized line per request instead (method, matched route,
status, duration, request ID; never the submitted URL).

`--no-proxy-headers` matters for the rate limit. By default uvicorn trusts
`X-Forwarded-For` from `127.0.0.1` and `::1` and replaces the client address with it, so
a local client could pick a new address on every request and never be limited
(`test_real_server_needs_no_proxy_headers` shows both cases). There is no proxy in front
of this service, so the socket address is the only client identity.

| Variable | Default | Meaning |
|---|---|---|
| `CORS_ALLOW_ORIGINS` | `http://localhost:5173` | Comma-separated exact origins. `*`, paths and wildcards are refused at startup. |
| `ANALYZE_MAX_CONCURRENCY` | `2` | In-flight `/analyze` calls per worker process (1-64). The default of 2 comes from the real-inference cap sweep in section 7 (`evidence/dos_cap_sweep_real_*.json`): during a flood of 100 the `/health` p95 was 971 ms at cap 2 against 1576 ms at cap 4 and 2035 ms with no cap, while cap 1 (584 ms) served only 104 of 500 requests against 203 at cap 2; no cap size met the 0.5 s target. The cost is fewer simultaneous analyses: a request that arrives while two are already in flight is refused with 503. |
| `RATE_LIMIT_REQUESTS` | `30` | Requests per client per window on `/analyze` (1-10000). |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | The window, in whole seconds (1-3600). |
| `RATE_LIMIT_ENABLED` | `true` | **Demo only.** `false` removes the per-client limit for the before/after recording; startup then logs a warning. Never set it in deployment. |
| `CONCURRENCY_CAP_ENABLED` | `true` | **Demo only.** `false` means the 503 cap never refuses (in-flight requests are still counted), for the denial of service before/after recording; startup then logs a warning. Never set it in deployment. |
| `BODY_LIMIT_ENABLED` | `true` | **Demo only.** `false` removes the 8192-byte body limit (no 413) for the before/after recording; startup then logs a warning. Never set it in deployment. |
| `DEMO_ANALYZE_DELAY_MS` | `0` | **Demo only.** 0-5000. Above 0, every `/analyze` sleeps this long in its worker thread while holding its concurrency slot, a stand-in for an expensive model call; startup then logs a warning. Never set it in deployment. |
| `HOMOGLYPH_DEFENCE` | `true` | Detection evasion defence (section 8): look-alike characters are folded before scoring. **Demo only** to set `false`, which scores the raw text as A2 does; startup then logs a warning. |
| `API_DOCS_ENABLED` | `true` | Set `false` in deployment to remove `/docs` and `/openapi.json`. |
| `MODEL_MANIFEST` | `backend/model_manifest.json` | Manifest naming the artefact and its expected SHA-256. |

No secrets are needed, and there is no `.env` for the backend. Invalid values stop startup.

## 3. Model loading and integrity

At startup (FastAPI lifespan, once per process) the service:

1. reads `model_manifest.json`;
2. checks the installed scikit-learn version;
3. reads the artefact bytes and compares their SHA-256 with the manifest (constant-time);
4. only then unpickles those same in-memory bytes;
5. checks that the bundle is the expected pipeline: steps `ngrams/tfidf/model`, the A2
   `preprocess_url_masked` preprocessor, `classes_ == [0, 1]`, a float threshold in [0, 1].

Any failure raises `ModelIntegrityError` and uvicorn exits ("Application startup
failed"). There is no unverified or degraded mode.

The expected digest was pinned from `models/char_ngram.joblib` as committed in `3fa96dd`
(merged to `main` in PR #1). The A2 model owner should confirm it. If the model is
retrained, update the artefact and `sha256`/`version` in the manifest together, in one
reviewed PR.

Facts confirmed from the artefact:

| Fact | Value |
|---|---|
| Bundle | `{"model": Pipeline, "threshold": 0.5}` |
| Pipeline | `HashingVectorizer(char, 3-5, 2^20, preprocessor=preprocess_url_masked)` → `TfidfTransformer(sublinear_tf)` → `LogisticRegression(C=10, liblinear)` |
| Phishing column | `classes_ == [0, 1]`, label 1 = phishing (README), so `predict_proba[:, 1]` |
| Threshold | 0.5, read from the bundle (never hard-coded) |

The pickled pipeline refers to `scripts/extract_features.py` by module name, so
`app/a2.py` puts `scripts/` on the import path. It also refuses to import if
`data/reference/tranco_top1000.csv` is missing, because the A2 brand list would then be
downloaded.

## 4. API contract (v1 draft) as implemented

`POST /analyze` takes exactly `{"url": string}` (`Content-Type: application/json`, body at
most 8192 bytes). The response fields are `submitted_url`, `analysed_url`, `label`,
`confidence`, `phishing_probability`, `trust_score`, `threshold`, `signals`, `model`.
See `/docs` for a real example.

- `analysed_url = preprocess_url(trimmed)`: scheme removed and lowercased, before brand
  masking. Note that `İ` lowercases to two code points.
- `label` is `phishing` iff `phishing_probability >= threshold`.
- `confidence` is the probability of the returned label.
- `trust_score = round(100 * (1 - phishing_probability))`.
- `model` is `{"name": "char_ngram_logreg", "version": "a2-3fa96dd"}`, taken from the
  manifest.

URL validation:

- trimmed with `str.strip()`, as `predict.py` does;
- 1-2048 code points;
- no whitespace, control (Cc), invisible formatting (Cf: zero-width, bidi overrides) or
  surrogate characters;
- the scheme is optional, but if present it must be `http://` or `https://`;
- `host:port` and `host.tld:user@...` prefixes are not treated as schemes;
- Unicode hostnames are accepted.

Errors all use the same shape:
`{"error": {"code", "message", "details": [{"field", "message"}], "request_id"}}`.
`request_id` is also sent as `X-Request-ID` and appears in the log line.

| HTTP | `code` | When |
|---|---|---|
| 422 | `validation_error` | Bad/missing/too-long URL, extra fields, malformed JSON, non-JSON `Content-Type` |
| 413 | `payload_too_large` | Body over 8192 bytes (counted while reading, chunked too) |
| 429 | `rate_limited` | This client went over its limit on `/analyze`; `Retry-After` in whole seconds, at least 1 |
| 503 | `service_busy` | Concurrency limit reached; `Retry-After: 1` |
| 404 | `not_found` | Unknown path |
| 405 | `method_not_allowed` | Wrong method (`Allow` header kept) |
| 500 | `internal_error` | Anything unexpected; generic message, no exception text |

## 5. Explanation signals

There are 0-10 signals per response: up to 5 `ngram` signals ordered by descending
`|weight|`, then the `rule` signals in a fixed order. `start`/`end` are code-point offsets
into `analysed_url`, and `text == analysed_url[start:end]`. When a span cannot be mapped
faithfully, all three are null. With the homoglyph defence on (section 8), every `ngram`
signal of a URL that folding changed has all three null, because the folded model input
no longer lines up with `analysed_url`; rule signals keep their offsets.

### N-gram signals

These come from the model itself (`app/services/explanations.py`).

The model's log-odds equal `intercept + Σ coef[j]·x[j]` over the TF-IDF row `x`. Each term
is an exact contribution, and the tests check that the terms add up to
`decision_function`. A column hit several times in one URL (a repeated n-gram, or a
collision) splits its contribution equally between those occurrences.

Segments are built like this:

1. Take the 12 largest-|share| occurrences that are at least 0.1.
2. Merge same-sign occurrences that overlap.
3. Set `weight` to the **net** contribution of every n-gram lying entirely inside the
   span.
4. Drop segments with `|weight| < 0.1` or whose sign flipped.

Phishing and legitimate segments may overlap each other; same-direction segments never
do.

### Brand mask

A2 rewrites official brand domains (`docs.google.com` → `docs.§.com`). The masked string
is aligned back to `analysed_url` by common prefix and suffix, so the `§` maps to the whole
brand label. When A2's rewrite is not a pure label swap (a trailing dot, or `。` treated as
a dot), the affected spans get null offsets instead of a wrong highlight.

### Rule signals

These are in `app/services/rules.py`. `weight` is always null, and each explanation starts
with "Rule check, separate from the model score". Every figure quoted comes from
`app/data/rule_stats.json`, which `scripts/build_rule_stats.py` builds from
`data/processed/features.parquet`.

| id | Fires when | A2 dataset figure |
|---|---|---|
| `rule-ip-host` | host is an IPv4 literal (A2 regex) | 99.86% of 19,168 phishing |
| `rule-punycode` | host contains `xn--` | 99.63% of 3,765 phishing |
| `rule-unusual-tld` | suffix has ≥1,000 rows and ≥95% phishing (31 suffixes) | per suffix, e.g. `.top` 99.96% of 34,581 |
| `rule-brand-lookalike` | domain label (≥5 chars) is not a brand but becomes one after A2's homoglyph and leetspeak maps | 98.44% of 64 phishing |
| `rule-long-url` | longer than 136 chars (99th percentile of legitimate URLs) | 78.93% of 35,932 phishing |

A fuzzy brand-similarity rule (score ≥ 0.85) was considered and rejected: only about 50%
of those rows are phishing (see also `data/analysis/model_report.md`).

## 6. Tests

```bash
python -m pytest              # whole suite (needs requirements-dev.txt)
python -m pytest -m "not model"   # HTTP/validation/security tests only, no model needed
```

| File | Covers |
|---|---|
| `test_model_integrity.py` | digest pinned, tampered file never unpickled, wrong digest/version/structure stops startup |
| `test_model_parity.py` | probabilities and labels equal genuine `scripts/predict.py` on 218 URLs (`data/test_urls.csv` + edge cases, atol 1e-12); preprocessing; threshold boundary |
| `test_api.py` | response shapes, uniform 404/405/500, request IDs, security headers, `/docs` content |
| `test_validation.py` | URL policy and every 422 path |
| `test_security.py` | 8192/8193-byte boundary with and without Content-Length (also over a real uvicorn socket), 429 + `Retry-After` (token bucket, bounded store, every body counts, keyed on the socket address, `X-Forwarded-For` ignored, demo switch, 429 before 503), 503 + `Retry-After`, slot release, CORS, config refusal, no network/subprocess calls, no URLs in logs |
| `test_security.py` (demo switches) | `CONCURRENCY_CAP_ENABLED`, `BODY_LIMIT_ENABLED` and `DEMO_ANALYZE_DELAY_MS` parse and bad values are refused; defaults unchanged; cap off gives no 503 but still counts in-flight requests; body limit off lets a 9000-byte body through; a 300 ms delay runs in the worker thread while `/health` answers in under 0.15 s; a startup warning per switch |
| `test_signals.py` | exact attribution, ordering, Unicode offsets, brand mask mapping, rules |
| `test_normalization.py` | the P2 defence: folding, mask decided on the original host; through `analyze` and over HTTP with the real model: ASCII URLs identical with the defence on and off, Cyrillic and fullwidth look-alikes score like their ASCII base, an official-domain homograph gets no brand mask, null n-gram offsets only when folding changed the text |

## 7. Security support

- **Body limit:** `BodySizeLimitMiddleware` rejects a declared `Content-Length` over 8192
  at once. Otherwise it counts bytes while reading and stops at the first chunk past the
  limit, so at most 8192 bytes plus one chunk are ever buffered.
- **Per-client rate limit (layer 1):** `app/rate_limit.py`, a token bucket per client on
  `/analyze`. By default a client may send 30 at once and then gets one more every
  2 seconds (30 per 60 s). Over that it gets `429 rate_limited` with `Retry-After`, the
  whole seconds until its next request is allowed, rounded up so waiting that long always
  works. Details:
  - The check runs as middleware before the body is read. Every request counts, even a
    malformed or oversized one, and a limited client costs no parsing or model time.
  - The key is the socket address, without the port. No forwarding header is read, and
    see `--no-proxy-headers` in section 2.
  - The store holds at most 10,000 clients as an LRU. A client that keeps sending is
    never the one evicted. A limit is only forgotten when more than 10,000 addresses
    arrive within one window, and layer 2 still bounds that case.
  - The limit is per worker process, like the concurrency cap.
- **Overload (layer 2):** a non-blocking per-process cap (`ANALYZE_MAX_CONCURRENCY`). Excess
  requests get 503 at once instead of queueing, and a slot is freed only when the worker
  thread has really finished. With N worker processes the total is N × limit. 429 means
  "this client asked too often", 503 means "the service is busy for everyone". A request
  turned away with 503 has still used one of its client's requests.
- **Misconfiguration:**
  - exact CORS origin, no credentials, and `http://127.0.0.1:5173` is *not* allowed;
  - `nosniff`, `no-store`, `no-referrer` and CSP/`X-Frame-Options` on API responses;
  - docs can be switched off;
  - error bodies are fixed strings, with no stack traces or paths;
  - startup is refused for a bad config or an unverified model.
- **Bounded localhost smoke test** (refuses non-local targets, at most 100 requests):

  ```bash
  python scripts/security_smoke.py --burst 40 --json-out evidence/security_smoke.json
  ```

  `evidence/security_smoke.json` is one real run (2026-11-03, Python 3.12.10) against the
  defended server with its default settings (rate limit on, cap 2): all 5 body cases
  passed, and the burst of 40 got 9 × 200, 15 × 429 and 16 × 503, each 503 with
  `Retry-After: 1`. It is not a before/after comparison. With the rate limit on, burst
  requests past the client's limit get 429, which the script also accepts.
- **Rate limit before/after** (localhost only, capped):

  ```bash
  # terminal 1, BEFORE: the demo switch turns the limiter off
  #   PowerShell: $env:RATE_LIMIT_ENABLED="false"    bash: export RATE_LIMIT_ENABLED=false
  uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-access-log
  # terminal 2
  python scripts/security/rate_limit_flood.py --phase before
  # terminal 1: stop, unset RATE_LIMIT_ENABLED (PowerShell: Remove-Item Env:RATE_LIMIT_ENABLED), start again
  python scripts/security/rate_limit_flood.py --phase after
  ```

  Each phase sends, from one client, a burst of 20 concurrent requests, then 60 one after
  another, then 5 with a new `X-Forwarded-For` each. The after phase finally sleeps the
  last `Retry-After` and sends one more. Both phases go into
  `evidence/rate_limit_before_after.json`, and once both exist the script prints them
  side by side. It refuses to pass a before phase that saw a 429, or an after phase with
  no 429, a malformed 429 or a spoofed address that got through.

  `evidence/rate_limit_before_after.json` is one real run (2026-11-03, Python 3.12.10,
  default settings for the after phase, so the concurrency cap is 2 in both phases):

  | | before (limiter off) | after (limiter on) |
  |---|---|---|
  | burst of 20: 200 / 503 | 2 / 18 | 2 / 18 |
  | flood of 60: 200 / 429 | 60 / 0 | 10 / 50 |
  | accepted before the first 429 | - | 30 (burst 20 + flood 10) |
  | `Retry-After` on 429 | - | 2 |
  | 5 spoofed `X-Forwarded-For` that got through | 5 (no limit) | 0 |
  | after sleeping `Retry-After` | - | 200 |
  | model runs / requests sent | 67 / 85 | 13 / 86 |
- **Denial of service before/after** (503 cap and body limit, localhost only, capped).
  `scripts/security/dos_before_after.py` has two modes for what makes a request
  expensive:
  - `--expensive delay` (default) uses a **stand-in** for an expensive call:
    `DEMO_ANALYZE_DELAY_MS=1000` makes every `/analyze` sleep 1 s in its worker thread.
    It writes `evidence/dos_before_after.json`.
  - `--expensive real` uses **real inference**: no demo delay, and the expensive request
    is the longest valid URL (2048 characters). It also times 30 short and 30 longest
    URLs one by one, the cost of crafted input. It writes
    `evidence/dos_before_after_real.json`.

  ```bash
  # DELAY MODE. terminal 1, BEFORE: cap and body limit off, 1 s demo delay, limiter off
  #   PowerShell: $env:RATE_LIMIT_ENABLED="false"; $env:CONCURRENCY_CAP_ENABLED="false"
  #               $env:BODY_LIMIT_ENABLED="false"; $env:DEMO_ANALYZE_DELAY_MS="1000"
  #   bash:       export RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false
  #               export BODY_LIMIT_ENABLED=false DEMO_ANALYZE_DELAY_MS=1000
  uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
  # terminal 2
  python scripts/security/dos_before_after.py --phase before
  # terminal 1: stop, unset CONCURRENCY_CAP_ENABLED and BODY_LIMIT_ENABLED (keep the other two), start again
  python scripts/security/dos_before_after.py --phase after

  # REAL MODE: the same, but DEMO_ANALYZE_DELAY_MS must NOT be set in either phase
  #   before: RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false BODY_LIMIT_ENABLED=false
  #   after:  RATE_LIMIT_ENABLED=false
  python scripts/security/dos_before_after.py --phase before --expensive real
  python scripts/security/dos_before_after.py --phase after --expensive real
  ```

  The limiter is off in both phases, so only the cap and the body limit are measured.
  Each phase repeats two steps (`--repeats`, default 5, at most 10): one expensive
  `/analyze` while 10 `/health` calls and a second expensive `/analyze` probe are timed,
  then a flood of 100 concurrent expensive `/analyze` (released together, at most 100)
  with 10 `/health` calls and one `/analyze` probe timed during it. Once per phase it
  sends valid JSON padded to 9 KB, 1 MB and 10 MB. The PASS rules check that the run is
  sound, not that before degrades. Before must show no 503. After must show 503s, each
  with `Retry-After`, a median 503 under 0.5 s, a p95 for `/health` during the flood
  under 0.5 s and 413 for all three bodies. Each phase records the Python version,
  platform, uvicorn, fastapi and scikit-learn versions and the model version (from
  `model_manifest.json`).

  Delay mode, one real run (2026-11-03, 5 repeats, Python 3.12.10 on Windows; ms as
  median / p95 / max). Both phases PASS:

  | | before (cap and body limit off) | after (defaults, cap 2) |
  |---|---|---|
  | one slow `/analyze` | 1024 / 1073 / 1073 ms | 1008 / 1084 / 1084 ms |
  | beside it: `/health` | 3 / 25 / 28 ms | 3 / 27 / 28 ms |
  | beside it: `/analyze` probe | 1010 / 1011 / 1011 ms, 5 × 200 | 1010 / 1031 / 1031 ms, 5 × 200 |
  | flood of 5 × 100: 200 / 503 | 500 / 0 | 10 / 490 |
  | flood: time to 200 | 2246 / 3330 / 3343 ms | 1032 / 1039 / 1039 ms |
  | flood: time to 503 | - | 108 / 211 / 236 ms, `Retry-After: 1` |
  | during flood: `/health` | 2 / 25 / 90 ms | 3 / 107 / 138 ms |
  | during flood: `/analyze` probe | 3216 / 3242 / 3242 ms, 5 × 200 | 110 / 142 / 142 ms, 5 × 503 |
  | 9 KB / 1 MB / 10 MB body | 200 / 200 / 200, about 1.2 s each | 413 / 413 / 413 in 2 / 22 / 2 ms |

  Before, all 100 requests were accepted and queued: a 1 s analysis took up to 3.3 s, and
  every oversized body was read in full and analysed. After (cap 2, the default), 2
  requests at a time ran in about 1 s and the rest were refused in a fraction of a second. In both phases
  `/health` stayed well under 0.5 s, because a sleeping worker thread does not hold up
  the event loop.

  Real mode, one real run (2026-11-03, same machine and versions). Before PASS, after
  **FAIL**: the `/health` p95 during the flood was 925 ms, over 0.5 s (the median 503,
  474 ms, was under it):

  | | before (cap and body limit off) | after (defaults, cap 2) |
  |---|---|---|
  | one longest-URL `/analyze` | 20 / 152 / 152 ms | 104 / 168 / 168 ms |
  | beside it: `/health` | 8 / 27 / 92 ms | 2 / 26 / 68 ms |
  | beside it: `/analyze` probe | 43 / 96 / 96 ms, 5 × 200 | 24 / 83 / 83 ms, 5 × 200 |
  | flood of 5 × 100: 200 / 503 | 500 / 0 | 192 / 308 |
  | flood: time to 200 | 1146 / 2181 / 2364 ms | 578 / 1053 / 1142 ms |
  | flood: time to 503 | - | 474 / 1017 / 1126 ms, `Retry-After: 1` |
  | during flood: `/health` | 3 / 2104 / 2138 ms | 16 / 925 / 1012 ms |
  | during flood: `/analyze` probe | 2225 / 2268 / 2268 ms, 5 × 200 | 974 / 1029 / 1029 ms, 2 × 200, 3 × 503 |
  | crafted input, 30 each: short URL | 4 / 28 / 29 ms | 15 / 31 / 32 ms |
  | crafted input, 30 each: longest URL | 30 / 97 / 110 ms | 20 / 92 / 108 ms |
  | longest / short, median and p95 | 6.6x, 3.4x | 1.3x, 3.0x |
  | 9 KB / 1 MB / 10 MB body | 200 / 200 / 200 in 206 / 222 / 273 ms | 413 / 413 / 413 in 2 / 2 / 2 ms |

  With real inference a single expensive request has a median of 20 to 104 ms in these
  runs, so the "slow" step is not slow and slots free quickly: after accepted 192 of 500
  flood requests. Under the flood both servers became slow, `/health` included; the cap
  of 2 cut the `/health` p95 from 2104 to 925 ms, but not under 0.5 s. The body limit
  still worked as designed. An earlier, unrecorded after run at cap 4 (then the default)
  gave a median 503 of 169 ms against 633 ms in its recorded run, so the 503 timing
  varies between runs. A likely cause, not measured here: the
  inference is CPU-bound Python, so worker threads compete with the event loop for the
  GIL, and the event loop also parses all 100 requests. The delay-mode result does not
  carry over to real inference.
- **Concurrency cap sweep with real inference.** Four real-mode runs on 2026-11-03, each
  against a fresh server (limiter off, no demo delay), the default flood (100 concurrent,
  5 repeats), Python 3.12.10 (`backend/.venv`) on Windows, load generator and server on
  the same machine:

  ```bash
  # no cap: RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false BODY_LIMIT_ENABLED=false
  python scripts/security/dos_before_after.py --phase before --expensive real --json-out evidence/dos_cap_sweep_real_before.json --label "no cap"
  # cap N: RATE_LIMIT_ENABLED=false ANALYZE_MAX_CONCURRENCY=N (N = 1, 2, 4)
  python scripts/security/dos_before_after.py --phase after --expensive real --max-concurrency N --json-out evidence/dos_cap_sweep_real_capN.json --label "cap N"
  ```

  `--max-concurrency` only records the cap in the file's `server_settings`; it must match
  the `ANALYZE_MAX_CONCURRENCY` the server was started with.

  | flood of 5 × 100 (ms as median / p95 / max) | no cap | cap 1 | cap 2 | cap 4 |
  |---|---|---|---|---|
  | 200 / 503 | 500 / 0 | 104 / 396 | 203 / 297 | 371 / 129 |
  | time to 503 (median / p95) | - | 364 / 760 | 547 / 1104 | 379 / 1575 |
  | time to 200 (median / p95) | 1184 / 2165 | 381 / 780 | 624 / 1151 | 920 / 1698 |
  | `/health` during the flood | 2 / 2035 / 2114 | 3 / 584 / 798 | 13 / 971 / 1241 | 14 / 1576 / 1657 |
  | `/analyze` probe during the flood | 2199 / 2272 / 2272, 5 × 200 | 608 / 901 / 901, 3 × 200, 2 × 503 | 1055 / 1283 / 1283, 2 × 200, 3 × 503 | 1645 / 1829 / 1829, 5 × 200 |
  | result | PASS | FAIL: `/health` p95 584 ms | FAIL: median 503 553 ms, `/health` p95 971 ms | FAIL: `/health` p95 1576 ms |

  "no cap" is a before phase, so its PASS only means the run was sound (no 503); its
  `/health` p95 of 2035 ms is the undefended baseline. In these runs a smaller cap gave
  a more responsive server: the `/health` p95 fell from 2035 ms (no cap) to 1576, 971
  and 584 ms (cap 4, 2, 1), and the time to 200 fell with it. The price is fewer
  accepted requests: 371, 203 and 104 of 500. No cap size met the 0.5 s `/health` rule;
  cap 1 came closest. The 503s were not always fast: their p95 was 760 to 1575 ms (the
  cap 2 result row's 553 ms median counts the probe's 503s too). Each
  figure comes from one run of 5 repeats; the earlier real-mode runs above show that
  the 503 timing in particular varies between runs.

  Hypotheses, not tested here: (1) the inference threads and the event loop contend for
  the interpreter lock (GIL), so fewer inference threads leave the event loop more time;
  (2) the load generator's 100 threads share the CPU with the server, which may inflate
  every latency compared with a separate client machine.
- **Dependencies:** `pip-audit -r requirements.txt -r requirements-dev.txt` found no known
  vulnerabilities on 2026-11-03 with Python 3.12.10 (`evidence/pip_audit.txt`).
- **Worst case per request:** a 2048-character URL takes about 30-70 ms on the test laptop,
  against about 3 ms for a typical URL. Body size, URL length and the concurrency cap
  bound the work any single client can cause.

## 8. Detection evasion defence (P2 look-alike characters)

On by default (`HOMOGLYPH_DEFENCE=true`). Before scoring, `/analyze` passes the URL
through `normalization.defended_model_input()`: NFKC (fullwidth, mathematical letters,
ligatures), lowercase, a table of listed Cyrillic/Greek/Armenian/Latin look-alikes, and
the A2 brand mask decided on the *original* host, never naive folding. The folded text is
scored with the verified pipeline's own fitted steps (`PreprocessedScorer`, built once at
startup). `analysed_url` and the rule signals stay on the unfolded text. A URL that
folding does not change, which includes every pure ASCII URL, gets exactly the A2 score
and the same response as with the defence off. A URL that folding changes is scored on
the folded text and its `ngram` signals have null offsets.

Measured in `experiments/FINDINGS.md` (`experiments/results/summary.json`, seed 42):

| | baseline (A2 as is) | naive folding | defence |
|---|---:|---:|---:|
| 1,000 look-alike variants of dataset phishing URLs: missed | 9 (0.9%) | 1 (0.1%) | 1 (0.1%) |
| 16 IDN homographs of official domains: detected | 16 | **10** | 16 |
| 5,000 legitimate test-split URLs: flagged | 384 (7.68%) | 384 | 384 |
| 60 legitimate non-ASCII URLs (7 changed by folding): flagged | 6 | 6 | 6 |

By strategy (200 variants each), baseline to defence: Greek 5 to 0, fullwidth 2 to 0,
Cyrillic-all 1 to 0, Cyrillic-one 0 to 0, dot diacritics (not covered) 1 to 1. Paired on
the same 1,000 variants, 8 were missed by the baseline and caught by the defence and none
the other way round (exact McNemar p = 0.0078). The defence changed no benign label. Mean
latency per URL in `summary.json`: baseline 1.057 ms (p95 1.931), defence 0.690 ms
(p95 1.455); FINDINGS.md quotes 1.627 and 1.553 ms from its write-up. Either way the
defence adds no measurable cost.

Known limits (from FINDINGS.md):

- NFKC does not fold cross-script letters, and the table covers only the letters listed in
  `normalization.py`, not all of `confusables.txt`.
- Diacritic look-alikes (`ạ`, `ọ`) are untouched on purpose, because stripping accents
  would change legitimate Vietnamese, French or German domains; that strategy still evades
  (1 of 200).
- Folding rewrites legitimate non-Latin text (Cyrillic "сор" becomes Latin "cop"), and the
  benign non-ASCII set it was checked on is small (60 URLs, 7 changed).
- The 16/16 homograph detection mostly reflects how the model scores login paths: the
  baseline also flags 5 of the 8 real ASCII login URLs.
- For a URL that folding changes, the score no longer equals `scripts/predict.py` (the
  parity tests use `ModelService.analyze` without the defence) and the n-gram signals
  cannot be highlighted in the URL.

### Detection evasion before and after

`scripts/security/evasion_before_after.py` attacks the running API (localhost only,
requests one at a time, counts capped) with the experiment's look-alike variants from
`experiments/results/cases.csv`, once with the defence off and once with it on:

```bash
# terminal 1, BEFORE: defence off, limiter off
#   PowerShell: $env:RATE_LIMIT_ENABLED="false"; $env:HOMOGLYPH_DEFENCE="false"
#   bash:       export RATE_LIMIT_ENABLED=false HOMOGLYPH_DEFENCE=false
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
# terminal 2
python scripts/security/evasion_before_after.py --phase before
# terminal 1: stop, unset HOMOGLYPH_DEFENCE (keep RATE_LIMIT_ENABLED=false), start again
python scripts/security/evasion_before_after.py --phase after
```

Each phase runs 10 repeats (`--repeats`, at most 20). Repeat r draws 100 distinct
category C bases with seed r (the same in both phases) and adds all 16 category A bases,
then sends all 579 of their variants. Only bases the undefended model flags as phishing
are used. The evasion rate is the share of variants labelled legitimate. The adaptive
attacker rate is the share of bases for which at least one of the five strategies gets
through. Each phase also sends 300 legitimate URLs from `experiments/results/benign.csv`
(all 60 non-ASCII ones and 240 seeded ASCII ones). Five of the non-ASCII ones contain
control characters, which the API's URL policy refuses with 422, so they are reported as
refused and the false positive rate is over the 295 scored. The run passes when it is
sound: only the expected statuses, the server detected in the expected mode (through the
`cyrillic_one` variant of `A01`, which scores exactly like its base only when folded), and
the same samples in both phases. It does not require the defence to help. Results go to
`evidence/evasion_before_after.json`.

One real run (2026-11-03, Python 3.12.10 on Windows; rates as mean (min to max) over the
10 repeats). Both phases PASS:

| | before (defence off) | after (defence on) |
|---|---|---|
| evasion, all variants | 0.60% (0.17 to 1.21) | 0.05% (0.00 to 0.17) |
| cyrillic_one | 0.00% (0.00 to 0.00) | 0.00% (0.00 to 0.00) |
| cyrillic_all | 0.26% (0.00 to 0.86) | 0.00% (0.00 to 0.00) |
| greek_mixed | 2.00% (0.00 to 4.35) | 0.00% (0.00 to 0.00) |
| fullwidth | 0.52% (0.00 to 0.86) | 0.00% (0.00 to 0.00) |
| dot_diacritics_uncovered | 0.26% (0.00 to 0.86) | 0.26% (0.00 to 0.86) |
| adaptive attacker (bases with a way through) | 2.24% (0.86 to 4.31) | 0.26% (0.00 to 0.86) |
| benign false positives | 20 of 295 (6.78%), 1 non-ASCII | 20 of 295 (6.78%), 1 non-ASCII |
| latency, attack, median / p95 | 10.32 / 31.47 ms | 9.68 / 32.11 ms |
| latency, benign, median / p95 | 6.9 / 29.57 ms | 4.94 / 29.71 ms |

Paired per repeat (before minus after): the evasion rate fell by 0.56 percentage points
on average (0.17 to 1.21) and the defence helped in 10 of 10 repeats, never hurt. The
adaptive attacker rate fell by 1.98 points on average and the defence helped in 9 repeats
and was equal in 1.

What this means:

- The baseline model is already hard to evade with look-alike characters
  (`experiments/FINDINGS.md`): without the defence only 0.60% of variants got through, so
  the room for improvement is small. The defence closes what remains for the strategies it
  covers (Cyrillic, Greek, fullwidth), and against an attacker who tries all five
  strategies it cut the bases with a way through from 2.24% to 0.26%.
- Its cost, measured here, is nil in this run: the benign false positive count did not
  change (20 of 295 in both phases), and latency did not change measurably (the medians
  were lower and the p95 values under 1 ms higher with the defence on, within run-to-run
  noise on one laptop).
- Its limits, from FINDINGS.md: letters outside the table in `normalization.py` are not
  folded, and diacritic look-alikes (`ạ`, `ọ`) are left alone on purpose; the
  `dot_diacritics_uncovered` row is the same in both phases for that reason.
- The repeats are not independent samples: they draw from the same 200 C bases and reuse
  all 16 A bases, so the spread over repeats shows sampling variation, not new attacks.

Reproduce with `python experiments/homoglyph_evasion.py` (needs `requirements-dev.txt`
and `data/processed/features.parquet`).
