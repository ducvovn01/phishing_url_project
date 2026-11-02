# Backend: Phishing URL Detector API (Assignment 3)

FastAPI service around the A2 model (`models/char_ngram.joblib`, char n-gram TF-IDF +
logistic regression). It scores URL **text** only: it never fetches the URL, resolves
DNS, runs WHOIS or calls any external service.

## 1. Setup

Tested with Python 3.12.0 on Windows 11. Run everything from `backend/`.

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
| `ANALYZE_MAX_CONCURRENCY` | `4` | In-flight `/analyze` calls per worker process (1-64). |
| `RATE_LIMIT_REQUESTS` | `30` | Requests per client per window on `/analyze` (1-10000). |
| `RATE_LIMIT_WINDOW_SECONDS` | `60` | The window, in whole seconds (1-3600). |
| `RATE_LIMIT_ENABLED` | `true` | **Demo only.** `false` removes the per-client limit for the before/after recording; startup then logs a warning. Never set it in deployment. |
| `CONCURRENCY_CAP_ENABLED` | `true` | **Demo only.** `false` means the 503 cap never refuses (in-flight requests are still counted), for the denial of service before/after recording; startup then logs a warning. Never set it in deployment. |
| `BODY_LIMIT_ENABLED` | `true` | **Demo only.** `false` removes the 8192-byte body limit (no 413) for the before/after recording; startup then logs a warning. Never set it in deployment. |
| `DEMO_ANALYZE_DELAY_MS` | `0` | **Demo only.** 0-5000. Above 0, every `/analyze` sleeps this long in its worker thread while holding its concurrency slot, a stand-in for an expensive model call; startup then logs a warning. Never set it in deployment. |
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
faithfully, all three are null.

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
| `test_normalization.py` | the P2 defence |

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

  `evidence/security_smoke.json` is one real run against the defended server, recorded
  before the rate limit existed: all 5 body cases passed, and the burst of 40 got 31 × 200
  and 9 × 503, each with `Retry-After: 1`. It is not a before/after comparison. With the
  rate limit on, burst requests past the client's limit get 429, which the script also
  accepts.
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

  `evidence/rate_limit_before_after.json` is one real run (2026-10-27, default settings
  for the after phase):

  | | before (limiter off) | after (limiter on) |
  |---|---|---|
  | burst of 20: 200 / 503 | 15 / 5 | 7 / 13 |
  | flood of 60: 200 / 429 | 60 / 0 | 10 / 50 |
  | accepted before the first 429 | – | 30 (burst 20 + flood 10) |
  | `Retry-After` on 429 | – | 1, 2 |
  | 5 spoofed `X-Forwarded-For` that got through | 5 (no limit) | 0 |
  | after sleeping `Retry-After` | – | 200 |
  | model runs / requests sent | 80 / 85 | 18 / 86 |
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

  Delay mode, one real run (2026-11-02, 5 repeats, Python 3.14.7 on Windows; ms as
  median / p95 / max). Both phases PASS:

  | | before (cap and body limit off) | after (defaults, cap 4) |
  |---|---|---|
  | one slow `/analyze` | 1025 / 1086 / 1086 ms | 1035 / 1111 / 1111 ms |
  | beside it: `/health` | 2 / 21 / 28 ms | 3 / 21 / 25 ms |
  | beside it: `/analyze` probe | 1010 / 1014 / 1014 ms, 5 × 200 | 1012 / 1027 / 1027 ms, 5 × 200 |
  | flood of 5 × 100: 200 / 503 | 500 / 0 | 20 / 480 |
  | flood: time to 200 | 2254 / 3314 / 3333 ms | 1050 / 1062 / 1062 ms |
  | flood: time to 503 | - | 109 / 202 / 219 ms, `Retry-After: 1` |
  | during flood: `/health` | 2 / 22 / 32 ms | 3 / 111 / 116 ms |
  | during flood: `/analyze` probe | 3215 / 3230 / 3230 ms, 5 × 200 | 113 / 121 / 121 ms, 5 × 503 |
  | 9 KB / 1 MB / 10 MB body | 200 / 200 / 200, about 1.2 s each | 413 / 413 / 413 in 2 / 1 / 2 ms |

  Before, all 100 requests were accepted and queued: a 1 s analysis took up to 3.3 s, and
  every oversized body was read in full and analysed. After, 4 requests at a time ran in
  about 1 s and the rest were refused in a fraction of a second. In both phases
  `/health` stayed well under 0.5 s, because a sleeping worker thread does not hold up
  the event loop.

  Real mode, one real run (2026-11-02, same machine and versions). Before PASS, after
  **FAIL**: the median 503 took 633 ms and the `/health` p95 during the flood was
  1557 ms, both over 0.5 s:

  | | before (cap and body limit off) | after (defaults, cap 4) |
  |---|---|---|
  | one longest-URL `/analyze` | 16 / 90 / 90 ms | 21 / 98 / 98 ms |
  | beside it: `/health` | 3 / 22 / 27 ms | 2 / 25 / 27 ms |
  | beside it: `/analyze` probe | 21 / 32 / 32 ms, 5 × 200 | 22 / 38 / 38 ms, 5 × 200 |
  | flood of 5 × 100: 200 / 503 | 500 / 0 | 385 / 115 |
  | flood: time to 200 | 1039 / 1953 / 2178 ms | 876 / 1704 / 1830 ms |
  | flood: time to 503 | - | 633 / 1629 / 1813 ms, `Retry-After: 1` |
  | during flood: `/health` | 2 / 1796 / 1996 ms | 14 / 1557 / 1671 ms |
  | during flood: `/analyze` probe | 1963 / 2082 / 2082 ms, 5 × 200 | 1645 / 1746 / 1746 ms, 5 × 200 |
  | crafted input, 30 each: short URL | 4 / 27 / 30 ms | 5 / 29 / 30 ms |
  | crafted input, 30 each: longest URL | 28 / 45 / 147 ms | 23 / 50 / 159 ms |
  | longest / short, median and p95 | 6.4x, 1.7x | 5.0x, 1.7x |
  | 9 KB / 1 MB / 10 MB body | 200 / 200 / 200 in 216 / 234 / 264 ms | 413 / 413 / 413 in 25 / 2 / 25 ms |

  With real inference a single expensive request is only about 20 ms, so the "slow"
  step is not slow and slots free quickly: after accepted 385 of 500 flood requests.
  Under the flood both servers became slow, `/health` included, and the cap made
  only a small difference. The body limit still worked as designed. A second after run
  (not recorded) gave the same `/health` result (p95 1513 ms) but a median 503 of
  169 ms, so the 503 timing varies between runs. A likely cause, not measured here: the
  inference is CPU-bound Python, so worker threads compete with the event loop for the
  GIL, and the event loop also parses all 100 requests. The delay-mode result does not
  carry over to real inference.
- **Dependencies:** `pip-audit -r requirements.txt -r requirements-dev.txt` found no known
  vulnerabilities on 2026-10-17 (`evidence/pip_audit.txt`).
- **Worst case per request:** a 2048-character URL takes about 30-70 ms on the test laptop,
  against about 3 ms for a typical URL. Body size, URL length and the concurrency cap
  bound the work any single client can cause.

## 8. Unicode look-alike experiment (P2)

See `experiments/FINDINGS.md`. In short, on 1,000 look-alike variants of real
dataset phishing URLs the baseline missed 9 and the mask-aware defence 1. Naive
NFKC/confusable folding made official-domain homographs *easier* to slip through (16/16 →
10/16). The defence is not enabled in v1.

Reproduce with `python experiments/homoglyph_evasion.py` (needs `requirements-dev.txt`
and `data/processed/features.parquet`).
