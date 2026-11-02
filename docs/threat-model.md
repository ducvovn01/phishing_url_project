# Threat model

This document covers the Assignment 3 system: the React client in `frontend/`, the FastAPI
service in `backend/` and the one scikit-learn model it serves. Every number below is read
from a file in `backend/evidence/`, `frontend/evidence/` or `backend/experiments/results/`;
the file is named next to it.

Evidence times are in UTC, taken from each file's `recorded_at` field (the `created` field
for the ZAP reports), while the audit dates in this repository (`pip_audit.txt`,
`npm_audit.txt`, the README files) use the local date, UTC+11, so a run at 13:33 UTC on
2 November is 3 November locally.

## 1. Purpose and scope

The system scores the **text** of a URL as phishing or legitimate. A user types a URL into
the React client; the client sends `{"url": "..."}` to `POST /analyze`; the backend scores it
with the verified A2 model (`models/char_ngram.joblib`, a char n-gram TF-IDF and logistic
regression pipeline) and returns a verdict, a trust score and explanation signals.

Offline constraint: the backend never opens the submitted URL. It does not fetch the page,
resolve DNS, run WHOIS or call a live reputation service. The model scores the string only.

In scope: the browser to API boundary, the API process, the model file and its loading,
the dependencies, and the configuration the service is started with.

Out of scope: the host machine and its operating system, browser extensions, a compromised
user machine, and the A2 training pipeline in `scripts/` (documented in
`docs/model-pipeline.md`).

## 2. System and data flow

The middleware order is taken from `backend/app/main.py`, where middleware is added
innermost first. A request passes through the layers from top to bottom.

```
 +--------------------------+
 | Browser                  |   React client, Vite dev server, http://localhost:5173
 | (frontend/)              |   renders every API string as plain text
 +------------+-------------+
              |  HTTP, JSON body {"url": "..."}
==============|=============== TRUST BOUNDARY (untrusted input crosses here) ==========
              v
 +--------------------------------------------------------------------------------+
 | uvicorn, http://127.0.0.1:8000, --no-proxy-headers --no-server-header           |
 |                                                                                |
 |  1. CORSMiddleware            exact origin list, no credentials                |
 |  2. RequestContextMiddleware  request ID, security headers, sanitised log,     |
 |                               unhandled error -> generic 500                    |
 |  3. RateLimitMiddleware       /analyze only, per socket address -> 429         |
 |  4. BodySizeLimitMiddleware   more than 8192 bytes -> 413                      |
 |  5. Route POST /analyze       JSON only, exactly {"url"}, 1 to 2048 code       |
 |                               points -> otherwise 422                          |
 |  6. ConcurrencyGuard          more than ANALYZE_MAX_CONCURRENCY in flight -> 503|
 |  7. ModelService (worker thread)                                               |
 |       homoglyph defence (normalization.py) -> A2 pipeline -> signals          |
 +--------------------------------------------------------------------------------+
              ^
              |  read once at startup
 +------------+-------------------------------------------------+
 | backend/model_manifest.json  ->  SHA-256 check  ->  joblib    |
 | models/char_ngram.joblib (never a path from a request)        |
 +---------------------------------------------------------------+
```

`RateLimitMiddleware` is only installed when `RATE_LIMIT_ENABLED` is true and
`BodySizeLimitMiddleware` only when `BODY_LIMIT_ENABLED` is true (both default to true).

## 3. Assets and attackers

Assets:

- availability of `POST /analyze` for everyone;
- integrity of verdicts (a phishing URL should not be scored as legitimate);
- integrity of the model file, which is loaded with joblib (pickle);
- secrets and environment values on the host (the backend needs none; the frontend reads
  only `VITE_API_BASE_URL` and `VITE_USE_MOCK`, listed in `frontend/.env.example` and read
  in `frontend/src/api/client.js` and `frontend/src/api/index.js`; `VITE_` values are
  built into the public bundle, so they must not hold secrets).

Attackers:

- an anonymous client that can reach the API and send many or large requests;
- a phisher who crafts URL text, for example with look-alike Unicode letters, so that the
  model scores it as legitimate;
- a malicious or vulnerable dependency in the Python or npm packages.

## 4. Marked items

### 4a. Denial of service (brief section 2.7)

**Attack.** One client floods `/analyze`, sends very large bodies, sends the longest URLs
(the most work per analysis), or opens many requests at once so that analyses pile up and
the service stops answering.

**Impact.** Legitimate users wait or get no answer; `/health` slows down; memory grows with
buffered bodies.

**Defence.** Four layers, in the order a request meets them:

| Layer | What it does | Code | Demo switch (default) |
|---|---|---|---|
| Per-client rate limit | Token bucket per socket address on `/analyze`: 30 requests at once, then 30 per 60 s. Over it: `429 rate_limited` with `Retry-After` in whole seconds. Checked before the body is read. The client store is an LRU of at most 10,000 addresses. | `backend/app/rate_limit.py`, defaults in `backend/app/config.py` | `RATE_LIMIT_ENABLED=false` (true) |
| Body limit | A declared `Content-Length` over 8192 bytes is refused at once; otherwise bytes are counted while reading, chunked bodies too. Over it: `413 payload_too_large`. | `BodySizeLimitMiddleware` in `backend/app/middleware.py`, `MAX_BODY_BYTES` in `config.py` | `BODY_LIMIT_ENABLED=false` (true) |
| URL length cap | 1 to 2048 Unicode code points after trimming, else `422`. Bounds the work of one analysis. | `backend/app/validation.py`, `MAX_URL_LENGTH` in `config.py` | none |
| Concurrency cap | A non-blocking count of analyses in flight per worker process. Over `ANALYZE_MAX_CONCURRENCY` (default 2, allowed 1 to 64) a request gets `503 service_busy` with `Retry-After: 1` at once instead of queueing. The slot is released only when the worker thread has finished. | `ConcurrencyGuard` in `backend/app/routes.py` | `CONCURRENCY_CAP_ENABLED=false` (true) |

`DEMO_ANALYZE_DELAY_MS` (default 0) makes every `/analyze` sleep in its worker thread, a
stand-in for an expensive model call, for the delay-mode evidence only.

**Evidence.**

- `backend/evidence/rate_limit_before_after.json` (recorded 2026-11-02 13:32 UTC; the file
  does not record the Python version). Limiter off: the flood of 60 got 60 × 200 and 5 of 5
  spoofed `X-Forwarded-For` requests got through. Limiter on: 10 × 200 and 50 × 429, first
  429 at request 11, `Retry-After` 2, 0 of 5 spoofed requests got through. Both phases PASS.
- `backend/evidence/security_smoke.json` (the file records no date, Python version or
  settings). 5 of 5 body-limit cases as expected; a burst of 40 got 9 × 200, 15 × 429 and
  16 × 503.
- `backend/evidence/dos_before_after.json`, delay mode, Python 3.12.10, recorded
  2026-11-02 13:33 UTC, 5 repeats of a flood of 100. Cap and body limit off: 500 × 200 and a
  `/health` p95 of 24.8 ms during the flood. Defaults (cap 2): 10 × 200 and 490 × 503, a
  median 503 of 108.3 ms, a `/health` p95 of 107.2 ms, and 413 for the 9 KB, 1 MB and
  10 MB bodies. Both phases PASS.
- `backend/evidence/dos_before_after_real.json`, real inference on the longest valid URL,
  Python 3.12.10, recorded 2026-11-02 13:34 UTC. Cap off: 500 × 200 and a `/health` p95 of
  2103.5 ms. Cap 2: 192 × 200 and 308 × 503, a median 503 of 474.2 ms, and a `/health` p95
  of 924.8 ms. **The after phase FAILS** the rule that `/health` p95 during the flood is
  under 0.5 s. That 0.5 s is the team's own target, set as `QUICK_MS = 500` in
  `backend/scripts/security/dos_before_after.py`, not an external standard.
- The cap sweep, real inference, Python 3.12.10, recorded 2026-11-02 13:35 to 13:36 UTC:

  | File | Cap | 200 / 503 | `/health` p95 during the flood | Result |
  |---|---|---|---|---|
  | `dos_cap_sweep_real_before.json` | none | 500 / 0 | 2034.7 ms | PASS (no 503, which is all a before phase checks) |
  | `dos_cap_sweep_real_cap1.json` | 1 | 104 / 396 | 584.3 ms | FAIL (`/health` p95) |
  | `dos_cap_sweep_real_cap2.json` | 2 | 203 / 297 | 970.8 ms | FAIL (`/health` p95, and median 503 of 552.55 ms) |
  | `dos_cap_sweep_real_cap4.json` | 4 | 371 / 129 | 1575.5 ms | FAIL (`/health` p95) |

  A smaller cap kept `/health` faster and accepted fewer requests. No cap size met the
  0.5 s rule with real inference.

**Residual risk and limits.**

- The delay-mode run, where the expensive request is simulated by a sleep, passes. The
  real-inference run does not meet the 0.5 s `/health` rule at the default cap of 2
  (924.8 ms in `dos_before_after_real.json`).
- Why real inference slows `/health` is not measured. Two hypotheses: the inference threads
  compete with the event loop for the Python interpreter lock (GIL), and the load generator
  shares the CPU with the server.
- The load generator and the server ran on the same machine.
- The rate limit and the cap are per worker process and held in memory. With N workers the
  limits are N times larger, and a restart resets the limiter.
- The rate limit is keyed by socket address. Behind a proxy every client would share one
  address; the service is run with `--no-proxy-headers` and no proxy, so it is not misled by
  `X-Forwarded-For`. The key is the peer IP address of the connection (`client[0]` in
  `RateLimitMiddleware`, `backend/app/rate_limit.py`), so clients that reach the API from
  one address, for example behind a NAT, share one limit.
- The rate limit is per address, so an attacker with many addresses is bounded only by the
  concurrency cap.

### 4b. Misconfiguration (brief section 2.7)

**Attack.** An attacker uses a weakness in the setup rather than in the code: a known
vulnerable dependency, a permissive CORS policy, missing security headers, exposed API
documentation, a leaked secret, or a server header that names the software version.

**Impact.** Ranges from information disclosure (documentation, versions) to cross-origin
abuse of the API or a dependency exploit.

**Defence.**

- Security headers on every response, added by `RequestContextMiddleware`
  (`backend/app/middleware.py`): `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store` and
  `Cross-Origin-Resource-Policy: same-origin`; API responses also get
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and
  `X-Frame-Options: DENY`.
- CORS pinned to exact origins (`CORS_ALLOW_ORIGINS`, default `http://localhost:5173`);
  `*`, paths and wildcards are refused at startup (`backend/app/config.py`); no credentials.
- `/docs` and `/openapi.json` are on by default for development and removed with
  `API_DOCS_ENABLED=false`, which the backend README says to set in deployment.
- No `Server` header: the run command passes `--no-server-header`.
- Error bodies use one shape with a fixed message and a request ID; exception text,
  tracebacks and paths never reach a response (`backend/app/errors.py`; checked by
  `test_unexpected_failure_is_generic_500` in `backend/tests/test_api.py`).
- Dependencies are pinned to exact versions (`backend/requirements*.txt`,
  `frontend/package.json` with `save-exact=true` in `frontend/.npmrc`, committed
  `package-lock.json`).

**Evidence.** Decisions are taken from `docs/misconfiguration.md`.

| Finding | Source | Decision |
|---|---|---|
| No known vulnerabilities in the backend requirements (`backend/evidence/pip_audit.txt`, pip-audit 2.10.1, Python 3.12.10, run 2026-11-03) | pip-audit | Justified (nothing to fix) |
| `follow-redirects` 1.16.1 via `axios` 1.20.0, GHSA-mrwp-f3q8-3g9p; updated to 1.16.2, and `frontend/evidence/npm_audit.txt` (npm 11.19.0, Node v26.8.1, run 2026-11-03) reports 0 vulnerabilities | npm audit | Fixed |
| `/docs` and `/openapi.json` reachable by default: 2 findings with docs on, 0 with docs off (`backend/evidence/security_headers.json`, recorded 2026-11-02 13:40 UTC) | header check | Justified for development; fixed in deployment by `API_DOCS_ENABLED=false` |
| Swagger UI at `/docs` loads its script and CSS from `cdn.jsdelivr.net`: `backend/app/main.py` sets only `docs_url`, so FastAPI 0.143.3 uses the default `swagger_js_url` and `swagger_css_url` in `fastapi/openapi/docs.py`. `/docs` is therefore outside the strict CSP | manual review | Justified for development; fixed by `API_DOCS_ENABLED=false` |
| With docs off, the `/docs` 404 has no CSP or `X-Frame-Options` | header check | Justified |
| CORS preflight responses carry none of the security headers | header check | Justified |
| CORS pinned to one exact origin: the preflight from `http://evil.example` gets 400 and no `Access-Control-Allow-Origin` | header check, manual review | Fixed (by design) |
| Security headers on API responses | header check | Fixed |
| No `Server` header | header check | Fixed by the run command |
| The frontend dev server sends no CSP or security headers | manual review | Justified (localhost only) |
| Rate limit and cap are per process and in memory | manual review | Justified |
| No secrets in the repository | manual review | Justified (nothing found) |
| ZAP: `Cross-Origin-Resource-Policy Header Missing or Invalid`, Low, 3 instances in `zap_api_docs_on_before_fix.json`; absent from `zap_api_docs_on.json` | ZAP 2.17.0 | Fixed |
| ZAP: `A Client Error response code was returned by the server`, Informational, 12 instances in each API scan | ZAP 2.17.0 | Justified |
| ZAP: `Non-Storable Content`, Informational, 3 instances in each API scan and 2 in `zap_baseline_docs_off.json` | ZAP 2.17.0 | Justified |

The ZAP reports in `backend/evidence/` were produced on 2026-11-02 between 13:10 and 13:19
UTC. No ZAP report has a High or Medium alert.

**Residual risk and limits.**

- The frontend was not scanned by ZAP, and its dev server sets no CSP
  (`docs/frontend-security.md` section 3).
- The security header evidence does not record the Python version or the server settings
  beyond the run label.
- The audits are a snapshot of the advisory databases on the day they ran.

### 4c. Detection evasion (brief section 2.8, look-alike Unicode)

**Attack.** A phisher rewrites a brand name in the URL with characters that look the same
but are different code points, so that the model no longer sees the n-grams it learned.
Five strategies were measured: one Cyrillic letter (`cyrillic_one`), every replaceable
letter in Cyrillic (`cyrillic_all`), Greek letters (`greek_mixed`), fullwidth Latin
(`fullwidth`) and Latin letters with a dot below or above (`dot_diacritics_uncovered`).

**Impact.** A phishing URL is scored as legitimate and the user trusts it.

**Defence.** `backend/app/services/normalization.py`, called from `ModelService.analyze`
when the setting `HOMOGLYPH_DEFENCE` is true (the default; `false` is the demo switch):

1. NFKC normalisation (folds fullwidth letters, mathematical letters, ligatures);
2. lowercase;
3. a confusables map: the A2 homoglyph map plus listed Cyrillic, Greek, Armenian and Latin
   look-alikes;
4. the A2 brand mask is decided on the **original** host, so a folded homograph of an
   official domain is not given the official-domain placeholder.

The folded text is scored with the verified pipeline's own fitted steps. `analysed_url` and
the rule signals stay on the unfolded text; n-gram signals of a folded URL get null offsets.

**Evidence.** `backend/evidence/evasion_before_after.json` (before recorded 2026-11-02
13:37 UTC, after 13:39 UTC; the file does not record the Python version). 10 repeats, each
of 579 variants (16 category A bases and 100 seeded category C bases):

| | defence off | defence on |
|---|---|---|
| evasion rate, mean (min to max) | 0.60% (0.17% to 1.21%) | 0.05% (0.00% to 0.17%) |
| adaptive attacker (bases with at least one strategy through), mean | 2.24% | 0.26% |
| benign URLs flagged as phishing | 20 of 295 | 20 of 295 |

The defence lowered the evasion rate in 10 of 10 repeats and never raised it. Both phases
PASS.

**Residual risk and limits.**

- Diacritic look-alikes (`dot_diacritics_uncovered`) are not covered on purpose, because
  stripping accents would change legitimate domains; that strategy is unchanged by the
  defence.
- Letters outside the confusables map are not folded.
- In the experiment, naive folding (brand mask decided on the folded text) made things
  worse: homograph detection fell from 16 of 16 to 10 of 16
  (`backend/experiments/results/summary.json`). The defence avoids this by deciding the mask
  on the original host.
- The absolute rates are small because the model already resists most variants, so the
  room for improvement is small.
- For a folded URL the score no longer equals the A2 `scripts/predict.py` score, and the
  n-gram signals cannot be highlighted in the URL.

## 5. Other risks from the brief

| Risk | Applies | Reason or control |
|---|---|---|
| SSRF | No | The backend never opens the submitted URL; `backend/app/` contains no HTTP client. `test_analysis_makes_no_network_or_subprocess_calls` in `backend/tests/test_security.py` fails the run if analysis opens a socket, resolves a name or calls `urlopen`. |
| Command injection | No | No `subprocess` or `os.system` in `backend/app/`; the same test also blocks `subprocess.Popen`. |
| SQL injection | No | There is no database. |
| File upload | No | `POST /analyze` takes exactly `{"url": string}` as JSON (`extra="forbid"` in `backend/app/schemas.py`, `Content-Type` checked in `routes.py`); there is no upload endpoint. |
| Broken access control | Low | There are no accounts, roles or admin endpoints. The endpoints are `GET /health`, `POST /analyze` and, when enabled, `/docs` and `/openapi.json`. Anyone who can reach the API can use it, by design; the rate limit and cap bound the use. |
| XSS and unsafe rendering | Low | The client renders every API string as plain text (contract section 6, rule 1); `frontend/src` contains no `dangerouslySetInnerHTML`. API responses are JSON with `nosniff` and `default-src 'none'`. |
| CORS abuse | Low | Exact origin list, `*` refused at startup, credentials off; a preflight from another origin gets 400 (`security_headers.json`). |
| Supply chain | Yes | Exact pins and a committed lockfile; pip-audit and npm audit report no known vulnerabilities (section 4b). The Python requirements pin versions but not hashes, so pip does not verify the downloaded files; `package-lock.json` records an integrity hash for each npm package. A vulnerability published after the audit date is not covered. |
| Unsafe model loading | Yes, in principle | joblib loading is pickle based and runs code while loading. `load_verified_bundle` in `backend/app/services/model_service.py` checks the installed scikit-learn version, reads the artefact bytes, compares their SHA-256 with `backend/model_manifest.json` (`hmac.compare_digest`), unpickles only those same bytes, and then checks the pipeline structure. The manifest path is `backend/model_manifest.json` or the operator's `MODEL_MANIFEST` setting, never a value from a request. |

What the SHA-256 check does not protect against:

- someone who can change both the model file and the manifest in the repository;
- a model that was already malicious when its digest was pinned;
- the code the pickle imports by name: `backend/app/a2.py` puts `scripts/` on the import
  path for `scripts/extract_features.py`, and that file is not covered by the digest;
- a compromised Python environment or dependency (scikit-learn, joblib).

## 6. Limitations and honest caveats

- Real-inference denial of service does not meet the 0.5 s `/health` rule at the default
  cap of 2 (924.8 ms, `dos_before_after_real.json`), nor at cap 1, 2 or 4 in the sweep.
  Only the delay-mode run, with a simulated expensive request, passes.
- The cause of the slow `/health` under real inference is a hypothesis (GIL contention,
  shared CPU), not a measured fact.
- The load generator shared the machine with the server.
- Rate limit and cap are per worker process, in memory and keyed by socket address.
- Each denial of service figure comes from one run of 5 repeats.
- The look-alike defence does not cover diacritics or letters outside its map, and the
  evasion rates were already small without it.
- For a folded URL the score differs from A2 `predict.py` and n-gram signals have no
  offsets.
- The frontend was not scanned by ZAP and its dev server sends no CSP.
- The SHA-256 model check does not cover the imported `scripts/` code or someone who can
  edit both the model and the manifest.
- Evidence files that lack metadata: `security_smoke.json` records no date, Python version
  or settings; `rate_limit_before_after.json` records no Python version, cap, body limit,
  delay or homoglyph setting; the `dos_*` files do not record the homoglyph setting;
  `evasion_before_after.json` records no Python version, cap, body limit or delay;
  `security_headers.json` records no Python version and no settings beyond its run label.

## 7. Evidence index

The commands are the ones in `backend/README.md` section 7 (section 8 for evasion) and, for
the header check and ZAP, in `docs/misconfiguration.md`. They are run from `backend/`
against a local server started with the README command.

| File | What it shows | How to repeat |
|---|---|---|
| `backend/evidence/pip_audit.txt` | No known vulnerabilities in the backend requirements | `pip-audit -r requirements.txt -r requirements-dev.txt` |
| `frontend/evidence/npm_audit.txt` | 0 npm vulnerabilities | `npm audit` from `frontend/` |
| `backend/evidence/security_smoke.json` | Body limit cases and one burst against the default server | `python scripts/security_smoke.py --burst 40 --json-out evidence/security_smoke.json` |
| `backend/evidence/rate_limit_before_after.json` | 429 limiter off and on, spoofed `X-Forwarded-For` | `python scripts/security/rate_limit_flood.py --phase before`, then `--phase after` (server with and without `RATE_LIMIT_ENABLED=false`) |
| `backend/evidence/dos_before_after.json` | Concurrency cap and body limit, delay mode | `python scripts/security/dos_before_after.py --phase before`, then `--phase after` (demo switches in README section 7) |
| `backend/evidence/dos_before_after_real.json` | The same with real inference | the same commands with `--expensive real` |
| `backend/evidence/dos_cap_sweep_real_before.json`, `_cap1.json`, `_cap2.json`, `_cap4.json` | Cap sweep with real inference | `python scripts/security/dos_before_after.py --phase after --expensive real --max-concurrency N --json-out evidence/dos_cap_sweep_real_capN.json --label "cap N"` (and the "no cap" before run) |
| `backend/evidence/evasion_before_after.json` | Look-alike evasion with the defence off and on | `python scripts/security/evasion_before_after.py --phase before`, then `--phase after` |
| `backend/evidence/security_headers.json` | Security headers and CORS, docs on and off | `scripts/security/check_headers.py`, two runs as described in the evidence table of `docs/misconfiguration.md` (`API_DOCS_ENABLED` default, then `false`) |
| `backend/evidence/zap_api_docs_on_before_fix.json` and `.html` | ZAP API scan before the CORP header | `zap-api-scan.py` steps in `docs/misconfiguration.md` |
| `backend/evidence/zap_api_docs_on.json` and `.html` | ZAP API scan after the CORP header | as above |
| `backend/evidence/zap_baseline_docs_off.json`, `.html` and `zap.yaml` | ZAP baseline scan with docs off | `zap-baseline.py` steps in `docs/misconfiguration.md` |
