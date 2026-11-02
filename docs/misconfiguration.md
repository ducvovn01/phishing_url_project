# Misconfiguration review (section 2.7)

Evidence gathered on 2026-11-02 on Windows 11; the audits and the header check were re-run on
2026-11-03 with Python 3.12.10. The brief asks for pip-audit, npm audit and an
OWASP ZAP scan of the running app, then a decision on each finding. The audits and the header
check below were run for real, and the ZAP scans were run by hand on 2026-11-03 (see the
last section).

| Evidence | Command | File |
|---|---|---|
| Python dependencies | `pip-audit -r requirements.txt -r requirements-dev.txt` (from `backend/`, pip-audit 2.10.1, Python 3.12.10), 2026-11-03: no known vulnerabilities | `backend/evidence/pip_audit.txt` |
| JavaScript dependencies | `npm audit` (from `frontend/`, npm 11.19.0, Node v26.8.1), 2026-11-02: first run 1 high (`follow-redirects`), 0 vulnerabilities after `npm audit fix`; re-run 2026-11-03: 0 vulnerabilities | `frontend/evidence/npm_audit.txt` (the 2026-11-03 run) |
| Response headers and CORS | `scripts/security/check_headers.py`, two runs on port 8001 with the README command (`--no-proxy-headers --no-server-header --no-access-log`): `API_DOCS_ENABLED` at its default, then `API_DOCS_ENABLED=false` | `backend/evidence/security_headers.json` |
| ZAP API scan, docs on, before the CORP fix | `zap-api-scan.py`, ZAP 2.17.0 (see "ZAP scan") | `backend/evidence/zap_api_docs_on_before_fix.html`, `backend/evidence/zap_api_docs_on_before_fix.json` |
| ZAP API scan, docs on, after the CORP fix | `zap-api-scan.py`, ZAP 2.17.0 | `backend/evidence/zap_api_docs_on.html`, `backend/evidence/zap_api_docs_on.json` |
| ZAP baseline scan, docs off, after the CORP fix | `zap-baseline.py`, ZAP 2.17.0 | `backend/evidence/zap_baseline_docs_off.html`, `backend/evidence/zap_baseline_docs_off.json`, and `backend/evidence/zap.yaml` (the automation plan ZAP wrote for this baseline run) |

## Findings

| Finding | Source | Severity | Decision | Reason |
|---|---|---|---|---|
| No known vulnerabilities in the backend's runtime and dev requirements | pip-audit | None | Justified (nothing to fix) | `No known vulnerabilities found`, exit code 0. Re-run before each release. |
| `follow-redirects` 1.16.1 (pulled in by `axios` 1.20.0): GHSA-mrwp-f3q8-3g9p, cross-realm `sensitiveHeaders` discarded, custom credentials can follow redirects | npm audit | High as rated by the advisory; low for this app | Fixed | `npm audit fix` updated `follow-redirects` from 1.16.1 to 1.16.2 in `package-lock.json`; no other package and not `package.json` changed, and `npm audit` now reports 0 vulnerabilities. The browser bundle was not exposed before the fix either: only axios's Node.js `http` adapter uses `follow-redirects`, axios's `browser` field maps that adapter to `lib/helpers/null.js`, and the built bundle in `frontend/dist/assets` contains no `follow-redirects` code (a search finds only the axios option name `maxRedirects`, before and after the fix). The app runs in the browser and sends no credentials. |
| `/docs` and `/openapi.json` are reachable with the default settings | header check | Medium in deployment, none in development | Justified for development; fixed in deployment by `API_DOCS_ENABLED=false` | Run "docs on (default)": both return 200, the only 2 findings. Run "docs off": both return 404, 0 findings. The README settings table says to set `false` in deployment. |
| Swagger UI at `/docs` loads its script and CSS from `cdn.jsdelivr.net` (`swagger-ui-dist@5`) and its favicon from `fastapi.tiangolo.com`; `/docs` is therefore left out of the API's strict CSP | manual review (`fastapi/openapi/docs.py`, `app/middleware.py`) | Medium in deployment (breaks the offline constraint, third-party script) | Justified for development; fixed in deployment by `API_DOCS_ENABLED=false` | Development convenience only. With docs off nothing on the API loads from a CDN, and the strict CSP covers every other response. |
| With docs off, the 404 for `/docs` has no `Content-Security-Policy` or `X-Frame-Options` | header check | Low | Justified | The middleware exempts the `/docs` path from the API-only headers whether or not docs are enabled. The 404 is a JSON error body with `nosniff` and `no-store`, so there is nothing to frame or run. |
| CORS preflight responses (`OPTIONS`) carry none of the security headers | header check | Low | Justified | `CORSMiddleware` is the outermost layer and answers preflights itself. The bodies are fixed plain text (200 for the allowed origin, 400 for others) with no data. |
| CORS is pinned to one exact origin | header check, manual review (`app/config.py`) | None (control in place) | Fixed (by design) | Preflight from `http://localhost:5173`: 200 with `Access-Control-Allow-Origin: http://localhost:5173`. Preflight from `http://evil.example`: 400 and no `Access-Control-Allow-Origin`. Credentials are off, and `*`, paths and wildcards in `CORS_ALLOW_ORIGINS` are refused at startup. |
| Security headers on API responses | header check | None (control in place) | Fixed | Every JSON response checked (200, 422, 404, 405, `/openapi.json`) has `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `X-Frame-Options: DENY`. No response had a `Server` header. Since 2026-11-03 every response also carries `Cross-Origin-Resource-Policy: same-origin` (ZAP finding below), recorded by the 2026-11-03 header check on every non-preflight response and also checked by the backend tests and the second ZAP report. |
| No `Server` header | header check | None (control in place) | Fixed by the run command | The README command passes `--no-server-header`. Not tested without that flag. |
| The frontend dev server sends no CSP, `X-Content-Type-Options` or frame protection | manual review (`docs/frontend-security.md` section 3) | Medium if deployed, low as run (localhost only) | Justified | The frontend runs only as a local dev server or a static build on localhost; there is no production host to configure. The headers a host should set (strict CSP with `connect-src` limited to the API origin, `frame-ancestors 'none'`) are listed in that section. |
| The rate limit (429) and the concurrency cap (503) are per worker process and held in memory | manual review (README section 7) | Low | Justified | The service runs as one uvicorn process on localhost, so per-process is the whole service. With N workers the limits become N times larger, and a restart resets the limiter. The limiter keys on the socket address with `--no-proxy-headers`, so all localhost traffic shares one bucket (which matters for scanners, see below). |
| No secrets in the repository | manual review | None found | Justified (nothing to fix) | Searched every file outside `.git`, `node_modules`, `.venv`, `dist` and caches for: AWS access keys (`AKIA` + 16), private key blocks (`BEGIN ... PRIVATE KEY`), GitHub tokens (`gh[pousr]_`), Slack tokens (`xox?-`), Google API keys (`AIza`), `sk-` style API keys, JWTs (`eyJ...eyJ...`), URLs with a password (`scheme://user:pass@`), and `password`/`secret`/`api_key`/`access_token` assigned a quoted value; also for `.env`, `*.pem`, `*.key`, `id_rsa*`, `*.p12`, `*.pfx` files. No AWS, private key, GitHub, Slack or Google pattern matched. The other matches are all inside phishing-dataset URLs (`data/processed/*.csv`, `backend/experiments/results/benign.csv`) and two URL-validation fixtures in `backend/tests/test_validation.py`, not credentials. The only env file is `frontend/.env.example`, with two non-secret keys (`VITE_API_BASE_URL`, `VITE_USE_MOCK`); `.env` files are ignored by `.gitignore`. The backend needs no secrets. |

## ZAP scan

Run by hand on 2026-11-03 (the reports are stamped 2 Nov 2026, 13:10 to 13:19 UTC) with
OWASP ZAP 2.17.0 in Docker (`ghcr.io/zaproxy/zaproxy:stable`), against the backend on the
same machine, reached from the container as `http://host.docker.internal:8000`. The
frontend was not scanned; its missing CSP and security headers on the Vite dev server are
covered in `docs/frontend-security.md` section 3 and in the findings table above.

Settings for the scans (as reported by the person who ran them; the reports record the
target and report names, not the server settings): the backend was started with the rate
limiter and the concurrency cap switched off (`RATE_LIMIT_ENABLED=false`,
`CONCURRENCY_CAP_ENABLED=false`), so the scan was not answered with 429 and 503, and it
listened on `0.0.0.0` only for the scans so that the container could reach it.

1. **API scan, docs on** (`zap-api-scan.py`: imports the OpenAPI definition, then runs the
   active scan rules). The reports list `http://host.docker.internal:8000` as the site and
   include `/openapi.json`, and the report names are those in `backend/evidence/`; the
   command line itself is not recorded in any file, and `-f openapi` is the script's
   required format option for an OpenAPI definition:

   ```bash
   zap-api-scan.py -t http://host.docker.internal:8000/openapi.json -f openapi -r zap_api_docs_on.html -J zap_api_docs_on.json
   ```

   Run once before the CORP fix (reports saved as `zap_api_docs_on_before_fix.*`) and once
   after it (`zap_api_docs_on.*`).

2. **Baseline scan, docs off** (`zap-baseline.py`: spider plus passive rules, no attacks),
   with `API_DOCS_ENABLED=false`, after the fix. Target and report names from `zap.yaml`:

   ```bash
   zap-baseline.py -t http://host.docker.internal:8000 -r zap_baseline_docs_off.html -J zap_baseline_docs_off.json
   ```

   An earlier docs-off baseline run before the fix had the same result; only the later
   report is kept.

Alerts per report (from the JSON files):

| Report | Low | Informational |
|---|---|---|
| API scan, docs on, before the fix | 1 (Cross-Origin-Resource-Policy, 3 instances) | 2 |
| API scan, docs on, after the fix | 0 | 2 |
| Baseline scan, docs off, after the fix | 0 | 1 |

No report has a High or Medium alert. The active scan raised no injection, cross-site
scripting, path traversal or server-side request forgery alert: the three alerts below are
the only ones in any of the reports.

| Alert | Risk | Instances | Decision | Reason |
|---|---|---|---|---|
| Cross-Origin-Resource-Policy Header Missing or Invalid (plugin 90004, CWE-693) | Low (confidence Medium) | 3 before the fix (`GET /health`, `GET /openapi.json`, `POST /analyze`); 0 after | Fixed | `Cross-Origin-Resource-Policy: same-origin` added to the security headers in `backend/app/middleware.py`, so every response carries it, errors included. Recorded in the `docs/api-contract.md` change log (2026-11-03) and checked by the backend tests on 200, 404, 413, 422, 429 and 503 responses. Absent from the second API scan report. |
| A Client Error response code was returned by the server (plugin 100000, CWE-388) | Informational (confidence High) | 12 in each API scan: 11 with evidence 404, 1 with evidence 422 | Justified | ZAP probes paths that do not exist, such as `/actuator/health`, `/` and cloud metadata URLs (`/latest/meta-data/`, `/computeMetadata/v1/`, `/metadata/instance`, `/openstack/latest/meta_data.json`, and others), and sends malformed bodies. The 404 answers for unknown paths and the 422 on `POST /analyze` are the intended rejections, in the contract's error shape with no internal detail. |
| Non-Storable Content (plugin 10049, CWE-524) | Informational (confidence Medium) | 3 in each API scan (`GET /health`, `GET /openapi.json`, `POST /analyze`); 2 in the baseline scan (`GET /`, `GET /robots.txt`) | Justified | The evidence is our own `Cache-Control: no-store`, set on purpose on every response so that analysis results, which include the submitted URL, are never cached. |

### How to repeat

1. From `backend/`, start the backend with the two switches off and listening on all
   interfaces (only on a trusted network, and only for the scan):

   ```bash
   # PowerShell: $env:RATE_LIMIT_ENABLED="false"; $env:CONCURRENCY_CAP_ENABLED="false"
   # bash:       export RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --no-proxy-headers --no-server-header --no-access-log
   ```

2. Check that the container can reach it:

   ```bash
   docker run --rm ghcr.io/zaproxy/zaproxy:stable curl -s http://host.docker.internal:8000/health
   ```

   It should print `{"status":"ok","model_loaded":true}`.

3. Run the API scan with docs on (the default), saving the reports in `backend/evidence/`:

   ```bash
   docker run --rm -v "$(pwd)/evidence:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-api-scan.py -t http://host.docker.internal:8000/openapi.json -f openapi -r zap_api_docs_on.html -J zap_api_docs_on.json
   ```

4. Restart the backend with `API_DOCS_ENABLED=false` as well and run the baseline scan:

   ```bash
   docker run --rm -v "$(pwd)/evidence:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:8000 -r zap_baseline_docs_off.html -J zap_baseline_docs_off.json
   ```

5. Stop the backend, unset the three variables, and go back to the normal start command
   (`--host 127.0.0.1`, see `backend/README.md` section 2).
