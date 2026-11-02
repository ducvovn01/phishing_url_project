# Misconfiguration review (section 2.7)

Evidence gathered on 2026-11-02 on Windows 11. The brief asks for pip-audit, npm audit and an
OWASP ZAP scan of the running app, then a decision on each finding. The audits and the header
check below were run for real; the ZAP scan is still to be run (see the last section).

| Evidence | Command | File |
|---|---|---|
| Python dependencies | `pip-audit -r requirements.txt -r requirements-dev.txt` (from `backend/`, pip-audit 2.10.1, Python 3.14.7) | `backend/evidence/pip_audit.txt` |
| JavaScript dependencies | `npm audit` (from `frontend/`, npm 11.19.0, Node v26.8.1), 2026-11-02: first run 1 high (`follow-redirects`), 0 vulnerabilities after `npm audit fix` | `frontend/evidence/npm_audit.txt` (the run after the fix) |
| Response headers and CORS | `scripts/security/check_headers.py`, two runs on port 8001 with the README command (`--no-proxy-headers --no-server-header --no-access-log`): `API_DOCS_ENABLED` at its default, then `API_DOCS_ENABLED=false` | `backend/evidence/security_headers.json` |
| ZAP baseline scan | not run yet | see "ZAP scan" |

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
| Security headers on API responses | header check | None (control in place) | Fixed | Every JSON response checked (200, 422, 404, 405, `/openapi.json`) has `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'` and `X-Frame-Options: DENY`. No response had a `Server` header. |
| No `Server` header | header check | None (control in place) | Fixed by the run command | The README command passes `--no-server-header`. Not tested without that flag. |
| The frontend dev server sends no CSP, `X-Content-Type-Options` or frame protection | manual review (`docs/frontend-security.md` section 3) | Medium if deployed, low as run (localhost only) | Justified | The frontend runs only as a local dev server or a static build on localhost; there is no production host to configure. The headers a host should set (strict CSP with `connect-src` limited to the API origin, `frame-ancestors 'none'`) are listed in that section. |
| The rate limit (429) and the concurrency cap (503) are per worker process and held in memory | manual review (README section 7) | Low | Justified | The service runs as one uvicorn process on localhost, so per-process is the whole service. With N workers the limits become N times larger, and a restart resets the limiter. The limiter keys on the socket address with `--no-proxy-headers`, so all localhost traffic shares one bucket (which matters for scanners, see below). |
| No secrets in the repository | manual review | None found | Justified (nothing to fix) | Searched every file outside `.git`, `node_modules`, `.venv`, `dist` and caches for: AWS access keys (`AKIA` + 16), private key blocks (`BEGIN ... PRIVATE KEY`), GitHub tokens (`gh[pousr]_`), Slack tokens (`xox?-`), Google API keys (`AIza`), `sk-` style API keys, JWTs (`eyJ...eyJ...`), URLs with a password (`scheme://user:pass@`), and `password`/`secret`/`api_key`/`access_token` assigned a quoted value; also for `.env`, `*.pem`, `*.key`, `id_rsa*`, `*.p12`, `*.pfx` files. No AWS, private key, GitHub, Slack or Google pattern matched. The other matches are all inside phishing-dataset URLs (`data/processed/*.csv`, `backend/experiments/results/benign.csv`) and two URL-validation fixtures in `backend/tests/test_validation.py`, not credentials. The only env file is `frontend/.env.example`, with two non-secret keys (`VITE_API_BASE_URL`, `VITE_USE_MOCK`); `.env` files are ignored by `.gitignore`. The backend needs no secrets. |

## ZAP scan

Not run yet. Steps for the person running it by hand:

1. Start the API from `backend/` with the limiter off. All localhost traffic shares one
   rate-limit bucket, so with the limiter on the scan would mostly see 429s:

   ```bash
   # PowerShell: $env:RATE_LIMIT_ENABLED="false"
   # bash:       export RATE_LIMIT_ENABLED=false
   uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
   ```

   Optionally scan a second time with `API_DOCS_ENABLED=false` as well, to see the
   deployment configuration.

2. Run the ZAP baseline scan (spider plus passive rules, no attacks) against
   `http://localhost:8000`, saving the reports in `backend/evidence/`. With the ZAP Docker
   image, from `backend/`:

   ```bash
   docker run --rm -v "$(pwd)/evidence:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable \
     zap-baseline.py -t http://host.docker.internal:8000 -r zap_baseline.html -J zap_baseline.json
   ```

   `host.docker.internal` is how the container reaches the host. If the container cannot
   reach a server bound to `127.0.0.1`, use the ZAP desktop app on the host instead (target
   `http://localhost:8000`, spider and passive scan only), or bind uvicorn to `0.0.0.0` for
   the duration of the scan only, on a trusted network.

3. Stop the server, unset `RATE_LIMIT_ENABLED`, and fill in one row per ZAP alert below:
   fixed (what changed) or justified (why it does not apply).

| ZAP alert | Risk | URL(s) | Decision | Reason |
|---|---|---|---|---|
| | | | | |
| | | | | |
| | | | | |
