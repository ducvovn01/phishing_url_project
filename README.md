# Phishing URL Detector (COS30049, Assignment 3)

A web application that scores the text of a URL as phishing or legitimate. A React client
sends the URL to a FastAPI service, which scores it with the char n-gram model trained in
Assignment 2 and returns a verdict, a trust score and the parts of the URL that pushed the
score up or down.

Offline constraint: the URL is only ever treated as text. The backend never fetches the
page, resolves DNS, runs WHOIS or calls a reputation service.

## Contents of the ZIP

| Folder or file | What it holds |
|---|---|
| `backend/` | The FastAPI service (`app/`), its tests (`tests/`), the security evidence scripts (`scripts/`), the evidence files (`evidence/`), the look-alike experiment (`experiments/`) and `backend/README.md` |
| `frontend/` | The React and Vite client (`src/`), `package.json`, `package-lock.json`, the npm audit evidence (`evidence/`) and `frontend/README.md` |
| `docs/` | API contract, threat model, misconfiguration review, frontend security, accessibility, and the Assignment 2 pipeline guide (`model-pipeline.md`) |
| `models/` | The trained Assignment 2 models (`*.joblib`); the API serves `char_ngram.joblib` |
| `data/` | Processed dataset, reference brand list, analysis reports and `test_urls.csv` |
| `scripts/` | The Assignment 2 pipeline: data preparation, feature extraction, training and `predict.py` |
| `requirements.txt` | Python dependencies of the Assignment 2 pipeline |

TODO(team): confirm which large data files are left out of the ZIP.

## Architecture

```
 +--------------------+        HTTP, JSON         +------------------------------+
 | Browser            |  POST /analyze {"url"}    | FastAPI backend              |
 | React client       | ------------------------> | uvicorn, port 8000           |
 | Vite, port 5173    | <------------------------ | middleware, validation,      |
 +--------------------+  verdict, trust score,    | concurrency cap              |
                         signals                  +--------------+---------------+
                                                                 |
                                                                 v
                                                  +------------------------------+
                                                  | ModelService                 |
                                                  | models/char_ngram.joblib     |
                                                  | SHA-256 checked against      |
                                                  | backend/model_manifest.json  |
                                                  +------------------------------+
```

The full data flow, with the middleware order and the trust boundary, is in
[docs/threat-model.md](docs/threat-model.md).

## Requirements and pinned versions

- Python 3.12.10 (the version in `backend/evidence/pip_audit.txt`; `backend/README.md` says
  it was tested on Windows 11).
- Node v26.8.1 and npm 11.19.0 (the versions in `frontend/evidence/npm_audit.txt`).
  `frontend/package.json` allows Node `^22.22.2 || ^24.15.0 || >=26.0.0`.

| Package | Version | Pinned in |
|---|---|---|
| FastAPI | 0.143.3 | `backend/requirements.txt` |
| Uvicorn | 0.54.0 | `backend/requirements.txt` |
| Pydantic | 2.14.1 | `backend/requirements.txt` |
| scikit-learn | 1.9.1 | `backend/requirements.txt` (the model was saved with it; the API refuses any other version) |
| joblib | 1.6.0 | `backend/requirements.txt` |
| React | 19.3.1 | `frontend/package.json` |
| MUI (`@mui/material`) | 9.5.0 | `frontend/package.json` |
| MUI X Charts (`@mui/x-charts`) | 9.16.0 | `frontend/package.json` |
| axios | 1.20.0 | `frontend/package.json` |
| Vite | 8.3.4 | `frontend/package.json` (dev dependency) |

## Quick start

Backend, from `backend/` (from `backend/README.md`):

```bash
cd backend
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
python -m pip install -r requirements.txt        # runtime only
python -m pip install -r requirements-dev.txt    # + tests and experiments
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
```

Check it: `curl http://localhost:8000/health` returns `{"status":"ok","model_loaded":true}`.

Frontend, from `frontend/` in a second terminal (from `frontend/README.md`):

```sh
npm ci          # install exact versions from package-lock.json
npm run dev     # dev server on http://localhost:5173
```

Open <http://localhost:5173> in a browser. With no `.env` file the client talks to
`http://localhost:8000`.

## Running the tests

```bash
# backend, from backend/ with the venv active (needs requirements-dev.txt)
python -m pytest

# frontend, from frontend/
npm run lint
npm test
```

Results on the final code: backend 204 passed, 0 failed (Python 3.12.10); frontend 23 test
files and 318 tests passed, 0 failed.

## Using the app

Type a URL into the form and submit it. The page shows the verdict, the trust score
(0 to 100, higher means more likely legitimate), the submitted URL with the parts that
influenced the score highlighted, a list of signals and a chart of their weights. The
session page compares the checks made in the current tab; nothing is stored after the tab
is closed.

- `paypa1-secure-login.top/verify`: the real model output in `docs/api-contract.md`
  section 3.2 is label `phishing` with trust score 0.
- `https://en.wikipedia.org/wiki/Phishing`: the legitimate example in
  `docs/api-contract.md` section 3.5 is label `legitimate` with trust score 99.

## Security

Three items are marked for this assignment. The full analysis, with evidence numbers and
limits, is in [docs/threat-model.md](docs/threat-model.md).

| Item | What | Where in code | Evidence | How to repeat |
|---|---|---|---|---|
| Denial of service (2.7) | Per-client rate limit (429), 8 KB body limit (413), URL length cap, concurrency cap (503, default 2) | `backend/app/rate_limit.py`, `backend/app/middleware.py`, `backend/app/validation.py`, `backend/app/routes.py` | `backend/evidence/rate_limit_before_after.json`, `dos_before_after.json`, `dos_before_after_real.json`, `dos_cap_sweep_real_*.json`, `security_smoke.json` | `backend/README.md` section 7 |
| Misconfiguration (2.7) | Dependency audits, security headers, CORS pinned, docs switched off in deployment, ZAP scan | `backend/app/middleware.py`, `backend/app/config.py` | `backend/evidence/pip_audit.txt`, `frontend/evidence/npm_audit.txt`, `backend/evidence/security_headers.json`, `backend/evidence/zap_*.json` | `docs/misconfiguration.md` |
| Detection evasion (2.8) | Look-alike Unicode folded before scoring (NFKC, lowercase, confusables map, brand mask decided on the original host) | `backend/app/services/normalization.py`, `backend/app/services/model_service.py` | `backend/evidence/evasion_before_after.json` | `backend/README.md` section 8 |

Limits: with real inference the service does not keep `/health` under 0.5 s during a
flood of 100 requests at the default cap of 2 (924.8 ms in `dos_before_after_real.json`).
The 0.5 s is the team's own target for `/health` during the flood, not a standard;
only the run with a simulated expensive request passes. The rate limit and the cap are per
worker process and keyed by socket address. The look-alike defence does not cover
diacritics, and evasion was already rare without it (0.60% of variants, 0.05% with it).
The frontend was not scanned by ZAP and its dev server sends no CSP.

## How to reproduce the evidence

Run from `backend/` with the venv active. Each block needs a server started with the
README command and the switches shown; stop it between phases. The demo switches are for
the before/after recordings only and must never be set in deployment.

```bash
# 1. Smoke test of the body limit and a burst, against the default server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
python scripts/security_smoke.py --burst 40 --json-out evidence/security_smoke.json

# 2. Rate limit before/after
#   BEFORE: PowerShell: $env:RATE_LIMIT_ENABLED="false"    bash: export RATE_LIMIT_ENABLED=false
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-access-log
python scripts/security/rate_limit_flood.py --phase before
#   stop, unset RATE_LIMIT_ENABLED (PowerShell: Remove-Item Env:RATE_LIMIT_ENABLED), start again
python scripts/security/rate_limit_flood.py --phase after

# 3. Denial of service, delay mode
#   BEFORE: PowerShell: $env:RATE_LIMIT_ENABLED="false"; $env:CONCURRENCY_CAP_ENABLED="false"
#                       $env:BODY_LIMIT_ENABLED="false"; $env:DEMO_ANALYZE_DELAY_MS="1000"
#           bash:       export RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false
#                       export BODY_LIMIT_ENABLED=false DEMO_ANALYZE_DELAY_MS=1000
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
python scripts/security/dos_before_after.py --phase before
#   stop, unset CONCURRENCY_CAP_ENABLED and BODY_LIMIT_ENABLED (keep the other two), start again
python scripts/security/dos_before_after.py --phase after

# 4. Denial of service, real mode: the same, but DEMO_ANALYZE_DELAY_MS must NOT be set
#   before: RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false BODY_LIMIT_ENABLED=false
#   after:  RATE_LIMIT_ENABLED=false
python scripts/security/dos_before_after.py --phase before --expensive real
python scripts/security/dos_before_after.py --phase after --expensive real

# 5. Concurrency cap sweep with real inference
#   no cap: RATE_LIMIT_ENABLED=false CONCURRENCY_CAP_ENABLED=false BODY_LIMIT_ENABLED=false
python scripts/security/dos_before_after.py --phase before --expensive real --json-out evidence/dos_cap_sweep_real_before.json --label "no cap"
#   cap N: RATE_LIMIT_ENABLED=false ANALYZE_MAX_CONCURRENCY=N (N = 1, 2, 4)
python scripts/security/dos_before_after.py --phase after --expensive real --max-concurrency N --json-out evidence/dos_cap_sweep_real_capN.json --label "cap N"

# 6. Detection evasion before/after
#   BEFORE: PowerShell: $env:RATE_LIMIT_ENABLED="false"; $env:HOMOGLYPH_DEFENCE="false"
#           bash:       export RATE_LIMIT_ENABLED=false HOMOGLYPH_DEFENCE=false
uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --no-access-log
python scripts/security/evasion_before_after.py --phase before
#   stop, unset HOMOGLYPH_DEFENCE (keep RATE_LIMIT_ENABLED=false), start again
python scripts/security/evasion_before_after.py --phase after
```

The dependency audits, the header check and the ZAP scans are described in
[docs/misconfiguration.md](docs/misconfiguration.md).

## The model and data

The served model is the Assignment 2 char n-gram model: hashed 3 to 5 character n-grams,
TF-IDF and logistic regression, saved as `models/char_ngram.joblib`. It was trained on four
phishing URL datasets, combined and deduplicated into 1,607,776 rows, with a
domain-grouped 80/20 split so that no registrable domain is in both training and test data.
The backend loads it only after its SHA-256 matches `backend/model_manifest.json` and
reads the decision threshold (0.5) from the saved bundle. The model sees only the URL text.
The training pipeline and its commands are in
[docs/model-pipeline.md](docs/model-pipeline.md).

## Repository layout

```
.
├── backend/          FastAPI service, tests, security scripts, evidence, experiment
│   ├── app/
│   ├── evidence/
│   ├── experiments/
│   ├── scripts/
│   └── tests/
├── frontend/         React and Vite client
│   ├── evidence/
│   └── src/
├── docs/             contract, threat model, security reviews, pipeline guide
├── models/           trained models (*.joblib)
├── data/             processed data, reference lists, analysis reports
├── scripts/          Assignment 2 pipeline
├── requirements.txt  Assignment 2 Python dependencies
└── README.md
```

## Team and contributions

- TODO(team): member 1 name, student ID and role.
- TODO(team): member 2 name, student ID and role.
- TODO(team): member 3 name, student ID and role.
- TODO(team): add or remove rows to match the team, and describe what each member
  contributed.

## Use of generative AI

TODO(team): list the tools used, what they were used for, and how the output was checked.

## References

- FastAPI (TODO(team): confirm year and access date) *FastAPI*, version 0.143.3.
  TODO(team): add URL.
- Uvicorn (TODO(team): confirm year and access date) *Uvicorn*, version 0.54.0.
  TODO(team): add URL.
- Pydantic (TODO(team): confirm year and access date) *Pydantic*, version 2.14.1.
  TODO(team): add URL.
- scikit-learn (TODO(team): confirm year and access date) *scikit-learn*, version 1.9.1. TODO(team): add URL.
- joblib (TODO(team): confirm year and access date) *joblib*, version 1.6.0.
  TODO(team): add URL.
- React (TODO(team): confirm year and access date) *React*, version 19.3.1.
  TODO(team): add URL.
- MUI (TODO(team): confirm year and access date) *Material UI*, version 9.5.0, and
  *MUI X Charts*, version 9.16.0. TODO(team): add URL.
- axios (TODO(team): confirm year and access date) *axios*, version 1.20.0.
  TODO(team): add URL.
- Vite (TODO(team): confirm year and access date) *Vite*, version 8.3.4.
  TODO(team): add URL.
- Mitake (TODO(team): confirm year and access date) *PhishingURLsANDBenignURLs*
  [dataset], Hugging Face. TODO(team): add URL.
- semihGuner2002 (TODO(team): confirm year and access date) *PhishingURLsDataset*
  [dataset], Hugging Face (gated). TODO(team): add URL.
- harisudhan411 (TODO(team): confirm year and access date) *phishing-and-legitimate-urls*
  [dataset], Kaggle. TODO(team): add URL.
- TODO(team): confirm authors, year and access date. *PhiUSIIL Phishing URL Dataset*
  [dataset], UCI Machine Learning Repository. TODO(team): add URL.
- TODO(team): confirm the publisher, year and access date. *OWASP ZAP*, version 2.17.0
  (the Docker image `ghcr.io/zaproxy/zaproxy:stable`). TODO(team): add URL.
- Unicode Consortium (TODO(team): confirm year and access date) *confusables.txt*
  (cited in `backend/app/services/normalization.py`). TODO(team): add URL.

## Before submitting

- [ ] Replace every TODO(team) in this README and in the other docs.
- [ ] Test the ZIP on a clean machine: unzip, follow the quick start, run both test suites.
- [ ] Remove `node_modules/`, `.venv/` and `dist/` from the ZIP.
- [ ] Run both test suites (`python -m pytest` in `backend/`, `npm test` in `frontend/`).
