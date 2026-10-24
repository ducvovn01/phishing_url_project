# Frontend security notes

Written for the threat model (COS30049 A3, Security). It describes what the frontend in `frontend/` trusts, what it never does, and how each rule is checked. The API rules it follows are in `docs/api-contract.md` section 6. The backend's own defences are documented separately.

Scope: the React client only. It sends one URL string to the backend and shows the answer. It never fetches the submitted URL, never opens it, and calls no service except the backend API (so it also respects the project's offline constraint).

## 1. What the frontend trusts

| Source | Trust | Why |
|---|---|---|
| The user's input | None | It is any text, including hostile URLs such as `javascript:...`. It is validated in the form and again by the backend. |
| The API response | Only after validation | A response is accepted only if every field has the contract's type and range (`isAnalysisResponse` in `src/api/client.js`). Anything else becomes a generic `internal_error`. |
| API error bodies | Limited | Only the code, a message of at most 300 characters, filtered `details` and a `request_id` are used (`src/api/errors.js`). Raw error text, stack traces and headers other than `Retry-After` are never copied into the UI. |
| Environment variables | Public | `VITE_API_BASE_URL` and `VITE_USE_MOCK` are compiled into the bundle and visible to anyone. They must never hold a secret. |

## 2. Threats and how the frontend handles them

| Threat | What the frontend does | Where | Check |
|---|---|---|---|
| Script injection (XSS) through the submitted URL or any API string | Every string is rendered as a React text node. `dangerouslySetInnerHTML`, `innerHTML` and `eval` are not used. The highlighted URL is built by cutting the string by code point and wrapping the pieces in React elements. | all components, `src/lib/segmentUrl.js` | Search of `src/` finds 0 uses. Test: `HomePage.test.jsx` ("a javascript: URL is shown as plain text and never becomes a link"). |
| The user clicks or the app opens a malicious link | The submitted URL is plain text only. It is never an anchor, never passed to `window.open`, and never used for navigation. The page tells the user not to open a flagged link. The only `href` in the app is the skip link to `#main-content`. The only `window.location` use is the error boundary's reload. | `SubmittedUrl.jsx`, `SessionPage.jsx`, `ErrorBoundary.jsx` | `HomePage.test.jsx` and `SessionPage.test.jsx` ("plain-text links"). Search finds 0 `window.open` and 1 `window.location` (the reload). |
| A hostile or broken backend response | The client validates the response shape and ranges before use. A malformed 200 becomes `internal_error`. Signal offsets that are not integers or are out of range are ignored for highlighting. Unknown error codes are treated as `internal_error`. | `src/api/client.js`, `src/lib/segmentUrl.js`, `ErrorState.jsx` | `client.test.js` ("a 200 with a malformed body becomes internal_error", "a non-JSON error body ..."), `errors.test.js` (message over 300 characters replaced), `segmentUrl.test.js`. |
| Information leaks through error screens | Error screens show a title chosen by code, the safe message, the request id and the wait time. They never show `details`, stack traces or exception text. | `ErrorState.jsx`, `errors.js` | `HomePage.test.jsx` ("the error state shows the message and reference, but no details or stack"). |
| Data kept in the browser | Results live in React state only. Nothing is written to `localStorage`, `sessionStorage`, cookies or IndexedDB. A refresh clears everything. | `src/session/SessionContext.jsx` | A search of all of `src/` (2026-10-24) finds no use of `localStorage`, `sessionStorage`, `document.cookie`, `indexedDB` or `caches`, and `frontend/README.md` documents the rule. Re-check with the search in section 4. |
| Credentials and secrets | The app has no login, no tokens and no cookies, and the API client sends no credentials. `.env` files are ignored by git (`frontend/.gitignore`); only `.env.example` with empty values is committed. | `frontend/.gitignore`, `.env.example` | `.env` and `.env.local` are not in the PR. |
| Cross-origin abuse | The backend allows only the exact origin `http://localhost:5173`. The dev server and `npm run preview` both use port 5173 with `strictPort: true`, so they never move to another port, which the backend would block. | `vite.config.js`, backend config | Backend CORS settings. |
| Supply chain | Every dependency is pinned to an exact version (`save-exact=true` in `.npmrc`), `package-lock.json` is committed, and installs use `npm ci`. `npm audit` reports 0 vulnerabilities. No script, font or image is loaded from a CDN, so the page makes no request except to the backend. | `package.json`, `.npmrc` | `npm audit` on the final branch. |
| Test code shipped to users | The mock API is chosen at build time with `VITE_USE_MOCK` and is left out of the production bundle (the bundle did not change when the mock changed). Mock triggers only work in mock mode. | `src/api/index.js`, `src/api/mock.js` | `frontend/README.md` documents the triggers. |
| Bad input and oversized requests | The form checks the same rules as the backend (1 to 2048 code points, no spaces, control or hidden characters, only http or https). It also checks the host: it must contain a dot, be a bracketed IPv6 literal (`[2001:db8::1]`) or be the single word `localhost` (any case), each with an optional port. The IPv6 check is a shortcut that only allows hex digits, colons and dots inside the brackets, not full IPv6 syntax. The backend does not apply the host check; it is the final authority and re-checks everything else. | `src/validation/urlRules.js` | `urlRules.test.js`. |
| Accidental request floods | The submit button is disabled while a request is running, and a 503 (`service_busy`) or 429 (`rate_limited`) shows the wait from `Retry-After`. This is a convenience, not a defence: a script can call the API directly, so rate limiting must live in the backend. | `UrlForm.jsx`, `ErrorState.jsx` | `HomePage.test.jsx` (loading, service_busy and rate_limited tests), `errors.test.js` (429 cases). |
| Timeouts and a dead backend | Requests time out after 30 seconds. No response, or a timeout, shows the "cannot be reached" state with a retry button. | `src/api/client.js` | `client.test.js` (no response and timeout cases). |

## 3. Not covered, and why

- **Security headers for the page itself.** The Vite dev server does not set a Content-Security-Policy, `X-Content-Type-Options` or frame protection for the frontend. In this project the frontend runs only as a local dev server or as a static build served on localhost, so we do not configure a production host. If it were deployed, the host should set a strict CSP (`default-src 'self'`, `connect-src` limited to the API origin) and `frame-ancestors 'none'`. The React code has no inline script that a strict CSP would break, but this has not been tested with one.
- **Rate limiting and denial of service.** Handled by the backend (body size limit, concurrency cap, and the planned per-client 429). The frontend only reacts: a `503` becomes `service_busy` and a `429` becomes `rate_limited`, with or without a valid error body, and both show the wait from `Retry-After` when it is a whole number of seconds above 0.
- **Authentication and authorisation.** There are no accounts, so none are implemented.
- **Browser extensions and a compromised machine.** Out of scope.
- **Accuracy of the model.** A wrong verdict is a model limitation, not a frontend vulnerability. The page labels the result as an estimate from the text of the link only.

## 4. How to re-check

Run from `frontend/`:

```sh
npm run lint          # oxlint with --deny-warnings
npm test              # includes the plain-text, error and validation tests above
npm audit             # expect 0 vulnerabilities
npm run build
```

Search `src/` (expect only the allowed results in brackets):

```sh
grep -rn "dangerouslySetInnerHTML\|innerHTML\|eval(" src          # expect none
grep -rn "window.open" src                                         # expect none
grep -rn "window.location" src                                     # expect 1: the error boundary's reload
grep -rn "localStorage\|sessionStorage\|document.cookie\|indexedDB\|caches" src   # expect none
grep -rn "href=" src --include=*.jsx                               # expect the skip link only (tests excluded)
```
