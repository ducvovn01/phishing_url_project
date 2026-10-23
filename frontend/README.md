# Frontend

React + Vite client for the COS30049 phishing URL detector (API: `../docs/api-contract.md`).
Needs Node 22.22.2+ on 22, 24.15.0+ on 24, or 26 and later (odd majors are not supported).
`npm run lint` runs oxlint with `--deny-warnings`; unlabelled form fields are caught by the Testing Library label queries in the tests, because no lint rule detects them.
Copy `.env.example` to `.env` and fill in the values before running.

```sh
npm ci          # install exact versions from package-lock.json
npm run dev     # dev server on http://localhost:5173
npm test        # run the Vitest suite once
npm run build   # production build into dist/
```

Mock triggers work only in mock mode (`VITE_USE_MOCK=true`); the real client ignores them.
Any URL containing a trigger (case-insensitive) gets that outcome. Use the dotted alias in the form, which needs a "." in the host.

| Trigger | Alias for the form | Simulates |
| --- | --- | --- |
| `mock-busy` | `busy.mock` | `service_busy` (503), retry after 5 seconds |
| `mock-error` | `error.mock` | `internal_error` (500) |
| `mock-offline` | `offline.mock` | `backend_unavailable` (no response) |
| `mock-invalid` | `invalid.mock` | `validation_error` (422) with a `url` detail |

## Charts

- The weight chart uses `@mui/x-charts`, pinned to an exact version in `package.json` (no `^` or `~`; `.npmrc` sets `save-exact=true`).
- `WeightChart` is loaded with `React.lazy`, so the chart code and `@mui/x-charts` sit in their own chunk, not in the main bundle.
- The bars show only the `weight` values returned by the API. Rule-based signals have no weight (`null`), so they are left out of the chart and listed in the signal list instead.
- "Show data as a table" below the chart shows the same data as an HTML table, for people who cannot use the chart.

## Session page

- Results are kept in memory only (React state), never in `localStorage`, `sessionStorage` or cookies. They are cleared when the tab is refreshed or closed, or with the "Clear session" button.
- The donut shows the share of phishing and legitimate verdicts; the bar chart shows the trust score for each check (the 12 most recent).
- Both charts have a "Show data as a table" button with the same data as an HTML table.
- The charts are loaded with `React.lazy`, so they stay out of the main bundle.
