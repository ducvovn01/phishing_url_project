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
