# Frontend

React + Vite client for the COS30049 phishing URL detector.
It talks to the backend described in `../docs/api-contract.md`.
Copy `.env.example` to `.env` and fill in the values before running.

```sh
npm ci          # install exact versions from package-lock.json
npm run dev     # dev server on http://localhost:5173
npm test        # run the Vitest suite once
npm run build   # production build into dist/
```
