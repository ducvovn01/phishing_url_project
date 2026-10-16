// JSDoc types for the API, matching ../docs/api-contract.md (v1). Types only; nothing runs here.

/**
 * POST /analyze request body.
 * @typedef {object} AnalyseRequest
 * @property {string} url Trimmed, 1 to 2048 characters, scheme optional.
 */

/**
 * @typedef {object} Signal
 * @property {string} id Stable within one response.
 * @property {'ngram' | 'rule'} kind
 * @property {string} title
 * @property {'phishing' | 'legitimate'} direction
 * @property {number | null} weight Log-odds contribution; null for rules.
 * @property {number | null} start Inclusive, in Unicode code points of analysed_url.
 * @property {number | null} end Exclusive, in Unicode code points of analysed_url.
 * @property {string | null} text The substring at start:end.
 * @property {string} explanation Plain text, never HTML.
 */

/**
 * POST /analyze 200 response.
 * @typedef {object} AnalysisResponse
 * @property {string} submitted_url
 * @property {string} analysed_url Scheme removed and lowercased.
 * @property {'phishing' | 'legitimate'} label
 * @property {number} confidence 0 to 1.
 * @property {number} phishing_probability 0 to 1.
 * @property {number} trust_score Integer 0 to 100.
 * @property {number} threshold 0 to 1.
 * @property {Signal[]} signals 0 to 10 items.
 * @property {{ name: string, version: string }} model
 */

/**
 * GET /health 200 response.
 * @typedef {object} HealthResponse
 * @property {string} status
 * @property {boolean} model_loaded
 */

/**
 * The contract error object (the value of the `error` key). The frontend adds the
 * client-only code "backend_unavailable" and, for 503, retryAfterSeconds.
 * @typedef {object} ApiErrorShape
 * @property {string} code
 * @property {string} message Safe to show to the user.
 * @property {{ field: string, message: string }[]} details
 * @property {string | null} request_id null when the error never reached the backend.
 * @property {number | null} [retryAfterSeconds]
 */

export {}
