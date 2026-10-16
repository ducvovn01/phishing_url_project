// The only file allowed to import axios.
import axios from 'axios'
import { ApiError, normaliseError } from './errors.js'

const DEV_BASE_URL = 'http://localhost:8000'
const MAX_SIGNALS = 10

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || DEV_BASE_URL,
  timeout: 30000,
})

const isString = (v) => typeof v === 'string'
const isUnit = (v) => typeof v === 'number' && v >= 0 && v <= 1
const isIntOrNull = (v) => v === null || Number.isInteger(v)
const isOneOf = (v, options) => options.includes(v)

function isSignal(s) {
  return (
    s !== null &&
    typeof s === 'object' &&
    isString(s.id) &&
    isOneOf(s.kind, ['ngram', 'rule']) &&
    isString(s.title) &&
    isOneOf(s.direction, ['phishing', 'legitimate']) &&
    (s.weight === null || typeof s.weight === 'number') &&
    isIntOrNull(s.start) &&
    isIntOrNull(s.end) &&
    (s.text === null || isString(s.text)) &&
    isString(s.explanation)
  )
}

/** True when data has every field of the /analyze 200 response with the contract's types. */
export function isAnalysisResponse(data) {
  return (
    data !== null &&
    typeof data === 'object' &&
    isString(data.submitted_url) &&
    isString(data.analysed_url) &&
    isOneOf(data.label, ['phishing', 'legitimate']) &&
    isUnit(data.confidence) &&
    isUnit(data.phishing_probability) &&
    Number.isInteger(data.trust_score) &&
    data.trust_score >= 0 &&
    data.trust_score <= 100 &&
    isUnit(data.threshold) &&
    Array.isArray(data.signals) &&
    data.signals.length <= MAX_SIGNALS &&
    data.signals.every(isSignal) &&
    isString(data.model?.name) &&
    isString(data.model?.version)
  )
}

/** True when data matches the /health 200 response. */
export function isHealthResponse(data) {
  return data !== null && typeof data === 'object' && isString(data.status) && typeof data.model_loaded === 'boolean'
}

async function request(config, isValid) {
  try {
    const { data } = await api.request(config)
    if (!isValid(data)) throw new ApiError('internal_error')
    return data
  } catch (err) {
    throw normaliseError(err)
  }
}

/** @returns {Promise<import('./types.js').AnalysisResponse>} */
export function analyseUrl(url) {
  return request({ method: 'post', url: '/analyze', data: { url } }, isAnalysisResponse)
}

/** @returns {Promise<import('./types.js').HealthResponse>} */
export function getHealth() {
  return request({ method: 'get', url: '/health' }, isHealthResponse)
}
