// MOCK DATA ONLY. This is NOT the model and NOT a real phishing check.
// It fakes the backend from ../docs/api-contract.md with simple substring rules so the
// UI can be built before the real API is ready. Its scores mean nothing.
import { ApiError } from './errors.js'

const DELAY_MS = 700
const MAX_SIGNALS = 10
const THRESHOLD = 0.5

const PATTERNS = [
  { text: '.top', direction: 'phishing', weight: 37.1 },
  { text: '.xyz', direction: 'phishing', weight: 33.8 },
  { text: 'login', direction: 'phishing', weight: 24.5 },
  { text: 'verify', direction: 'phishing', weight: 21.2 },
  { text: 'secure', direction: 'phishing', weight: 18.9 },
  { text: 'www.', direction: 'legitimate', weight: -29.4 },
  { text: '.org', direction: 'legitimate', weight: -16.6 },
  { text: '.com', direction: 'legitimate', weight: -9.3 },
]

const COPY = {
  phishing: {
    title: 'Pattern linked to phishing',
    explanation: 'URLs containing this pattern were mostly phishing in the training data.',
  },
  legitimate: {
    title: 'Pattern linked to legitimate sites',
    explanation: 'URLs containing this pattern were mostly legitimate in the training data.',
  },
}

const wait = () => new Promise((resolve) => setTimeout(resolve, DELAY_MS))
const round2 = (n) => Math.round(n * 100) / 100

/** Index of the first match of needle in the code-point array, or -1. */
function codePointIndexOf(codePoints, needle) {
  const n = Array.from(needle)
  for (let i = 0; i + n.length <= codePoints.length; i++) {
    if (n.every((c, j) => codePoints[i + j] === c)) return i
  }
  return -1
}

function buildResponse(url) {
  const submitted = url.trim()
  const analysed = submitted.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').toLowerCase()
  const codePoints = Array.from(analysed)

  const signals = PATTERNS.flatMap((p) => {
    const start = codePointIndexOf(codePoints, p.text)
    if (start === -1) return []
    const end = start + Array.from(p.text).length
    return [{ ...p, start, end }]
  })
    .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
    .slice(0, MAX_SIGNALS)
    .map((s, i) => ({
      id: `ngram-${i + 1}`,
      kind: 'ngram',
      title: COPY[s.direction].title,
      direction: s.direction,
      weight: s.weight,
      start: s.start,
      end: s.end,
      text: codePoints.slice(s.start, s.end).join(''),
      explanation: COPY[s.direction].explanation,
    }))

  const phishingHits = signals.filter((s) => s.direction === 'phishing').length
  const legitimateHits = signals.length - phishingHits
  const probability = round2(Math.min(0.97, Math.max(0.03, 0.15 + 0.2 * phishingHits - 0.05 * legitimateHits)))
  const label = probability >= THRESHOLD ? 'phishing' : 'legitimate'

  return {
    submitted_url: submitted,
    analysed_url: analysed,
    label,
    confidence: label === 'phishing' ? probability : round2(1 - probability),
    phishing_probability: probability,
    trust_score: Math.round(100 * (1 - probability)),
    threshold: THRESHOLD,
    signals,
    model: { name: 'char_ngram_logreg', version: 'mock' },
  }
}

/** @returns {Promise<import('./types.js').AnalysisResponse>} */
export async function analyseUrl(url) {
  await wait()
  if (url.includes('mock-busy')) throw new ApiError('service_busy', { request_id: 'mock', retryAfterSeconds: 5 })
  if (url.includes('mock-error')) throw new ApiError('internal_error', { request_id: 'mock' })
  if (url.includes('mock-offline')) throw new ApiError('backend_unavailable')
  return buildResponse(url)
}

/** @returns {Promise<import('./types.js').HealthResponse>} */
export async function getHealth() {
  await wait()
  return { status: 'ok', model_loaded: true }
}
