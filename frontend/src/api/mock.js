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

const LONG_URL_CODE_POINTS = 75

const rule = (id, title, explanation, codePoints, start, end) => ({
  id,
  kind: 'rule',
  title,
  direction: 'phishing',
  weight: null,
  start,
  end,
  text: start === null ? null : codePoints.slice(start, end).join(''),
  explanation,
})

/** Rule signals from the host (the text before the first "/", "?" or "#") and the length. */
function ruleSignals(codePoints) {
  const signals = []
  const hostEnd = codePoints.findIndex((c) => c === '/' || c === '?' || c === '#')
  const host = codePoints.slice(0, hostEnd === -1 ? codePoints.length : hostEnd)

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host.join(''))) {
    signals.push(
      rule('rule-ip-host', 'IP address instead of a name', 'Legitimate sites almost always use a name, not a bare number address.', codePoints, 0, host.length),
    )
  }

  let labelStart = 0
  for (const label of host.join('').split('.')) {
    const length = Array.from(label).length
    if (label.startsWith('xn--')) {
      signals.push(
        rule('rule-punycode', 'Encoded international name', 'This part of the address is encoded, which can hide look-alike letters.', codePoints, labelStart, labelStart + length),
      )
      break
    }
    labelStart += length + 1
  }

  if (codePoints.length > LONG_URL_CODE_POINTS) {
    signals.push(
      rule('rule-long-url', 'Very long URL', 'Very long links are more common in phishing than in legitimate sites.', codePoints, null, null),
    )
  }
  return signals
}

function buildResponse(url) {
  const submitted = url.trim()
  const analysed = submitted.replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').toLowerCase()
  const codePoints = Array.from(analysed)

  const ngrams = PATTERNS.flatMap((p) => {
    const start = codePointIndexOf(codePoints, p.text)
    if (start === -1) return []
    const end = start + Array.from(p.text).length
    return [{ ...p, start, end }]
  })
    .sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
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

  // Contract ordering: ngram signals first, rule signals after, at most 10 in total.
  const signals = [...ngrams, ...ruleSignals(codePoints)].slice(0, MAX_SIGNALS)

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
  if (url.includes('mock-invalid')) {
    throw new ApiError('validation_error', {
      details: [{ field: 'url', message: 'The mock says this URL is invalid.' }],
      request_id: 'mock',
    })
  }
  return buildResponse(url)
}

/** @returns {Promise<import('./types.js').HealthResponse>} */
export async function getHealth() {
  await wait()
  return { status: 'ok', model_loaded: true }
}
