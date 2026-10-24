import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { analyseUrl, api, getHealth } from './client.js'
import { ApiError, DEFAULT_MESSAGES } from './errors.js'

const VALID = {
  submitted_url: 'paypa1-secure-login.top/verify',
  analysed_url: 'paypa1-secure-login.top/verify',
  label: 'phishing',
  confidence: 0.93,
  phishing_probability: 0.93,
  trust_score: 7,
  threshold: 0.5,
  signals: [
    {
      id: 'ngram-1',
      kind: 'ngram',
      title: 'Pattern linked to phishing',
      direction: 'phishing',
      weight: 37.1,
      start: 19,
      end: 23,
      text: '.top',
      explanation: 'URLs containing this pattern were mostly phishing in the training data.',
    },
    {
      id: 'rule-unusual-tld',
      kind: 'rule',
      title: 'Unusual top-level domain',
      direction: 'phishing',
      weight: null,
      start: 20,
      end: 23,
      text: 'top',
      explanation: 'This ending is far more common in phishing links than in legitimate ones.',
    },
  ],
  model: { name: 'char_ngram_logreg', version: 'a2-final' },
}

// The stub replaces the network layer. Real adapters reject non-2xx responses with an
// AxiosError, so the stub rejects with the same shape (isAxiosError, response, code).
let adapter
const originalAdapter = api.defaults.adapter
beforeEach(() => {
  adapter = vi.fn()
  api.defaults.adapter = adapter
})
afterEach(() => {
  api.defaults.adapter = originalAdapter
})

const reply = (status, data, headers = {}) =>
  adapter.mockImplementation(async (config) => {
    const response = { data, status, statusText: '', headers, config, request: {} }
    if (status >= 200 && status < 300) return response
    throw Object.assign(new Error('Request failed with status code ' + status), {
      isAxiosError: true,
      config,
      response,
    })
  })

const failWithoutResponse = (code) =>
  adapter.mockImplementation(async (config) => {
    throw Object.assign(new Error('raw low-level text'), { isAxiosError: true, code, config, request: {} })
  })

describe('analyseUrl', () => {
  test('returns a valid 200 response and POSTs { url } to /analyze', async () => {
    reply(200, VALID)
    await expect(analyseUrl('paypa1-secure-login.top/verify')).resolves.toEqual(VALID)
    const config = adapter.mock.calls[0][0]
    expect(config.method).toBe('post')
    expect(config.url).toBe('/analyze')
    expect(JSON.parse(config.data)).toEqual({ url: 'paypa1-secure-login.top/verify' })
    expect(config.timeout).toBe(30000)
  })

  test('422 in the contract shape becomes validation_error with details kept', async () => {
    const details = [{ field: 'url', message: 'Must be 1 to 2048 characters.' }]
    reply(422, { error: { code: 'validation_error', message: "That doesn't look like a valid URL.", details, request_id: '9f3c1a' } })
    const err = await analyseUrl('').catch((e) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ code: 'validation_error', message: "That doesn't look like a valid URL.", details, request_id: '9f3c1a' })
  })

  test('503 with Retry-After gives service_busy and retryAfterSeconds', async () => {
    reply(503, { error: { code: 'service_busy', message: 'The service is busy. Please try again in a moment.', details: [], request_id: 'c41b7e' } }, { 'retry-after': '5' })
    await expect(analyseUrl('a.com')).rejects.toMatchObject({ code: 'service_busy', retryAfterSeconds: 5, request_id: 'c41b7e' })
  })

  test('no response at all gives backend_unavailable', async () => {
    failWithoutResponse('ERR_NETWORK')
    const err = await analyseUrl('a.com').catch((e) => e)
    expect(err).toMatchObject({ code: 'backend_unavailable', message: DEFAULT_MESSAGES.backend_unavailable })
    expect(err.message).not.toContain('raw low-level text')
  })

  test('a timeout gives backend_unavailable', async () => {
    failWithoutResponse('ECONNABORTED')
    await expect(analyseUrl('a.com')).rejects.toMatchObject({ code: 'backend_unavailable' })
  })

  test('a 200 with a malformed body becomes internal_error', async () => {
    const { trust_score, ...missingField } = VALID
    expect(trust_score).toBe(7)
    reply(200, missingField)
    await expect(analyseUrl('a.com')).rejects.toMatchObject({ code: 'internal_error', message: DEFAULT_MESSAGES.internal_error })
  })

  test('a 200 with duplicate signal ids becomes internal_error', async () => {
    reply(200, { ...VALID, signals: [VALID.signals[0], { ...VALID.signals[1], id: VALID.signals[0].id }] })
    await expect(analyseUrl('a.com')).rejects.toMatchObject({ code: 'internal_error', message: DEFAULT_MESSAGES.internal_error })
  })

  test('an error body with an unknown code is kept as is', async () => {
    reply(500, { error: { code: 'model_on_fire', message: 'The model is resting.', details: [], request_id: 'zz1' } })
    await expect(analyseUrl('a.com')).rejects.toMatchObject({ code: 'model_on_fire', message: 'The model is resting.', request_id: 'zz1' })
  })

  test('a non-JSON error body becomes internal_error with the default message', async () => {
    reply(500, '<html><body>Traceback (most recent call last): /app/main.py</body></html>')
    const err = await analyseUrl('a.com').catch((e) => e)
    expect(err).toMatchObject({ code: 'internal_error', message: DEFAULT_MESSAGES.internal_error, details: [], request_id: null })
  })
})

describe('getHealth', () => {
  test('returns a valid health body from GET /health', async () => {
    reply(200, { status: 'ok', model_loaded: true })
    await expect(getHealth()).resolves.toEqual({ status: 'ok', model_loaded: true })
    expect(adapter.mock.calls[0][0]).toMatchObject({ method: 'get', url: '/health' })
  })

  test('a malformed health body becomes internal_error', async () => {
    reply(200, { status: 'ok' })
    await expect(getHealth()).rejects.toMatchObject({ code: 'internal_error' })
  })
})
