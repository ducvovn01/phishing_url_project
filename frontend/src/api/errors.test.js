import { describe, expect, test } from 'vitest'
import { ApiError, DEFAULT_MESSAGES, normaliseError } from './errors.js'

const axiosError = (response, extra = {}) => ({ isAxiosError: true, message: 'raw axios text', response, ...extra })
const res = (status, data = '', headers = {}) => ({ status, data, headers })

function expectShape(e) {
  expect(e).toBeInstanceOf(ApiError)
  expect(typeof e.code).toBe('string')
  expect(typeof e.message).toBe('string')
  expect(Array.isArray(e.details)).toBe(true)
  expect(e.request_id === null || typeof e.request_id === 'string').toBe(true)
}

describe('normaliseError', () => {
  test('uses a valid contract error body', () => {
    const body = {
      error: {
        code: 'validation_error',
        message: "That doesn't look like a valid URL.",
        details: [{ field: 'url', message: 'Must be 1 to 2048 characters.' }, { bad: true }],
        request_id: '9f3c1a',
      },
    }
    const e = normaliseError(axiosError(res(422, body)))
    expectShape(e)
    expect(e.code).toBe('validation_error')
    expect(e.message).toBe("That doesn't look like a valid URL.")
    expect(e.details).toEqual([{ field: 'url', message: 'Must be 1 to 2048 characters.' }])
    expect(e.request_id).toBe('9f3c1a')
  })

  test('replaces a message over 300 characters with the safe default', () => {
    const body = { error: { code: 'internal_error', message: 'x'.repeat(301), details: [], request_id: 'a' } }
    const e = normaliseError(axiosError(res(500, body)))
    expect(e.message).toBe(DEFAULT_MESSAGES.internal_error)
  })

  test('accepts a message of exactly 300 characters', () => {
    const body = { error: { code: 'internal_error', message: 'y'.repeat(300), details: [], request_id: 'a' } }
    expect(normaliseError(axiosError(res(500, body))).message).toBe('y'.repeat(300))
  })

  test('replaces a non-string message with the default for its code', () => {
    const body = { error: { code: 'service_busy', message: { html: '<b>' }, request_id: 'c41b7e' } }
    const e = normaliseError(axiosError(res(503, body, { 'retry-after': '7' })))
    expect(e.code).toBe('service_busy')
    expect(e.message).toBe(DEFAULT_MESSAGES.service_busy)
    expect(e.details).toEqual([])
    expect(e.retryAfterSeconds).toBe(7)
  })

  test.each([
    [422, 'validation_error'],
    [413, 'payload_too_large'],
    [404, 'not_found'],
    [405, 'method_not_allowed'],
    [429, 'rate_limited'],
    [500, 'internal_error'],
    [418, 'internal_error'],
  ])('status %i without a valid body gives %s', (status, code) => {
    const e = normaliseError(axiosError(res(status, '<html>Traceback at /app/main.py</html>')))
    expectShape(e)
    expect(e.code).toBe(code)
    expect(e.message).toBe(DEFAULT_MESSAGES[code])
    expect(e.request_id).toBeNull()
  })

  test('503 without a valid body reads Retry-After', () => {
    const e = normaliseError(axiosError(res(503, null, { 'retry-after': '5' })))
    expect(e.code).toBe('service_busy')
    expect(e.retryAfterSeconds).toBe(5)
  })

  test('503 with an unreadable Retry-After gives null', () => {
    expect(normaliseError(axiosError(res(503, null, { 'retry-after': 'soon' }))).retryAfterSeconds).toBeNull()
  })

  test('429 with a valid body gives rate_limited and reads Retry-After', () => {
    const body = { error: { code: 'rate_limited', message: 'Too many requests. Please wait a moment and try again.', details: [], request_id: 'b7d2e019' } }
    const e = normaliseError(axiosError(res(429, body, { 'retry-after': '10' })))
    expectShape(e)
    expect(e).toMatchObject({ code: 'rate_limited', message: DEFAULT_MESSAGES.rate_limited, request_id: 'b7d2e019', retryAfterSeconds: 10 })
  })

  test('429 with no body is rate_limited, not internal_error', () => {
    const e = normaliseError(axiosError(res(429, '', { 'retry-after': '10' })))
    expect(e).toMatchObject({ code: 'rate_limited', message: DEFAULT_MESSAGES.rate_limited, request_id: null, retryAfterSeconds: 10 })
  })

  test.each([
    [503, '1', 1],
    [503, '10', 10],
    [429, '1', 1],
    [429, '10', 10],
    [429, 'soon', null],
    [429, '1.5', null],
    [429, undefined, null],
  ])('status %i with Retry-After %j gives retryAfterSeconds %j, with and without a body', (status, header, seconds) => {
    const headers = header === undefined ? {} : { 'retry-after': header }
    const body = { error: { code: status === 429 ? 'rate_limited' : 'service_busy', message: 'm', details: [], request_id: 'a' } }
    expect(normaliseError(axiosError(res(status, body, headers))).retryAfterSeconds).toBe(seconds)
    expect(normaliseError(axiosError(res(status, null, headers))).retryAfterSeconds).toBe(seconds)
  })

  test('network error with no response is backend_unavailable', () => {
    const e = normaliseError(axiosError(undefined, { code: 'ERR_NETWORK' }))
    expectShape(e)
    expect(e.code).toBe('backend_unavailable')
    expect(e.message).toBe(DEFAULT_MESSAGES.backend_unavailable)
  })

  test('timeout with no response is backend_unavailable', () => {
    expect(normaliseError(axiosError(undefined, { code: 'ECONNABORTED' })).code).toBe('backend_unavailable')
  })

  test.each([new Error('boom at /src/secret.js:12'), 'a string', null, undefined, { weird: 1 }])(
    'anything else (%s) is a generic internal_error',
    (thrown) => {
      const e = normaliseError(thrown)
      expectShape(e)
      expect(e.code).toBe('internal_error')
      expect(e.message).toBe(DEFAULT_MESSAGES.internal_error)
      expect(e.message).not.toMatch(/boom|secret/)
    },
  )

  test('returns an ApiError unchanged', () => {
    const original = new ApiError('service_busy', { retryAfterSeconds: 5 })
    expect(normaliseError(original)).toBe(original)
  })
})
