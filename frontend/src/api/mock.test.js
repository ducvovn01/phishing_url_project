import { describe, expect, test } from 'vitest'
import { isAnalysisResponse, isHealthResponse } from './client.js'
import { analyseUrl, getHealth } from './mock.js'

const URLS = [
  'paypa1-secure-login.top/verify', // contract example 3.2
  'https://www.wikipedia.org/wiki/Phishing', // contract example 3.5
  'HTTP://Example.COM',
  'secure-login-verify.xyz/account/login',
  'localhost',
  'https://😀login.top/verify',
]

// The mock waits 700 ms per call, so run every URL at once.
const responses = Promise.all(URLS.map((u) => analyseUrl(u)))

describe('mock analyseUrl', () => {
  test('every response passes the client shape check and contract rules', async () => {
    for (const r of await responses) {
      expect(isAnalysisResponse(r), r.submitted_url).toBe(true)
      expect(r.label).toBe(r.phishing_probability >= r.threshold ? 'phishing' : 'legitimate')
      expect(r.confidence).toBeCloseTo(r.label === 'phishing' ? r.phishing_probability : 1 - r.phishing_probability)
      expect(r.trust_score).toBe(Math.round(100 * (1 - r.phishing_probability)))
    }
  })

  test('matches the contract examples in label, analysed_url and signal positions', async () => {
    const [phish, wiki] = await responses
    expect(phish.label).toBe('phishing')
    expect(phish.analysed_url).toBe('paypa1-secure-login.top/verify')
    expect(phish.signals[0]).toMatchObject({ text: '.top', start: 19, end: 23, direction: 'phishing' })

    expect(wiki.label).toBe('legitimate')
    expect(wiki.analysed_url).toBe('www.wikipedia.org/wiki/phishing')
    expect(wiki.signals.map(({ text, start, end }) => [text, start, end])).toEqual([
      ['www.', 0, 4],
      ['.org', 13, 17],
    ])
  })

  test('cutting analysed_url by code point at start:end gives the signal text', async () => {
    const all = await responses
    for (const r of all) {
      const codePoints = Array.from(r.analysed_url)
      for (const s of r.signals) {
        expect(codePoints.slice(s.start, s.end).join('')).toBe(s.text)
      }
    }
    // With the emoji, code-point and UTF-16 offsets differ, so this proves code points are used.
    const emoji = all.at(-1)
    expect(emoji.analysed_url).toBe('😀login.top/verify')
    expect(emoji.signals.find((s) => s.text === 'login')).toMatchObject({ start: 1, end: 6 })
  })

  test.each([
    ['https://mock-busy.test', { code: 'service_busy', retryAfterSeconds: 5 }],
    ['https://mock-error.test', { code: 'internal_error' }],
    ['https://mock-offline.test', { code: 'backend_unavailable' }],
  ])('%s fails with %o', async (url, expected) => {
    await expect(analyseUrl(url)).rejects.toMatchObject({ ...expected, details: [] })
  })

  test('the shape check rejects a response missing a required field', async () => {
    const { model, ...rest } = (await responses)[0]
    expect(model).toBeDefined()
    expect(isAnalysisResponse(rest)).toBe(false)
  })
})

describe('mock rule signals', () => {
  const ruleOf = (r, id) => r.signals.find((s) => s.id === id)

  test.each([
    ['http://192.168.0.1/login', 'rule-ip-host', { start: 0, end: 11, text: '192.168.0.1' }],
    ['xn--pypal-4ve.com/secure', 'rule-punycode', { start: 0, end: 13, text: 'xn--pypal-4ve' }],
    ['https://www.xn--80ak6aa92e.com/', 'rule-punycode', { start: 4, end: 18, text: 'xn--80ak6aa92e' }],
    ['example.com/' + 'a'.repeat(64), 'rule-long-url', { start: null, end: null, text: null }],
  ])('%s gets %s', async (url, id, position) => {
    const r = await analyseUrl(url)
    expect(isAnalysisResponse(r)).toBe(true)
    expect(ruleOf(r, id)).toMatchObject({ kind: 'rule', weight: null, direction: 'phishing', ...position })
    if (position.start !== null) {
      expect(Array.from(r.analysed_url).slice(position.start, position.end).join('')).toBe(position.text)
    }
  })

  test('no rules for a normal host or a URL of exactly 75 code points', async () => {
    const r = await analyseUrl('example.com/' + 'a'.repeat(63))
    expect(Array.from(r.analysed_url)).toHaveLength(75)
    expect(r.signals.filter((s) => s.kind === 'rule')).toEqual([])
  })

  test('rules come after ngrams and the total stays at most 10', async () => {
    const r = await analyseUrl('xn--abc.top/www./login/verify/secure/.xyz/.org/.com/' + 'a'.repeat(40))
    expect(isAnalysisResponse(r)).toBe(true)
    expect(r.signals).toHaveLength(10)
    const kinds = r.signals.map((s) => s.kind)
    expect(kinds.lastIndexOf('ngram')).toBeLessThan(kinds.indexOf('rule'))
    expect(kinds.filter((k) => k === 'rule')).toHaveLength(2)
  })
})

test('mock-invalid fails with validation_error, details and a request_id', async () => {
  await expect(analyseUrl('https://mock-invalid.test')).rejects.toMatchObject({
    code: 'validation_error',
    details: [{ field: 'url', message: 'The mock says this URL is invalid.' }],
    request_id: 'mock',
  })
})

test('mock getHealth passes the client shape check', async () => {
  expect(isHealthResponse(await getHealth())).toBe(true)
})
