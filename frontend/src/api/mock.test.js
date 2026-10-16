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

test('mock getHealth passes the client shape check', async () => {
  expect(isHealthResponse(await getHealth())).toBe(true)
})
