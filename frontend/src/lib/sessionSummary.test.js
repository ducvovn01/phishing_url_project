import { describe, expect, test } from 'vitest'
import { summariseSession } from './sessionSummary.js'

const at = new Date('2026-10-23T10:00:00Z')
const entry = (id, label, analysed = 'example.com/path', extra = {}) => ({
  id,
  checkedAt: at,
  result: {
    submitted_url: `https://${analysed}`,
    analysed_url: analysed,
    label,
    confidence: 0.9,
    trust_score: label === 'phishing' ? 7 : 93,
    ...extra,
  },
})
const EMPTY = { total: 0, phishingCount: 0, legitimateCount: 0, phishingPercent: 0, legitimatePercent: 0, rows: [] }

describe('summariseSession', () => {
  test('empty list', () => {
    expect(summariseSession([])).toEqual(EMPTY)
  })

  test('one entry', () => {
    expect(summariseSession([entry(1, 'phishing', 'paypa1-secure-login.top/verify')])).toEqual({
      total: 1,
      phishingCount: 1,
      legitimateCount: 0,
      phishingPercent: 100,
      legitimatePercent: 0,
      rows: [
        {
          id: 1,
          number: 1,
          label: 'paypa1-secure-login....',
          fullLabel: 'https://paypa1-secure-login.top/verify',
          trustScore: 7,
          verdict: 'phishing',
          confidence: 0.9,
          checkedAt: at,
        },
      ],
    })
  })

  test('mixed verdicts are counted', () => {
    const s = summariseSession([entry(1, 'phishing'), entry(2, 'legitimate'), entry(3, 'phishing'), entry(4, 'legitimate')])
    expect(s).toMatchObject({ total: 4, phishingCount: 2, legitimateCount: 2, phishingPercent: 50, legitimatePercent: 50 })
  })

  test('percentages are whole numbers that add up to 100 (largest remainder)', () => {
    const run = (phishing, legitimate) => {
      const list = [...Array(phishing)].map((_, i) => entry(i, 'phishing'))
      list.push(...[...Array(legitimate)].map((_, i) => entry(100 + i, 'legitimate')))
      const s = summariseSession(list)
      return [s.phishingPercent, s.legitimatePercent]
    }
    expect(run(1, 2)).toEqual([33, 67])
    expect(run(2, 1)).toEqual([67, 33])
    expect(run(1, 7)).toEqual([13, 87]) // 12.5 / 87.5: the tie goes to phishing
    expect(run(0, 3)).toEqual([0, 100])
    for (let p = 0; p <= 13; p++) {
      for (let l = 0; l <= 13; l++) {
        if (p + l === 0) continue
        const [a, b] = run(p, l)
        expect(Number.isInteger(a) && Number.isInteger(b), `${p}/${l}`).toBe(true)
        expect(a + b, `${p}/${l}`).toBe(100)
      }
    }
  })

  test('label is the host, ending at the first "/", "?" or "#"', () => {
    const label = (analysed) => summariseSession([entry(1, 'legitimate', analysed)]).rows[0].label
    expect(label('example.com/a?b#c')).toBe('example.com')
    expect(label('example.com?x=/y')).toBe('example.com')
    expect(label('example.com#frag/x')).toBe('example.com')
    expect(label('example.com')).toBe('example.com')
  })

  test('label is cut by code point, so emoji are never split; fullLabel keeps the submitted URL', () => {
    const host = '😀'.repeat(25) + '.com'
    const [row] = summariseSession([entry(1, 'phishing', `${host}/x`)]).rows
    expect(row.label).toBe('😀'.repeat(20) + '...')
    expect(row.fullLabel).toBe(`https://${host}/x`)
    expect(summariseSession([entry(1, 'phishing', '😀'.repeat(20))]).rows[0].label).toBe('😀'.repeat(20))
  })

  test('order is preserved (oldest first) and numbers are 1-based', () => {
    const { rows } = summariseSession([entry(5, 'legitimate', 'a.com'), entry(2, 'phishing', 'b.com'), entry(9, 'legitimate', 'c.com')])
    expect(rows.map((r) => [r.number, r.id, r.label])).toEqual([
      [1, 5, 'a.com'],
      [2, 2, 'b.com'],
      [3, 9, 'c.com'],
    ])
  })

  test('odd input never throws and unusable entries are skipped', () => {
    for (const bad of [undefined, null, 'x', 42, {}]) expect(summariseSession(bad)).toEqual(EMPTY)
    const s = summariseSession([null, undefined, 7, {}, { id: 1 }, { id: 2, result: null }, { id: 3, result: { label: 'maybe' } }, entry(4, 'legitimate')])
    expect(s).toMatchObject({ total: 1, legitimateCount: 1, legitimatePercent: 100 })
    expect(s.rows[0]).toMatchObject({ id: 4, number: 1 })
    expect(summariseSession([{ id: 1, result: { label: 'phishing' } }]).rows[0]).toMatchObject({ label: '', fullLabel: undefined })
  })
})
