import { describe, expect, test } from 'vitest'
import { segmentUrl } from './segmentUrl.js'

const sig = (id, start, end, weight, direction = 'phishing') => ({ id, start, end, weight, direction })
const plain = (text) => ({ text, signalId: null, direction: null })

describe('segmentUrl', () => {
  test('no signals gives one plain piece', () => {
    expect(segmentUrl('example.com', [])).toEqual([plain('example.com')])
    expect(segmentUrl('example.com')).toEqual([plain('example.com')])
  })

  test('empty string gives no pieces', () => {
    expect(segmentUrl('', [sig('a', 0, 1, 1)])).toEqual([])
  })

  test('the contract example cuts .top out', () => {
    expect(segmentUrl('paypa1-secure-login.top/verify', [sig('ngram-1', 19, 23, 37.1)])).toEqual([
      plain('paypa1-secure-login'),
      { text: '.top', signalId: 'ngram-1', direction: 'phishing' },
      plain('/verify'),
    ])
  })

  test('overlaps go to the largest absolute weight, whatever its sign', () => {
    const pieces = segmentUrl('abcdef', [sig('small', 0, 4, 5), sig('big', 2, 6, -9, 'legitimate')])
    expect(pieces).toEqual([
      { text: 'ab', signalId: 'small', direction: 'phishing' },
      { text: 'cdef', signalId: 'big', direction: 'legitimate' },
    ])
  })

  test('rules (null weight) rank below ngrams, and ties go to the earlier signal', () => {
    expect(segmentUrl('abcd', [sig('rule', 0, 4, null), sig('ngram', 1, 3, 0.1)]).map((p) => p.signalId)).toEqual([
      'rule',
      'ngram',
      'rule',
    ])
    expect(segmentUrl('abcd', [sig('first', 0, 4, 3), sig('second', 0, 4, -3)])).toEqual([
      { text: 'abcd', signalId: 'first', direction: 'phishing' },
    ])
    expect(segmentUrl('abcd', [sig('r1', 0, 4, null), sig('r2', 0, 4, null)])[0].signalId).toBe('r1')
  })

  test('cuts by code point, so an emoji counts as one', () => {
    expect(segmentUrl('😀login.top', [sig('login', 1, 6, 2)])).toEqual([
      plain('😀'),
      { text: 'login', signalId: 'login', direction: 'phishing' },
      plain('.top'),
    ])
  })

  test('rule signals with null positions are ignored', () => {
    expect(segmentUrl('example.com', [{ ...sig('rule-long-url', null, null, null), text: null }])).toEqual([
      plain('example.com'),
    ])
  })

  test.each([
    ['start equal to end', sig('x', 2, 2, 1)],
    ['start after end', sig('x', 4, 2, 1)],
    ['negative start', sig('x', -1, 2, 1)],
    ['end past the string', sig('x', 2, 99, 1)],
    ['non-integer start', sig('x', 1.5, 3, 1)],
    ['string positions', sig('x', '1', '3', 1)],
  ])('ignores an invalid range (%s) without throwing', (_, bad) => {
    expect(segmentUrl('abcdef', [bad])).toEqual([plain('abcdef')])
  })

  test('neighbouring pieces with the same signal are merged; different signals are not', () => {
    expect(segmentUrl('abcdef', [sig('a', 0, 2, 1), sig('a2', 2, 4, 1)]).map((p) => p.text)).toEqual(['ab', 'cd', 'ef'])
    // "big" outranks "small" everywhere, so its code points form one merged piece, not three.
    expect(segmentUrl('abcdef', [sig('big', 0, 6, 9), sig('small', 2, 4, 1)])).toEqual([
      { text: 'abcdef', signalId: 'big', direction: 'phishing' },
    ])
  })

  test('pieces always rebuild the whole string', () => {
    const url = 'https😀://xn--a.top/login?x=1'
    const signals = [sig('a', 0, 5, 1), sig('b', 3, 12, -4), sig('c', 20, 25, null), sig('bad', 30, 40, 9)]
    expect(segmentUrl(url, signals).map((p) => p.text).join('')).toBe(url)
  })
})
