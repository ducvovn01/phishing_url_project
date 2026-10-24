import { describe, expect, test } from 'vitest'
import { markSelected, segmentUrl } from './segmentUrl.js'

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

describe('markSelected', () => {
  // Contract example: the ngram ".top" (19-23) owns "top", which the rule "top" (20-23) also covers.
  const url = 'paypa1-secure-login.top/verify'
  const ngram = sig('ngram-1', 19, 23, 37.1)
  const rule = sig('rule-unusual-tld', 20, 23, null)
  const pieces = segmentUrl(url, [ngram, rule])

  test('nothing selected: the pieces are returned exactly as segmentUrl made them', () => {
    expect(markSelected(pieces, undefined)).toBe(pieces)
    expect(markSelected(pieces, null)).toBe(pieces)
  })

  test('a selected rule under an ngram emphasises its own range, keeping the ngram as owner', () => {
    expect(markSelected(pieces, rule)).toEqual([
      { ...plain('paypa1-secure-login'), selected: false },
      { text: '.', signalId: 'ngram-1', direction: 'phishing', selected: false },
      { text: 'top', signalId: 'ngram-1', direction: 'phishing', selected: true },
      { ...plain('/verify'), selected: false },
    ])
  })

  test('selecting the owning ngram emphasises the same characters as before', () => {
    const marked = markSelected(pieces, ngram)
    expect(marked.filter((p) => p.selected).map((p) => [p.text, p.signalId])).toEqual([['.top', 'ngram-1']])
    expect(marked.map((p) => p.text).join('')).toBe(url)
  })

  test('a lighter ngram under a heavier one emphasises its whole range, across owners', () => {
    const big = sig('big', 2, 5, 9)
    const small = sig('small', 0, 4, -1, 'legitimate')
    expect(markSelected(segmentUrl('abcdef', [big, small]), small)).toEqual([
      { text: 'ab', signalId: 'small', direction: 'legitimate', selected: true },
      { text: 'cd', signalId: 'big', direction: 'phishing', selected: true },
      { text: 'e', signalId: 'big', direction: 'phishing', selected: false },
      { ...plain('f'), selected: false },
    ])
  })

  test.each([
    ['missing range', { id: 'x' }],
    ['null range', sig('x', null, null, null)],
    ['non-integer', sig('x', 1.5, 3, 1)],
    ['string offsets', sig('x', '1', '3', 1)],
    ['out of bounds', sig('x', 2, 99, 1)],
    ['negative start', sig('x', -1, 2, 1)],
    ['empty range', sig('x', 3, 3, 1)],
  ])('ignores an invalid range (%s) without throwing', (_, bad) => {
    expect(markSelected(pieces, bad)).toBe(pieces)
  })

  test('offsets are code points, so an emoji does not shift the range', () => {
    const emojiUrl = '😀😀login.top'
    const rule2 = sig('rule', 8, 11, null) // "top"
    const marked = markSelected(segmentUrl(emojiUrl, [sig('n', 2, 7, 3), rule2]), rule2)
    expect(marked.filter((p) => p.selected).map((p) => p.text)).toEqual(['top'])
    expect(marked.map((p) => p.text).join('')).toBe(emojiUrl)
  })
})
