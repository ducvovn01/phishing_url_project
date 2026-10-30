import { expect, test } from 'vitest'
import { formatConfidence } from './formatConfidence.js'

test.each([
  [0, '0%'],
  [0.5, '50%'],
  [0.874, '87%'],
  [0.994, '99%'],
  [0.995, 'Over 99%'],
  [0.9999999990, 'Over 99%'], // a real backend value
  [1, 'Over 99%'],
])('formatConfidence(%s) is %s', (input, expected) => {
  expect(formatConfidence(input)).toBe(expected)
})

test.each([NaN, null, undefined, 2, -1, Infinity, '0.9'])('bad input %s gives 0%% and does not throw', (input) => {
  expect(formatConfidence(input)).toBe('0%')
})
