import { describe, expect, test } from 'vitest'
import { MAX_URL_LENGTH, validateUrl } from './urlRules.js'

const EMPTY = 'Paste or type a URL to check.'
const TOO_LONG = 'That URL is too long. The limit is 2048 characters.'
const SPACES = "A URL can't contain spaces. Check that you pasted only one link."
const CONTROL = "That URL contains characters that aren't allowed. Try copying it again."
const NOT_URL = "That doesn't look like a valid URL. Check it for typos, for example example.com/page."

const urlOfLength = (n) => 'a.com/' + 'x'.repeat(n - 6)

describe('validateUrl', () => {
  test('MAX_URL_LENGTH is the contract limit', () => {
    expect(MAX_URL_LENGTH).toBe(2048)
  })

  test.each([
    ['', EMPTY],
    ['   ', EMPTY],
    ['\n\t', EMPTY],
    [urlOfLength(2049), TOO_LONG],
    ['a.com/' + '😀'.repeat(2043), TOO_LONG], // 2049 code points
    ['a b.com', SPACES],
    ['http://exa mple.com', SPACES],
    ['example.com/\tpage', SPACES], // tab is whitespace, so rule 3 wins over rule 4
    ['a.com/\u0000', CONTROL],
    ['a.com/\u007f', CONTROL],
    ['https://', NOT_URL],
    ['localhost', NOT_URL],
    ['example.', NOT_URL],
    ['.com', NOT_URL],
    ['https://localhost/a.b', NOT_URL], // the dot must be in the host part
    ['localhost?q=a.b', NOT_URL],
    ['localhost#a.b', NOT_URL],
    ['ftp://', NOT_URL],
  ])('rejects %j', (input, message) => {
    expect(validateUrl(input)).toEqual({ valid: false, value: input.trim(), message })
  })

  test.each([
    'example.com',
    '  example.com  ',
    'https://www.paypal.com/login',
    'HTTPS://Example.COM',
    '192.168.0.1/login',
    'paypa1-secure-login.top/verify',
    'пример.рф',
    'a.b',
    urlOfLength(2048),
    'a.com/' + '😀'.repeat(2042), // 2048 code points but 4090 UTF-16 units
  ])('accepts %j', (input) => {
    expect(validateUrl(input)).toEqual({ valid: true, value: input.trim(), message: null })
  })

  test('first failure wins: a long URL with spaces reports the length', () => {
    expect(validateUrl('a b' + 'x'.repeat(2048)).message).toBe(TOO_LONG)
  })
})
