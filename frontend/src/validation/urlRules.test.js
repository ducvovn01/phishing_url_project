import { describe, expect, test } from 'vitest'
import { MAX_URL_LENGTH, validateUrl } from './urlRules.js'

const EMPTY = 'Paste or type a URL to check.'
const TOO_LONG = 'That URL is too long. The limit is 2048 characters.'
const SPACES = "A URL can't contain spaces. Check that you pasted only one link."
const CONTROL = "That URL contains characters that aren't allowed. Try copying it again."
const NOT_URL = "That doesn't look like a valid URL. Check it for typos, for example example.com/page."
const HIDDEN = 'That URL contains hidden characters. Try copying it again.'
const SCHEME = 'Only web addresses starting with http:// or https:// can be checked.'

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
    ['ftp://', SCHEME],
    // Schemes: only http:// and https:// (backend/app/validation.py, ALLOWED_SCHEMES).
    ['ftp://x.com', SCHEME],
    ['javascript:alert(1)', SCHEME],
    ['javascript:alert(document.domain)', SCHEME],
    ['data:text/html,x', SCHEME],
    ['file:///etc/x', SCHEME],
    ['mailto:a@b.com', SCHEME],
    ['http:example.com', SCHEME], // http without "//"
    ['HTTPS:/example.com', SCHEME],
    // Invisible and space characters (categories Cc, Cf, Cs, Zl, Zp, Zs).
    ['a.com/​', HIDDEN], // zero width space (Cf)
    ['a.com/‮', HIDDEN], // right-to-left override (Cf)
    ['a.com/\ud800', HIDDEN], // lone surrogate (Cs)
    ['a.com/x\udc00y', HIDDEN], // lone low surrogate (Cs)
    ['a.com/ x', SPACES], // no-break space (Zs) is whitespace
    ['a.com/ x', SPACES], // line separator (Zl) is whitespace
    ['a.com/ x', SPACES], // paragraph separator (Zp) is whitespace
    ['a.com/　x', SPACES], // ideographic space (Zs)
    ['a.com/\u0085x', CONTROL], // next line (Cc), not whitespace in JavaScript
    ['mock-busy', NOT_URL], // the bare triggers never passed the form; their dotted aliases do
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
    'http://example.com',
    'https://example.com/a?b=c#d',
    'example.com:443/path', // "host:port" is not a scheme
    'user.name:pw@example.com', // a "." before the colon means it is not a scheme
    '😀.com', // an emoji is a symbol (So), not an invisible character
    // Mock special inputs (src/api/mock.js) must still pass the form.
    'busy.mock',
    'error.mock',
    'offline.mock',
    'invalid.mock',
    'https://busy.mock/page',
    'https://mock-busy.test',
    'https://mock-error.test',
    'https://mock-offline.test',
    'https://mock-invalid.test',
  ])('accepts %j', (input) => {
    expect(validateUrl(input)).toEqual({ valid: true, value: input.trim(), message: null })
  })

  test('first failure wins: a long URL with spaces reports the length', () => {
    expect(validateUrl('a b' + 'x'.repeat(2048)).message).toBe(TOO_LONG)
  })

  test('no scheme is fine, as in the backend (scheme optional)', () => {
    expect(validateUrl('paypa1-secure-login.top/verify').valid).toBe(true)
    expect(validateUrl('www.wikipedia.org/wiki/Phishing').valid).toBe(true)
  })
})
