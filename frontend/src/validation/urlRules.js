// Rules 1 to 6 mirror backend/app/validation.py (check_url) and the contract (docs/api-contract.md,
// sections 2 and 3.1). Rule 7 is a front-end usability check only; the backend stays the authority:
// the host must contain a "." between two other characters, or be a bracketed IPv6 literal
// ("[2001:db8::1]") or the word "localhost", each with an optional port.

export const MAX_URL_LENGTH = 2048

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i
// Same categories as REJECTED_CATEGORIES in validation.py; the space and control checks catch most of them first.
const HIDDEN = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}\p{Zs}]/u
// A scheme as validation.py's _has_scheme sees it: not "host:port" (digit after the colon) and no "." in it.
const SCHEME_PREFIX = /^([a-z][a-z0-9+.-]*):(?!\d)/i
const ALLOWED_SCHEMES = new Set(['http', 'https'])
// shortcut: only hex digits, ":" and "." are checked inside the brackets, not real IPv6 syntax; the backend is the authority.
const IPV6_OR_LOCALHOST = /^(\[[0-9a-f.]*:[0-9a-f:.]*\]|localhost)(:\d+)?$/i

const fail = (value, message) => ({ valid: false, value, message })

/**
 * @param {string} raw
 * @returns {{ valid: boolean, value: string, message: string | null }} value is the trimmed input.
 */
export function validateUrl(raw) {
  const value = String(raw ?? '').trim()

  if (value === '') return fail(value, 'Paste or type a URL to check.')
  if (Array.from(value).length > MAX_URL_LENGTH) {
    return fail(value, `That URL is too long. The limit is ${MAX_URL_LENGTH} characters.`)
  }
  if (/\s/u.test(value)) {
    return fail(value, "A URL can't contain spaces. Check that you pasted only one link.")
  }
  if (/\p{Cc}/u.test(value)) {
    return fail(value, "That URL contains characters that aren't allowed. Try copying it again.")
  }
  if (HIDDEN.test(value)) {
    return fail(value, 'That URL contains hidden characters. Try copying it again.')
  }
  // Scheme optional, as in the backend; when present it must be http:// or https://.
  const scheme = SCHEME_PREFIX.exec(value)
  if (scheme && !scheme[1].includes('.') && !(ALLOWED_SCHEMES.has(scheme[1].toLowerCase()) && value.startsWith('//', scheme[0].length))) {
    return fail(value, 'Only web addresses starting with http:// or https:// can be checked.')
  }
  const host = value.replace(SCHEME, '').split(/[/?#]/, 1)[0]
  if (!/[^.]\.[^.]/.test(host) && !IPV6_OR_LOCALHOST.test(host)) {
    return fail(value, "That doesn't look like a valid URL. Check it for typos, for example example.com/page.")
  }

  return { valid: true, value, message: null }
}
