// Rules 1 to 4 mirror the backend contract (docs/api-contract.md, sections 2 and 3.1) exactly.
// Rule 5 is a front-end usability check only; the backend stays the authority.

export const MAX_URL_LENGTH = 2048

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i

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
  const host = value.replace(SCHEME, '').split(/[/?#]/, 1)[0]
  if (!/[^.]\.[^.]/.test(host)) {
    return fail(value, "That doesn't look like a valid URL. Check it for typos, for example example.com/page.")
  }

  return { valid: true, value, message: null }
}
