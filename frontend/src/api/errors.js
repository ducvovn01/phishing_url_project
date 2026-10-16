const MAX_MESSAGE_LENGTH = 300

export const DEFAULT_MESSAGES = {
  validation_error: "That doesn't look like a valid URL.",
  payload_too_large: 'That request is too large. Try a shorter URL.',
  service_busy: 'The service is busy. Please try again in a few seconds.',
  not_found: 'That address was not found on the server.',
  method_not_allowed: 'The server did not accept that request.',
  internal_error: 'Something went wrong on our side. Please try again.',
  backend_unavailable: 'The checker cannot be reached right now. Check your connection and try again.',
}

const STATUS_CODES = {
  422: 'validation_error',
  413: 'payload_too_large',
  503: 'service_busy',
  404: 'not_found',
  405: 'method_not_allowed',
}

/** An error in the contract shape. Its message is always one we chose or a vetted server message. */
export class ApiError extends Error {
  constructor(code, { message, details = [], request_id = null, retryAfterSeconds } = {}) {
    super(message ?? DEFAULT_MESSAGES[code] ?? DEFAULT_MESSAGES.internal_error)
    this.name = 'ApiError'
    this.code = code
    this.details = details
    this.request_id = request_id
    if (retryAfterSeconds !== undefined) this.retryAfterSeconds = retryAfterSeconds
  }
}

const isString = (v) => typeof v === 'string'

// shortcut: only the delta-seconds form of Retry-After is read, not the HTTP-date form; upgrade if the backend ever sends dates.
function readRetryAfter(headers) {
  const raw = headers?.['retry-after'] ?? headers?.['Retry-After']
  return /^\d+$/.test(String(raw ?? '').trim()) ? Number(raw) : null
}

function fromBody(body, status, headers) {
  const e = body?.error
  if (!e || typeof e !== 'object' || !isString(e.code) || e.code === '') return null
  const message = isString(e.message) && e.message.length <= MAX_MESSAGE_LENGTH ? e.message : undefined
  const details = Array.isArray(e.details)
    ? e.details.filter((d) => isString(d?.field) && isString(d?.message) && d.message.length <= MAX_MESSAGE_LENGTH)
    : []
  return new ApiError(e.code, {
    message,
    details,
    request_id: isString(e.request_id) ? e.request_id : null,
    retryAfterSeconds: status === 503 ? readRetryAfter(headers) : undefined,
  })
}

/**
 * Turn anything thrown during an API call into an ApiError in the contract shape.
 * Never copies raw error text or stack traces into the message.
 * @returns {ApiError}
 */
export function normaliseError(err) {
  if (err instanceof ApiError) return err

  if (err?.isAxiosError) {
    const res = err.response
    if (!res) return new ApiError('backend_unavailable') // network error or timeout
    const fromServer = fromBody(res.data, res.status, res.headers)
    if (fromServer) return fromServer
    const code = STATUS_CODES[res.status] ?? 'internal_error'
    return new ApiError(code, {
      retryAfterSeconds: code === 'service_busy' ? readRetryAfter(res.headers) : undefined,
    })
  }

  return new ApiError('internal_error')
}
