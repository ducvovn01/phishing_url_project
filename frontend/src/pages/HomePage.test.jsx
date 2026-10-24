import { screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { analyseUrl } from '../api/index.js'
import { ApiError } from '../api/errors.js'
import { renderApp } from '../test/renderApp.jsx'

vi.mock('../api/index.js', () => ({ analyseUrl: vi.fn(), getHealth: vi.fn() }))

// Contract section 3.2 example.
const PHISHING = {
  submitted_url: 'paypa1-secure-login.top/verify',
  analysed_url: 'paypa1-secure-login.top/verify',
  label: 'phishing',
  confidence: 0.93,
  phishing_probability: 0.93,
  trust_score: 7,
  threshold: 0.5,
  signals: [
    {
      id: 'ngram-1',
      kind: 'ngram',
      title: 'Pattern linked to phishing',
      direction: 'phishing',
      weight: 37.1,
      start: 19,
      end: 23,
      text: '.top',
      explanation: 'URLs containing this pattern were mostly phishing in the training data.',
    },
    {
      id: 'rule-unusual-tld',
      kind: 'rule',
      title: 'Unusual top-level domain',
      direction: 'phishing',
      weight: null,
      start: 20,
      end: 23,
      text: 'top',
      explanation: 'This ending is far more common in phishing links than in legitimate ones.',
    },
  ],
  model: { name: 'char_ngram_logreg', version: 'a2-final' },
}

const field = () => screen.getByRole('textbox', { name: 'Paste a URL to check' })

async function check(url) {
  const user = userEvent.setup()
  await user.type(field(), url)
  await user.click(screen.getByRole('button', { name: 'Analyse URL' }))
  return user
}

beforeEach(() => {
  analyseUrl.mockReset()
})

describe('HomePage', () => {
  test('success shows the verdict, confidence, score and analysis, and focuses the verdict', async () => {
    analyseUrl.mockResolvedValue(PHISHING)
    renderApp()
    await check('paypa1-secure-login.top/verify')

    const verdict = await screen.findByRole('heading', { level: 2, name: 'Likely phishing' })
    expect(verdict).toHaveFocus()
    expect(screen.getByText('93% confidence')).toBeInTheDocument()
    expect(document.title).toBe('Likely phishing | Phishing URL Checker')
    expect(screen.getByRole('meter', { name: 'Trust score' })).toHaveAttribute('aria-valuenow', '7')
    expect(screen.getByRole('region', { name: 'Analysis details' })).toBeInTheDocument()
    expect(screen.getByText(/Do not open this link/)).toBeInTheDocument()
    // The same form instance is still there and keeps the typed value.
    expect(field()).toHaveValue('paypa1-secure-login.top/verify')
  })

  test('selecting a signal sets aria-pressed and emphasises its segment', async () => {
    analyseUrl.mockResolvedValue(PHISHING)
    renderApp()
    const user = await check('paypa1-secure-login.top/verify')
    const signal = await screen.findByRole('button', { name: /Pattern linked to phishing/ })
    expect(signal).toHaveAttribute('aria-pressed', 'false')
    signal.focus()
    await user.keyboard('{Enter}')
    expect(signal).toHaveAttribute('aria-pressed', 'true')
    await user.keyboard(' ')
    expect(signal).toHaveAttribute('aria-pressed', 'false')
  })

  test('selecting a rule under an ngram emphasises its own characters in the URL', async () => {
    analyseUrl.mockResolvedValue(PHISHING)
    const { container } = renderApp()
    const user = await check('paypa1-secure-login.top/verify')
    const url = (await screen.findByRole('region', { name: 'Analysis details' })).querySelector('p')
    const emphasised = () => Array.from(url.querySelectorAll('mark')).filter((m) => getComputedStyle(m).fontWeight === '700').map((m) => m.textContent)

    expect(Array.from(url.querySelectorAll('mark'), (m) => m.textContent)).toEqual(['.top'])
    expect(emphasised()).toEqual([])

    await user.click(screen.getByRole('button', { name: /Unusual top-level domain/ }))
    expect(Array.from(url.querySelectorAll('mark'), (m) => m.textContent)).toEqual(['.', 'top'])
    expect(emphasised()).toEqual(['top'])
    expect(url).toHaveTextContent('paypa1-secure-login.top/verify')
    expect(url.querySelector('a')).toBeNull()

    await user.click(screen.getByRole('button', { name: /Pattern linked to phishing/ }))
    expect(emphasised()).toEqual(['.top'])
    expect(container.querySelectorAll('a[href*="paypa1"]')).toHaveLength(0)
  })

  test('clearing the form resets the selection', async () => {
    analyseUrl.mockResolvedValue(PHISHING)
    renderApp()
    const user = await check('paypa1-secure-login.top/verify')
    await user.click(await screen.findByRole('button', { name: /Pattern linked to phishing/ }))
    await user.click(screen.getByRole('button', { name: 'Clear' }))
    await check('paypa1-secure-login.top/verify')
    expect(await screen.findByRole('button', { name: /Pattern linked to phishing/ })).toHaveAttribute('aria-pressed', 'false')
  })

  test('a javascript: URL is shown as plain text and never becomes a link', async () => {
    const url = 'javascript:alert(document.domain)'
    // The form now rejects this scheme, so the response carries it, as a misbehaving backend might.
    analyseUrl.mockResolvedValue({ ...PHISHING, submitted_url: url, analysed_url: url, signals: [] })
    const { container } = renderApp()
    const user = await check(url)
    expect(await screen.findByText('Only web addresses starting with http:// or https:// can be checked.')).toBeInTheDocument()
    expect(analyseUrl).not.toHaveBeenCalled()

    await user.clear(field())
    await check('example.com')

    await screen.findByRole('heading', { level: 2, name: 'Likely phishing' })
    const checked = screen.getByText('Checked:').parentElement
    expect(checked).toHaveTextContent(`Checked: ${url}`)
    expect(checked.querySelector('a')).toBeNull()
    for (const a of container.querySelectorAll('a')) {
      expect(a.getAttribute('href') ?? '').not.toContain('javascript')
    }
    expect(container.querySelector(`a[href="${url}"]`)).toBeNull()
  })

  test('the error state shows the message and reference, but no details or stack', async () => {
    const error = new ApiError('internal_error', {
      message: 'Something went wrong on our side. Please try again.',
      details: [{ field: 'model', message: 'secret detail' }],
      request_id: 'abc123',
    })
    analyseUrl.mockRejectedValue(error)
    renderApp()
    await check('example.com')

    const alert = await screen.findByRole('alert')
    expect(within(alert).getByRole('heading', { name: 'Something went wrong' })).toHaveFocus()
    expect(alert).toHaveTextContent('Something went wrong on our side. Please try again.')
    expect(alert).toHaveTextContent('Reference: abc123')
    expect(document.body).not.toHaveTextContent('secret detail')
    expect(document.body).not.toHaveTextContent(/ApiError|at .*\.js/)
  })

  test('Try again resubmits the last value', async () => {
    analyseUrl.mockRejectedValueOnce(new ApiError('backend_unavailable')).mockResolvedValueOnce(PHISHING)
    renderApp()
    const user = await check('example.com')
    await user.click(await screen.findByRole('button', { name: 'Try again' }))
    await screen.findByRole('heading', { level: 2, name: 'Likely phishing' })
    expect(analyseUrl).toHaveBeenLastCalledWith('example.com')
  })

  test('service_busy shows the wait text', async () => {
    analyseUrl.mockRejectedValue(new ApiError('service_busy', { retryAfterSeconds: 5, request_id: 'c41b7e' }))
    renderApp()
    await check('example.com')
    expect(await screen.findByRole('heading', { name: 'The checker is busy' })).toBeInTheDocument()
    expect(screen.getByText('Please wait about 5 seconds, then try again.')).toBeInTheDocument()
  })

  test('rate_limited shows its title and the wait text', async () => {
    analyseUrl.mockRejectedValue(new ApiError('rate_limited', { retryAfterSeconds: 10, request_id: 'mock' }))
    renderApp()
    await check('example.com')
    expect(await screen.findByRole('heading', { name: 'Too many requests' })).toBeInTheDocument()
    expect(screen.getByText('Please wait about 10 seconds, then try again.')).toBeInTheDocument()
  })

  test('loading shows a status message and a disabled submit button', async () => {
    analyseUrl.mockReturnValue(new Promise(() => {}))
    renderApp()
    await check('example.com')
    expect(screen.getByText('Analysing the link text...')).toHaveRole('status')
    expect(screen.getByRole('button', { name: 'Analysing...' })).toBeDisabled()
  })

  test('a validation_error with a url detail appears in the form', async () => {
    analyseUrl.mockRejectedValue(
      new ApiError('validation_error', {
        message: "That doesn't look like a valid URL.",
        details: [{ field: 'url', message: 'Must be 1 to 2048 characters.' }],
        request_id: '9f3c1a',
      }),
    )
    renderApp()
    await check('example.com')
    await screen.findByRole('heading', { name: 'Check the URL' })
    expect(field()).toHaveAccessibleDescription('Must be 1 to 2048 characters.')
    expect(field()).toHaveAttribute('aria-invalid', 'true')
  })

  test('the session context receives one entry per success', async () => {
    analyseUrl.mockResolvedValueOnce(PHISHING).mockRejectedValueOnce(new ApiError('internal_error')).mockResolvedValueOnce(PHISHING)
    const { session } = renderApp()
    const user = await check('a.com')
    await screen.findByRole('heading', { level: 2, name: 'Likely phishing' })
    await user.click(screen.getByRole('button', { name: 'Analyse URL' }))
    await screen.findByRole('alert')
    await user.click(screen.getByRole('button', { name: 'Analyse URL' }))
    await screen.findByRole('heading', { level: 2, name: 'Likely phishing' })

    expect(session.current.results).toHaveLength(2)
    expect(session.current.results.map((r) => r.id)).toEqual([1, 2])
    expect(session.current.results[0].checkedAt).toBeInstanceOf(Date)
    expect(session.current.results[0].result).toBe(PHISHING)
  })

  test('Clear returns to idle', async () => {
    analyseUrl.mockResolvedValue(PHISHING)
    renderApp()
    const user = await check('a.com')
    await screen.findByRole('heading', { level: 2, name: 'Likely phishing' })
    await user.click(screen.getByRole('button', { name: 'Clear' }))
    expect(screen.queryByRole('heading', { level: 2, name: 'Likely phishing' })).not.toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'How it works' })).toBeInTheDocument()
    expect(document.title).toBe('Check a URL | Phishing URL Checker')
  })
})
