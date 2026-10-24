import { act, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeAll, describe, expect, test, vi } from 'vitest'
import { axe } from 'vitest-axe'
import { analyseUrl } from '../api/index.js'
import { ApiError } from '../api/errors.js'
import { renderApp } from './renderApp.jsx'

vi.mock('../api/index.js', () => ({ analyseUrl: vi.fn(), getHealth: vi.fn() }))

// jsdom cannot compute colours, so contrast is covered by src/theme.test.js instead.
const AXE_OPTIONS = { rules: { 'color-contrast': { enabled: false } } }
// The charts load lazily; under a full parallel test run that can take longer than findBy's 1s default.
const SLOW = { timeout: 5000 }

async function expectNoViolations() {
  const { violations } = await axe(document.body, AXE_OPTIONS)
  // Map to id and targets so a failure names the rule and the elements.
  expect(violations.map((v) => ({ id: v.id, nodes: v.nodes.map((n) => n.target.join(' ')) }))).toEqual([])
}

// Real response shapes from the mock backend (src/api/mock.js), contract examples 3.2 and 3.5.
let PHISHING
let LEGITIMATE
beforeAll(async () => {
  const mock = await vi.importActual('../api/mock.js')
  ;[PHISHING, LEGITIMATE] = await Promise.all([
    mock.analyseUrl('paypa1-secure-login.top/verify'),
    mock.analyseUrl('https://www.wikipedia.org/wiki/Phishing'),
  ])
})

async function submit(url) {
  const user = userEvent.setup()
  await user.type(screen.getByRole('textbox', { name: 'Paste a URL to check' }), url)
  await user.click(screen.getByRole('button', { name: 'Analyse URL' }))
}

describe('no axe violations', { timeout: 15000 }, () => {
  test('home, idle', async () => {
    renderApp('/')
    await expectNoViolations()
  })

  test('home, loading', async () => {
    analyseUrl.mockReturnValue(new Promise(() => {}))
    renderApp('/')
    await submit('example.com')
    await screen.findByText('Analysing the link text...')
    await expectNoViolations()
  })

  test.each([
    ['phishing', () => PHISHING, 'Likely phishing'],
    ['legitimate', () => LEGITIMATE, 'Likely legitimate'],
  ])('home, success (%s) with the weight chart loaded', async (_, result, verdict) => {
    analyseUrl.mockResolvedValue(result())
    renderApp('/')
    await submit(result().submitted_url)
    await screen.findByRole('heading', { level: 2, name: verdict }, SLOW)
    await screen.findByRole('heading', { level: 2, name: 'How much each part counted' }, SLOW)
    await expectNoViolations()
  })

  test.each([
    ['busy', new ApiError('service_busy', { request_id: 'req-1', retryAfterSeconds: 5 })],
    ['unreachable', new ApiError('backend_unavailable')],
  ])('home, error (%s)', async (_, error) => {
    analyseUrl.mockRejectedValue(error)
    renderApp('/')
    await submit('example.com')
    await screen.findByRole('alert')
    await expectNoViolations()
  })

  test('session, empty', async () => {
    renderApp('/session')
    await expectNoViolations()
  })

  test('session, several checks with both charts loaded', async () => {
    const { session } = renderApp('/session')
    act(() => {
      session.current.addResult(PHISHING)
      session.current.addResult(LEGITIMATE)
      session.current.addResult({ ...PHISHING, submitted_url: 'xn--pple-43d.com/signin', trust_score: 12 })
    })
    await screen.findByRole('heading', { level: 2, name: 'Results at a glance' }, SLOW)
    await screen.findByRole('heading', { level: 2, name: 'Trust score for each check' }, SLOW)
    await expectNoViolations()
  })

  test('404', async () => {
    renderApp('/no-such-page')
    await screen.findByRole('heading', { level: 1, name: 'Page not found' })
    await expectNoViolations()
  })
})

describe('layout at any width (what jsdom can check)', { timeout: 15000 }, () => {
  // 2048 code points with an unbroken host of 1000 letters, the worst case the form accepts.
  const host = 'a'.repeat(1000) + '.com'
  const longUrl = `https://${host}/` + 'p'.repeat(2048 - host.length - 9)

  test('a 2048 character URL wraps anywhere and grid cells may shrink below their content', async () => {
    expect(Array.from(longUrl)).toHaveLength(2048)
    analyseUrl.mockResolvedValue({ ...PHISHING, submitted_url: longUrl, analysed_url: longUrl.slice(8), signals: [] })
    renderApp('/')
    // Pasted, not typed: typing 2048 characters one by one takes longer than the test timeout.
    const user = userEvent.setup()
    await user.click(screen.getByRole('textbox', { name: 'Paste a URL to check' }))
    await user.paste(longUrl)
    await user.click(screen.getByRole('button', { name: 'Analyse URL' }))
    await screen.findByRole('heading', { level: 2, name: 'Likely phishing' }, SLOW)

    const submitted = screen.getByText(longUrl)
    expect(getComputedStyle(submitted).overflowWrap).toBe('anywhere')
    const analysis = screen.getByRole('region', { name: 'Analysis details' })
    expect(getComputedStyle(analysis.querySelector('p')).overflowWrap).toBe('anywhere')
    // Every grid cell on the results page has min-width 0, so long content cannot widen the page.
    const grid = analysis.parentElement.parentElement
    expect(grid.children.length).toBeGreaterThanOrEqual(5) // form, URL, verdict, score, analysis
    for (const cell of grid.children) expect(getComputedStyle(cell).minWidth, cell.textContent.slice(0, 30)).toMatch(/^0(px)?$/)
  })

  test('the session table sits in a focusable scroll region and long links wrap', async () => {
    const { session } = renderApp('/session')
    act(() => {
      session.current.addResult({ ...PHISHING, submitted_url: longUrl })
      session.current.addResult(LEGITIMATE)
    })
    const region = screen.getByRole('region', { name: 'Checked links table' })
    expect(region).toHaveAttribute('tabindex', '0')
    expect(getComputedStyle(region).overflowX).toBe('auto')
    expect(region).toContainElement(screen.getByRole('table', { name: 'Links checked in this session' }))
    expect(getComputedStyle(screen.getByRole('cell', { name: longUrl })).overflowWrap).toBe('anywhere')
    await screen.findByRole('heading', { level: 2, name: 'Results at a glance' }, SLOW)
  })
})
