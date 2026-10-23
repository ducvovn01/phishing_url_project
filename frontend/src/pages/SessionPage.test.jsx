import { act, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { renderApp } from '../test/renderApp.jsx'

// jsdom has no SVG layout; the stubs show what the session charts were given.
vi.mock('@mui/x-charts/PieChart', () => ({
  PieChart: ({ series }) => <div data-testid="pie-chart">{series[0].data.map((d) => `${d.id}=${d.value}`).join(' ')}</div>,
}))
vi.mock('@mui/x-charts/BarChart', () => ({
  BarChart: ({ series }) => <div data-testid="bar-chart">{series[0].data.join(' ')}</div>,
}))
vi.mock('@mui/x-charts/ChartsReferenceLine', () => ({ ChartsReferenceLine: () => null }))

const result = (submitted, label) => ({
  submitted_url: submitted,
  analysed_url: submitted.replace(/^[a-z]+:\/\//i, '').toLowerCase(),
  label,
  confidence: 0.9,
  phishing_probability: label === 'phishing' ? 0.9 : 0.1,
  trust_score: label === 'phishing' ? 10 : 90,
  threshold: 0.5,
  signals: [],
  model: { name: 'm', version: 'v' },
})

function renderWith(...results) {
  const utils = renderApp('/session')
  act(() => results.forEach((r) => utils.session.current.addResult(r)))
  return { ...utils, user: userEvent.setup() }
}

const tableBody = () => screen.getByRole('table', { name: 'Links checked in this session' }).querySelector('tbody')

let setItem
beforeEach(() => {
  setItem = vi.spyOn(Storage.prototype, 'setItem')
})
afterEach(() => {
  // Results live in memory only (contract section 6.5); nothing may reach web storage.
  expect(setItem).not.toHaveBeenCalled()
  setItem.mockRestore()
})

describe('SessionPage', () => {
  // Must run first in this file: once the lazy import has resolved, later renders no longer suspend.
  test('with checks: "Loading charts..." shows first, then the charts between the summary and the table', async () => {
    renderWith(result('bad.top', 'phishing'), result('example.com', 'legitimate'))
    expect(screen.getByRole('status')).toHaveTextContent('Loading charts...')
    const donut = await screen.findByRole('heading', { level: 2, name: 'Results at a glance' })
    const bars = screen.getByRole('heading', { level: 2, name: 'Trust score for each check' })
    expect(screen.queryByText('Loading charts...')).not.toBeInTheDocument()
    const summary = screen.getByText('2 checks: 1 likely phishing, 1 likely legitimate')
    const table = screen.getByRole('region', { name: 'Checked links table' })
    const follows = (a, b) => Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING)
    expect(follows(summary, donut) && follows(donut, bars) && follows(bars, table)).toBe(true)
  })

  test('with no checks, the charts are not rendered', () => {
    renderWith()
    expect(screen.queryByText('Loading charts...')).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Results at a glance' })).not.toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Trust score for each check' })).not.toBeInTheDocument()
    expect(screen.getByText(/You haven't checked any links yet\./)).toBeInTheDocument()
  })

  test('adding a result or clearing updates the charts without a reload', async () => {
    const { session, user } = renderWith(result('bad.top', 'phishing'))
    // One check: both charts show their "check at least two links" message.
    expect(await screen.findByText('Check at least two links to compare results here.')).toBeInTheDocument()
    expect(screen.getByText('Check at least two links to compare trust scores here.')).toBeInTheDocument()

    act(() => session.current.addResult(result('example.com', 'legitimate')))
    expect(screen.getByTestId('pie-chart')).toHaveTextContent('phishing=1 legitimate=1')
    expect(screen.getByTestId('bar-chart')).toHaveTextContent('10 90')

    act(() => session.current.addResult(result('worse.top', 'phishing')))
    expect(screen.getByTestId('pie-chart')).toHaveTextContent('phishing=2 legitimate=1')
    expect(screen.getByTestId('bar-chart')).toHaveTextContent('10 90 10')
    expect(screen.getByRole('img', { name: /^Donut chart of 3 checks/ })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Clear session' }))
    expect(screen.queryByTestId('pie-chart')).not.toBeInTheDocument()
    expect(screen.queryByTestId('bar-chart')).not.toBeInTheDocument()
  })

  test('empty state shows the message and a link to "/", and sets the title', () => {
    renderWith()
    expect(screen.getByRole('heading', { level: 1, name: 'This session' })).toBeInTheDocument()
    expect(screen.getByText(/Nothing is saved: the list is cleared when you refresh or close the tab\./)).toBeInTheDocument()
    expect(screen.getByText(/You haven't checked any links yet\./)).toBeInTheDocument()
    expect(within(screen.getByRole('main')).getByRole('link', { name: 'Check a URL' })).toHaveAttribute('href', '/')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(document.title).toBe('This session | Phishing URL Checker')
  })

  test('with checks: summary line, one row per check in order, verdict words, plain-text links', () => {
    const js = 'javascript:alert(document.domain)'
    renderWith(result('paypa1-secure-login.top/verify', 'phishing'), result('https://www.wikipedia.org/wiki/Phishing', 'legitimate'), result(js, 'phishing'))

    expect(screen.getByText('3 checks: 2 likely phishing, 1 likely legitimate')).toBeInTheDocument()
    expect(screen.getByRole('region', { name: 'Checked links table' })).toHaveAttribute('tabindex', '0')

    const headers = within(screen.getByRole('table')).getAllByRole('columnheader').map((h) => h.textContent)
    expect(headers).toEqual(['#', 'Link', 'Result', 'Trust score', 'Time'])

    const rows = within(tableBody()).getAllByRole('row')
    expect(rows.map((r) => within(r).getAllByRole('cell').slice(0, 4).map((c) => c.textContent))).toEqual([
      ['1', 'paypa1-secure-login.top/verify', 'Likely phishing', '10'],
      ['2', 'https://www.wikipedia.org/wiki/Phishing', 'Likely legitimate', '90'],
      ['3', js, 'Likely phishing', '10'],
    ])
    for (const row of rows) expect(row.querySelector('time')).toHaveAttribute('datetime')

    expect(tableBody().querySelector('a')).toBeNull()
    expect(within(tableBody()).queryByRole('link')).not.toBeInTheDocument()
    expect(within(tableBody()).getByText(js).tagName).toBe('TD')
  })

  test('a single check says "1 check"', () => {
    renderWith(result('example.com', 'legitimate'))
    expect(screen.getByText('1 check: 0 likely phishing, 1 likely legitimate')).toBeInTheDocument()
  })

  test('Clear session empties the list, shows the empty state and focuses the h1', async () => {
    const { user, session } = renderWith(result('example.com', 'legitimate'), result('bad.top', 'phishing'))
    await user.click(screen.getByRole('button', { name: 'Clear session' }))
    expect(session.current.results).toEqual([])
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Clear session' })).not.toBeInTheDocument()
    expect(screen.getByText(/You haven't checked any links yet\./)).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 1, name: 'This session' })).toHaveFocus()
  })
})
