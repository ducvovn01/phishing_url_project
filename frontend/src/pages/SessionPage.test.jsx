import { act, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest'
import { renderApp } from '../test/renderApp.jsx'

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
