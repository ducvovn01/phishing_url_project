import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { expect, test } from 'vitest'
import App from './App.jsx'

const renderAt = (path) =>
  render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  )

test('home route renders with the skip link first', async () => {
  renderAt('/')
  expect(screen.getByRole('heading', { level: 1, name: 'Check a URL' })).toBeInTheDocument()
  await userEvent.tab()
  expect(screen.getByRole('link', { name: 'Skip to main content' })).toHaveFocus()
})

test('unknown route shows not-found page and its back button goes home', async () => {
  renderAt('/no-such-page')
  expect(screen.getByRole('heading', { name: 'Page not found' })).toBeInTheDocument()
  expect(document.title).toBe('Page not found | Phishing URL Checker')

  await userEvent.click(screen.getByRole('link', { name: 'Back to the URL checker' }))
  expect(screen.getByRole('heading', { level: 1, name: 'Check a URL' })).toBeInTheDocument()
})
