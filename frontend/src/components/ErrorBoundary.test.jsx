import { render, screen } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import ErrorBoundary from './ErrorBoundary.jsx'

afterEach(() => vi.restoreAllMocks())

function Boom() {
  throw new Error('secret internal detail at /src/foo.js')
}

test('shows the fallback and hides the thrown error', () => {
  const log = vi.spyOn(console, 'error').mockImplementation(() => {})
  render(
    <ErrorBoundary>
      <Boom />
    </ErrorBoundary>,
  )
  expect(screen.getByRole('heading', { name: 'Something went wrong' })).toBeInTheDocument()
  expect(screen.getByRole('button', { name: 'Reload' })).toBeInTheDocument()
  expect(screen.getByRole('link', { name: 'Back to home' })).toHaveAttribute('href', '/')
  expect(screen.queryByText(/secret internal detail/)).not.toBeInTheDocument()
  expect(log).toHaveBeenCalled()
})
