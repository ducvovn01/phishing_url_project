import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, test, vi } from 'vitest'
import { ApiError } from '../../api/errors.js'
import ErrorState from './ErrorState.jsx'

test('"Try again" is a button inside the alert and calls the retry handler', async () => {
  const user = userEvent.setup()
  const onRetry = vi.fn()
  render(<ErrorState error={new ApiError('backend_unavailable')} onRetry={onRetry} />)

  const button = screen.getByRole('button', { name: 'Try again' })
  expect(screen.getByRole('alert')).toContainElement(button)
  await user.click(button)
  expect(onRetry).toHaveBeenCalledTimes(1)

  button.focus()
  await user.keyboard('{Enter}')
  expect(onRetry).toHaveBeenCalledTimes(2)
})

test.each([
  [1, 'Please wait about 1 second, then try again.'],
  [2, 'Please wait about 2 seconds, then try again.'],
  [30, 'Please wait about 30 seconds, then try again.'],
])('service_busy with Retry-After %s shows "%s"', (seconds, line) => {
  render(<ErrorState error={new ApiError('service_busy', { retryAfterSeconds: seconds })} onRetry={() => {}} />)
  expect(screen.getByText(line)).toBeInTheDocument()
})

test('rate_limited has its own title and shows the wait line', () => {
  render(<ErrorState error={new ApiError('rate_limited', { retryAfterSeconds: 10 })} onRetry={() => {}} />)
  expect(screen.getByRole('heading', { level: 2, name: 'Too many requests' })).toBeInTheDocument()
  expect(screen.getByText('Too many requests. Please wait a moment and try again.')).toBeInTheDocument()
  expect(screen.getByText('Please wait about 10 seconds, then try again.')).toBeInTheDocument()
})

test('rate_limited with Retry-After 1 uses the singular', () => {
  render(<ErrorState error={new ApiError('rate_limited', { retryAfterSeconds: 1 })} onRetry={() => {}} />)
  expect(screen.getByText('Please wait about 1 second, then try again.')).toBeInTheDocument()
})

test.each([0, -5, NaN, Infinity, undefined])('service_busy with Retry-After %s shows no wait line', (seconds) => {
  render(<ErrorState error={new ApiError('service_busy', { retryAfterSeconds: seconds })} onRetry={() => {}} />)
  expect(screen.getByRole('alert')).toBeInTheDocument()
  expect(screen.queryByText(/Please wait about/)).not.toBeInTheDocument()
})
