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
