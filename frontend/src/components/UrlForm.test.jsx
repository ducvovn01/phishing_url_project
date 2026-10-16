import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, test, vi } from 'vitest'
import UrlForm from './UrlForm.jsx'

const HELPER = 'Only the text of the link is checked. The page is never opened.'
const EMPTY = 'Paste or type a URL to check.'
const FALLBACK = "Couldn't read your clipboard. Click the box and press Ctrl+V (Cmd+V on Mac)."

function setup(props = {}) {
  const user = userEvent.setup()
  const onSubmit = vi.fn()
  const onClear = vi.fn()
  const utils = render(<UrlForm onSubmit={onSubmit} onClear={onClear} {...props} />)
  const field = screen.getByRole('textbox', { name: 'Paste a URL to check' })
  return { user, onSubmit, onClear, field, ...utils }
}

// userEvent.setup() installs its own clipboard stub, so replace it afterwards.
const mockClipboard = (readText) =>
  Object.defineProperty(navigator, 'clipboard', { value: { readText }, configurable: true })

describe('UrlForm', () => {
  test('shows helper text and no error on an untouched field', () => {
    const { field } = setup()
    expect(field).toHaveAccessibleDescription(HELPER)
    expect(field).not.toHaveAttribute('aria-invalid', 'true')
  })

  test('empty submit shows an associated error and does not call onSubmit', async () => {
    const { user, onSubmit, field } = setup()
    await user.click(screen.getByRole('button', { name: 'Analyse URL' }))
    expect(onSubmit).not.toHaveBeenCalled()
    expect(field).toHaveAttribute('aria-invalid', 'true')
    expect(field).toHaveAccessibleDescription(EMPTY)
    expect(field).toHaveFocus()
  })

  test('the error clears while typing after a failed submit', async () => {
    const { user, field } = setup()
    await user.type(field, 'localhost{Enter}')
    expect(field).toHaveAttribute('aria-invalid', 'true')
    await user.type(field, '.com')
    expect(field).toHaveAccessibleDescription(HELPER)
    expect(field).not.toHaveAttribute('aria-invalid', 'true')
  })

  test('a valid URL calls onSubmit once with the trimmed value', async () => {
    const { user, onSubmit, field } = setup()
    await user.type(field, '  example.com/page  ')
    await user.click(screen.getByRole('button', { name: 'Analyse URL' }))
    expect(onSubmit).toHaveBeenCalledTimes(1)
    expect(onSubmit).toHaveBeenCalledWith('example.com/page')
  })

  test('Enter submits', async () => {
    const { user, onSubmit, field } = setup()
    await user.type(field, 'example.com{Enter}')
    expect(onSubmit).toHaveBeenCalledWith('example.com')
  })

  test('clipboard success fills and focuses the field without submitting', async () => {
    const { user, onSubmit, field } = setup()
    mockClipboard(vi.fn().mockResolvedValue('paypa1-secure-login.top/verify'))
    await user.click(screen.getByRole('button', { name: 'Paste from clipboard' }))
    expect(field).toHaveValue('paypa1-secure-login.top/verify')
    expect(field).toHaveFocus()
    expect(onSubmit).not.toHaveBeenCalled()
  })

  test('clipboard failure shows the fallback in a status region', async () => {
    const { user } = setup()
    mockClipboard(vi.fn().mockRejectedValue(new Error('denied')))
    await user.click(screen.getByRole('button', { name: 'Paste from clipboard' }))
    expect(screen.getByRole('status')).toHaveTextContent(FALLBACK)
  })

  test('missing Clipboard API shows the fallback too', async () => {
    const { user } = setup()
    mockClipboard(undefined)
    await user.click(screen.getByRole('button', { name: 'Paste from clipboard' }))
    expect(screen.getByRole('status')).toHaveTextContent(FALLBACK)
  })

  test('Clear is hidden when empty, and resets and focuses the field', async () => {
    const { user, onClear, field } = setup()
    expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument()
    await user.type(field, 'bad{Enter}')
    await user.click(screen.getByRole('button', { name: 'Clear' }))
    expect(field).toHaveValue('')
    expect(field).toHaveFocus()
    expect(field).toHaveAccessibleDescription(HELPER)
    expect(onClear).toHaveBeenCalledTimes(1)
    expect(screen.queryByRole('button', { name: 'Clear' })).not.toBeInTheDocument()
  })

  test('serverError shows in the helper text and is removed when typing', async () => {
    const { user, field } = setup({ serverError: { message: 'The service is busy.' } })
    expect(field).toHaveAccessibleDescription('The service is busy.')
    expect(field).toHaveAttribute('aria-invalid', 'true')
    await user.type(field, 'a')
    expect(field).toHaveAccessibleDescription(HELPER)
  })

  test('a new serverError shows again after the old one was dismissed', async () => {
    const { user, field, rerender, onSubmit, onClear } = setup({ serverError: { message: 'First' } })
    await user.type(field, 'a')
    rerender(<UrlForm onSubmit={onSubmit} onClear={onClear} serverError={{ message: 'Second' }} />)
    expect(field).toHaveAccessibleDescription('Second')
  })

  test('loading disables submit, shows Analysing... and keeps the field editable', async () => {
    const { user, onSubmit, field, container } = setup({ loading: true })
    const button = screen.getByRole('button', { name: 'Analysing...' })
    expect(button).toBeDisabled()
    expect(container.querySelector('form')).toHaveAttribute('aria-busy', 'true')
    await user.type(field, 'example.com{Enter}')
    expect(field).toHaveValue('example.com')
    expect(onSubmit).not.toHaveBeenCalled()
  })
})
