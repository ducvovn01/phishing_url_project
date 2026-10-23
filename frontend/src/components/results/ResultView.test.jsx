import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider } from '@mui/material'
import { describe, expect, test } from 'vitest'
import theme from '../../theme.js'
import ResultView from './ResultView.jsx'

const signal = (id, title, weight) => ({
  id,
  kind: 'ngram',
  title,
  direction: 'phishing',
  weight,
  start: 0,
  end: 3,
  text: 'abc',
  explanation: `Explains ${title}.`,
})

const makeResult = () => ({
  submitted_url: 'abc.top/x',
  analysed_url: 'abc.top/x',
  label: 'phishing',
  confidence: 0.9,
  phishing_probability: 0.9,
  trust_score: 10,
  threshold: 0.5,
  signals: [signal('s1', 'First signal', 5), signal('s2', 'Second signal', 3)],
  model: { name: 'm', version: 'v' },
})

const view = (result) => (
  <ThemeProvider theme={theme}>
    <ResultView result={result} verdictRef={{ current: null }} />
  </ThemeProvider>
)
const button = (name) => screen.getByRole('button', { name: new RegExp(name) })

describe('ResultView', () => {
  test('selecting a signal selects it, and selecting another moves the selection', async () => {
    const user = userEvent.setup()
    render(view(makeResult()))
    await user.click(button('First signal'))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'true')
    expect(button('Second signal')).toHaveAttribute('aria-pressed', 'false')
    await user.click(button('Second signal'))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'false')
    expect(button('Second signal')).toHaveAttribute('aria-pressed', 'true')
  })

  test('selecting the selected signal again deselects it', async () => {
    const user = userEvent.setup()
    render(view(makeResult()))
    await user.click(button('First signal'))
    await user.click(button('First signal'))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'false')
    expect(document.querySelectorAll('[aria-pressed="true"]')).toHaveLength(0)
  })

  test('a new result resets the selection, even with the same signal ids', async () => {
    const user = userEvent.setup()
    const { rerender } = render(view(makeResult()))
    await user.click(button('First signal'))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'true')
    rerender(view(makeResult()))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'false')
  })
})
