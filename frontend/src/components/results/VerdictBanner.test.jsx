import { render, screen } from '@testing-library/react'
import { ThemeProvider } from '@mui/material'
import { expect, test } from 'vitest'
import theme from '../../theme.js'
import VerdictBanner from './VerdictBanner.jsx'

const renderBanner = (label, confidence) =>
  render(
    <ThemeProvider theme={theme}>
      <VerdictBanner result={{ label, confidence }} />
    </ThemeProvider>,
  )

test('a backend-style 0.9999999990 reads "Over 99% confidence", never 100%', () => {
  renderBanner('phishing', 0.999999999)
  expect(screen.getByText('Over 99% confidence')).toBeInTheDocument()
  expect(screen.queryByText(/100%/)).not.toBeInTheDocument()
})

test('an ordinary value is a whole percentage', () => {
  renderBanner('legitimate', 0.874)
  expect(screen.getByRole('heading', { level: 2, name: 'Likely legitimate' })).toBeInTheDocument()
  expect(screen.getByText('87% confidence')).toBeInTheDocument()
})
