import { render, screen } from '@testing-library/react'
import { expect, test } from 'vitest'
import App from './App.jsx'

test('renders without crashing', () => {
  render(<App />)
  expect(screen.getByRole('heading', { name: 'Phishing URL Checker' })).toBeInTheDocument()
})
