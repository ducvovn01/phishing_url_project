import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider } from '@mui/material'
import { describe, expect, test, vi } from 'vitest'
import theme from '../../theme.js'
import ResultView from './ResultView.jsx'

// The same kind of stub as WeightChart.test.jsx: one button per bar, wired to the real props.
vi.mock('@mui/x-charts/BarChart', () => ({
  BarChart: ({ series, slotProps, onItemClick }) => (
    <div data-testid="bar-chart">
      {series[0].data.map((_, dataIndex) => (
        <button
          key={dataIndex}
          type="button"
          data-selected={slotProps.bar({ dataIndex })['data-selected']}
          onClick={(e) => onItemClick(e, { type: 'bar', seriesId: 's', dataIndex })}
        >
          bar {dataIndex}
        </button>
      ))}
    </div>
  ),
}))
vi.mock('@mui/x-charts/ChartsReferenceLine', () => ({ ChartsReferenceLine: () => null }))

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
// Bars are sorted by absolute weight: bar 0 is s1 (First signal), bar 1 is s2.
const chartBar = (i) => screen.findByRole('button', { name: `bar ${i}` })

describe('ResultView', () => {
  // Must run first: once the lazy import has resolved, later renders no longer suspend.
  test('shows the Loading chart... fallback before the chart resolves, then the chart under the analysis', async () => {
    render(view(makeResult()))
    expect(screen.getByRole('status')).toHaveTextContent('Loading chart...')
    expect(await screen.findByRole('heading', { name: 'How much each part counted' })).toBeInTheDocument()
    expect(screen.queryByText('Loading chart...')).not.toBeInTheDocument()
    // DOM order: analysis panel, then the chart, inside the same grid cell.
    const analysis = screen.getByRole('region', { name: 'Analysis details' })
    const chart = screen.getByRole('heading', { name: 'How much each part counted' })
    expect(analysis.compareDocumentPosition(chart) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    expect(analysis.parentElement).toContainElement(chart)
  })

  test('the list and the chart share one selection', async () => {
    const user = userEvent.setup()
    render(view(makeResult()))
    await user.click(await chartBar(1))
    expect(button('Second signal')).toHaveAttribute('aria-pressed', 'true')
    expect(await chartBar(1)).toHaveAttribute('data-selected', 'true')

    await user.click(button('First signal'))
    expect(await chartBar(0)).toHaveAttribute('data-selected', 'true')
    expect(await chartBar(1)).toHaveAttribute('data-selected', 'false')
    expect(button('Second signal')).toHaveAttribute('aria-pressed', 'false')
  })

  test('clicking the selected bar again deselects it', async () => {
    const user = userEvent.setup()
    render(view(makeResult()))
    await user.click(await chartBar(0))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'true')
    await user.click(await chartBar(0))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'false')
    expect(await chartBar(0)).toHaveAttribute('data-selected', 'false')
  })

  test('a new result resets a selection made through the chart', async () => {
    const user = userEvent.setup()
    const { rerender } = render(view(makeResult()))
    await user.click(await chartBar(0))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'true')
    rerender(view(makeResult()))
    expect(button('First signal')).toHaveAttribute('aria-pressed', 'false')
    expect(await chartBar(0)).toHaveAttribute('data-selected', 'false')
  })

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
