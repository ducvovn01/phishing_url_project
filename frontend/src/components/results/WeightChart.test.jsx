import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider } from '@mui/material'
import { getContrastRatio } from '@mui/material/styles'
import { describe, expect, test, vi } from 'vitest'
import theme from '../../theme.js'
import WeightChart from './WeightChart.jsx'

// jsdom has no layout for SVG, so the stub renders one button per bar from the props the real chart gets.
vi.mock('@mui/x-charts/BarChart', () => ({
  BarChart: ({ series, yAxis, slotProps, onItemClick, layout }) => (
    <div data-testid="bar-chart" data-layout={layout}>
      {series[0].data.map((value, dataIndex) => {
        const id = yAxis[0].data[dataIndex]
        return (
          <button
            key={id}
            type="button"
            data-color={series[0].colorGetter({ value, dataIndex })}
            data-selected={slotProps.bar({ dataIndex })['data-selected']}
            data-tooltip={`${yAxis[0].valueFormatter(id, { location: 'tooltip' })}: ${series[0].valueFormatter(value, { dataIndex })}`}
            onClick={(e) => onItemClick(e, { type: 'bar', seriesId: 's', dataIndex })}
          >
            {yAxis[0].valueFormatter(id, { location: 'tick' })}
          </button>
        )
      })}
    </div>
  ),
}))
vi.mock('@mui/x-charts/ChartsReferenceLine', () => ({ ChartsReferenceLine: () => null }))

const ngram = (id, text, weight) => ({
  id,
  kind: 'ngram',
  title: 'Pattern',
  direction: weight < 0 ? 'legitimate' : 'phishing',
  weight,
  start: 0,
  end: 1,
  text,
  explanation: 'x',
})
const rule = (id) => ({ id, kind: 'rule', title: 'Rule', direction: 'phishing', weight: null, start: null, end: null, text: null, explanation: 'x' })

// The mock's contract example 3.2 plus one rule.
const SIGNALS = [ngram('ngram-1', '.top', 37.1), ngram('ngram-2', 'login', 24.5), ngram('ngram-3', 'www.', -29.4), rule('rule-1')]

function renderChart(props = {}) {
  const onSelect = vi.fn()
  const utils = render(
    <ThemeProvider theme={theme}>
      <WeightChart signals={SIGNALS} selectedId={null} onSelect={onSelect} {...props} />
    </ThemeProvider>,
  )
  return { ...utils, onSelect, user: userEvent.setup() }
}
const bar = (name) => within(screen.getByTestId('bar-chart')).getByRole('button', { name })

describe('WeightChart', () => {
  test('heading, sentence, horizontal bars sorted by absolute weight', () => {
    renderChart()
    expect(screen.getByRole('heading', { level: 2, name: 'How much each part counted' })).toBeInTheDocument()
    expect(screen.getByText(/Bars to the right push the result towards phishing\./)).toBeInTheDocument()
    expect(screen.getByTestId('bar-chart')).toHaveAttribute('data-layout', 'horizontal')
    expect(within(screen.getByTestId('bar-chart')).getAllByRole('button').map((b) => b.textContent)).toEqual(['.top', 'www.', 'login'])
    expect(screen.getByText('← Lowers risk')).toBeInTheDocument()
    expect(screen.getByText('Raises risk →')).toBeInTheDocument()
  })

  test('the aria-label summarises the chart', () => {
    renderChart()
    expect(screen.getByRole('img')).toHaveAccessibleName('Bar chart of 3 signals. The largest is .top, raising risk by 37.1.')
  })

  test('the summary says lowering when the largest bar is negative', () => {
    renderChart({ signals: [ngram('a', 'www.', -29.4)] })
    expect(screen.getByRole('img')).toHaveAccessibleName('Bar chart of 1 signal. The largest is www., lowering risk by 29.4.')
  })

  test('tooltip has the full label, direction in words and one decimal', () => {
    renderChart({ signals: [ngram('a', 'a-very-long-pattern-text', -9.25)] })
    const b = bar('a-very-long-pa...')
    expect(b).toHaveAttribute('data-tooltip', 'a-very-long-pattern-text: Lowers risk, weight -9.3')
  })

  test('clicking a bar calls onSelect with that signal id', async () => {
    const { user, onSelect } = renderChart()
    await user.click(bar('www.'))
    expect(onSelect).toHaveBeenCalledWith('ngram-3')
  })

  test('the selected bar is marked and the others are lighter', () => {
    renderChart({ selectedId: 'ngram-2' })
    expect(bar('login')).toHaveAttribute('data-selected', 'true')
    expect(bar('.top')).toHaveAttribute('data-selected', 'false')
    expect(bar('login')).toHaveAttribute('data-color', theme.palette.phishing.main)
    expect(bar('.top')).not.toHaveAttribute('data-color', theme.palette.phishing.main)
  })

  test('bar colours use the semantic palette and reach 3:1 on the page, selected or faded', () => {
    const { rerender } = renderChart()
    expect(bar('.top')).toHaveAttribute('data-color', theme.palette.phishing.main)
    expect(bar('www.')).toHaveAttribute('data-color', theme.palette.legitimate.main)
    const colours = new Set(within(screen.getByTestId('bar-chart')).getAllByRole('button').map((b) => b.dataset.color))
    rerender(
      <ThemeProvider theme={theme}>
        <WeightChart signals={SIGNALS} selectedId="none-of-them" onSelect={() => {}} />
      </ThemeProvider>,
    )
    within(screen.getByTestId('bar-chart')).getAllByRole('button').forEach((b) => colours.add(b.dataset.color))
    expect(colours.size).toBe(4)
    for (const c of colours) {
      expect(getContrastRatio(c, theme.palette.background.default), c).toBeGreaterThanOrEqual(3)
    }
  })

  test('the table toggle works and lists every row with the direction in words', async () => {
    const { user } = renderChart()
    const toggle = screen.getByRole('button', { name: 'Show data as a table' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(toggle).toHaveAccessibleName('Hide table')
    const table = screen.getByRole('table')
    expect(document.getElementById(toggle.getAttribute('aria-controls'))).toContainElement(table)
    const rows = within(table)
      .getAllByRole('row')
      .map((r) => Array.from(r.querySelectorAll('th, td'), (c) => c.textContent))
    expect(rows).toEqual([
      ['Part', 'Direction', 'Weight'],
      ['.top', 'Raises risk', '37.1'],
      ['www.', 'Lowers risk', '-29.4'],
      ['login', 'Raises risk', '24.5'],
    ])

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  test('the skipped line shows only when rules were left out', () => {
    const { rerender } = renderChart()
    expect(screen.getByText('1 rule-based check has no weight and is not shown here; it is listed above.')).toBeInTheDocument()
    rerender(
      <ThemeProvider theme={theme}>
        <WeightChart signals={[...SIGNALS, rule('rule-2')]} selectedId={null} onSelect={() => {}} />
      </ThemeProvider>,
    )
    expect(screen.getByText('2 rule-based checks have no weight and are not shown here; they are listed above.')).toBeInTheDocument()
    rerender(
      <ThemeProvider theme={theme}>
        <WeightChart signals={SIGNALS.slice(0, 3)} selectedId={null} onSelect={() => {}} />
      </ThemeProvider>,
    )
    expect(screen.queryByText(/rule-based check/)).not.toBeInTheDocument()
  })

  test('no rows: no chart, no table toggle, an empty message', () => {
    renderChart({ signals: [rule('rule-1')] })
    expect(screen.getByText('No weighted parts to show for this result.')).toBeInTheDocument()
    expect(screen.queryByTestId('bar-chart')).not.toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Show data as a table' })).not.toBeInTheDocument()
    expect(screen.getByText(/1 rule-based check has no weight/)).toBeInTheDocument()
  })

  test('odd signals do not throw', () => {
    renderChart({ signals: null })
    expect(screen.getByText('No weighted parts to show for this result.')).toBeInTheDocument()
  })
})
