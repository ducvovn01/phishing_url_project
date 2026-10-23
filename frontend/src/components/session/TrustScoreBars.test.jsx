import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider } from '@mui/material'
import { getContrastRatio } from '@mui/material/styles'
import { describe, expect, test, vi } from 'vitest'
import { summariseSession } from '../../lib/sessionSummary.js'
import theme from '../../theme.js'
import TrustScoreBars from './TrustScoreBars.jsx'

// jsdom has no SVG layout, so the stub renders one bar per value from the props the real chart gets.
vi.mock('@mui/x-charts/BarChart', () => ({
  BarChart: ({ xAxis, yAxis, series, children }) => (
    <div data-testid="bar-chart" data-y={`${yAxis[0].min}-${yAxis[0].max} ${yAxis[0].tickInterval.join(',')}`}>
      {series[0].data.map((value, dataIndex) => {
        const n = xAxis[0].data[dataIndex]
        return (
          <span
            key={n}
            data-testid="bar"
            data-color={series[0].colorGetter({ value, dataIndex })}
            data-tooltip={`${xAxis[0].valueFormatter(n, { location: 'tooltip' })}: ${series[0].valueFormatter(value, { dataIndex })}`}
            data-label={series[0].barLabel}
          >
            {xAxis[0].valueFormatter(n, { location: 'tick' })}
          </span>
        )
      })}
      {children}
    </div>
  ),
}))
vi.mock('@mui/x-charts/ChartsReferenceLine', () => ({
  ChartsReferenceLine: ({ y, label }) => <span data-testid="reference" data-y={y} data-label={label} />,
}))

const entry = (id, trust, url = `site${id}.com/x`) => ({
  id,
  checkedAt: new Date(2026, 9, 23, 10, id),
  result: {
    submitted_url: url,
    analysed_url: url,
    label: trust < 50 ? 'phishing' : 'legitimate',
    confidence: 0.9,
    trust_score: trust,
  },
})
const summaryOf = (...scores) => summariseSession(scores.map((s, i) => entry(i + 1, s)))

function renderBars(summary) {
  render(
    <ThemeProvider theme={theme}>
      <TrustScoreBars summary={summary} />
    </ThemeProvider>,
  )
  return userEvent.setup()
}
const bars = () => screen.getAllByTestId('bar')

describe('TrustScoreBars', () => {
  test.each([
    ['empty', summaryOf()],
    ['one check', summaryOf(40)],
    ['missing summary', undefined],
  ])('%s: message and no chart', (_, s) => {
    renderBars(s)
    expect(screen.getByRole('heading', { level: 2, name: 'Trust score for each check' })).toBeInTheDocument()
    expect(screen.getByText(/Higher is safer\. 100 means no sign of phishing was found, 0 means very likely phishing\./)).toBeInTheDocument()
    expect(screen.getByText('Check at least two links to compare trust scores here.')).toBeInTheDocument()
    expect(screen.queryByTestId('bar-chart')).not.toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
  })

  test('one bar per check in order, fixed 0-100 axis, reference line at 50, value labels', () => {
    renderBars(summaryOf(7, 96, 50))
    expect(bars().map((b) => b.textContent)).toEqual(['#1', '#2', '#3'])
    expect(screen.getByTestId('bar-chart')).toHaveAttribute('data-y', '0-100 0,25,50,75,100')
    expect(screen.getByTestId('reference')).toHaveAttribute('data-y', '50')
    // No label on the line: it overlapped the bars at narrow widths; the axis has the 50 tick.
    expect(screen.getByTestId('reference')).not.toHaveAttribute('data-label')
    expect(screen.getByText('The dashed line marks a trust score of 50.')).toBeInTheDocument()
    expect(bars()[0]).toHaveAttribute('data-label', 'value')
    expect(bars()[0]).toHaveAttribute('data-tooltip', '#1 site1.com/x: Likely phishing, trust score 7')
    expect(bars()[1]).toHaveAttribute('data-tooltip', '#2 site2.com/x: Likely legitimate, trust score 96')
  })

  test('the aria-label names the lowest and highest check', () => {
    renderBars(summaryOf(40, 5, 70, 96, 12))
    expect(screen.getByRole('img')).toHaveAccessibleName('Bar chart of trust scores for 5 checks. Lowest: check 2 at 5. Highest: check 4 at 96.')
  })

  test('on a tie the first check wins, and two checks read as plural', () => {
    renderBars(summaryOf(30, 90, 30, 90))
    expect(screen.getByRole('img')).toHaveAccessibleName('Bar chart of trust scores for 4 checks. Lowest: check 1 at 30. Highest: check 2 at 90.')
  })

  test('two equal checks: both lowest and highest are check 1', () => {
    renderBars(summaryOf(50, 50))
    expect(screen.getByRole('img')).toHaveAccessibleName('Bar chart of trust scores for 2 checks. Lowest: check 1 at 50. Highest: check 1 at 50.')
  })

  test('more than 12 checks: only the 12 most recent are charted and tabled, with a note', async () => {
    const scores = Array.from({ length: 15 }, (_, i) => (i * 7) % 101)
    const user = renderBars(summaryOf(...scores))
    expect(screen.getByText('Showing the 12 most recent of 15 checks.')).toBeInTheDocument()
    expect(bars().map((b) => b.textContent)).toEqual(Array.from({ length: 12 }, (_, i) => `#${i + 4}`))
    await user.click(screen.getByRole('button', { name: 'Show data as a table' }))
    const numbers = within(screen.getByRole('table')).getAllByRole('row').slice(1).map((r) => r.querySelector('td').textContent)
    expect(numbers).toEqual(Array.from({ length: 12 }, (_, i) => `${i + 4}`))
  })

  test('12 checks or fewer: no note', () => {
    renderBars(summaryOf(...Array(12).fill(60)))
    expect(bars()).toHaveLength(12)
    expect(screen.queryByText(/most recent/)).not.toBeInTheDocument()
  })

  test('the table toggle works and lists rows in order with verdict words and plain-text links', async () => {
    const js = 'javascript:alert(document.domain)'
    const user = renderBars(summariseSession([entry(1, 7, js), entry(2, 96, 'https://www.wikipedia.org/wiki/Phishing')]))
    const toggle = screen.getByRole('button', { name: 'Show data as a table' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(toggle).toHaveAccessibleName('Hide table')
    const table = screen.getByRole('table')
    expect(document.getElementById(toggle.getAttribute('aria-controls'))).toContainElement(table)
    expect(within(table).getAllByRole('row').map((r) => Array.from(r.querySelectorAll('th, td'), (c) => c.textContent))).toEqual([
      ['#', 'Link', 'Result', 'Trust score'],
      ['1', js, 'Likely phishing', '7'],
      ['2', 'https://www.wikipedia.org/wiki/Phishing', 'Likely legitimate', '96'],
    ])
    expect(table.querySelector('a')).toBeNull()
    expect(within(table).queryByRole('link')).not.toBeInTheDocument()
    expect(document.querySelector('a')).toBeNull()

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
  })

  test('bar colours follow the verdict and reach 3:1 on the page background', () => {
    renderBars(summaryOf(7, 96))
    const colours = bars().map((b) => b.dataset.color)
    expect(colours).toEqual([theme.palette.phishing.main, theme.palette.legitimate.main])
    for (const c of colours) {
      expect(getContrastRatio(c, theme.palette.background.default), c).toBeGreaterThanOrEqual(3)
    }
  })
})
