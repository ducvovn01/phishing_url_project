import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ThemeProvider } from '@mui/material'
import { getContrastRatio } from '@mui/material/styles'
import { describe, expect, test, vi } from 'vitest'
import theme from '../../theme.js'
import VerdictDonut from './VerdictDonut.jsx'

// jsdom has no SVG layout, so the stub renders the slices the real chart would get.
vi.mock('@mui/x-charts/PieChart', () => ({
  PieChart: ({ series }) => (
    <div data-testid="pie-chart" data-inner-radius={series[0].innerRadius}>
      {series[0].data.map((d) => (
        <span key={d.id} data-testid="slice" data-id={d.id} data-value={d.value} data-color={d.color} />
      ))}
    </div>
  ),
}))

const summary = (phishingCount, legitimateCount, phishingPercent, legitimatePercent) => ({
  total: phishingCount + legitimateCount,
  phishingCount,
  legitimateCount,
  phishingPercent,
  legitimatePercent,
  rows: [],
})

function renderDonut(s) {
  render(
    <ThemeProvider theme={theme}>
      <VerdictDonut summary={s} />
    </ThemeProvider>,
  )
  return userEvent.setup()
}
const legend = () => within(screen.getByRole('img')).getAllByRole('listitem').map((li) => li.textContent)
const slices = () => screen.getAllByTestId('slice').map((s) => [s.dataset.id, Number(s.dataset.value)])

describe('VerdictDonut', () => {
  test.each([
    ['empty', summary(0, 0, 0, 0)],
    ['one check', summary(1, 0, 100, 0)],
    ['missing summary', undefined],
  ])('%s: message and no chart', (_, s) => {
    renderDonut(s)
    expect(screen.getByRole('heading', { level: 2, name: 'Results at a glance' })).toBeInTheDocument()
    expect(screen.getByText('Check at least two links to compare results here.')).toBeInTheDocument()
    expect(screen.queryByTestId('pie-chart')).not.toBeInTheDocument()
    expect(screen.queryByRole('img')).not.toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })

  test('mixed: a donut with both slices, legend, centre text and summary', () => {
    renderDonut(summary(4, 2, 67, 33))
    expect(screen.getByTestId('pie-chart')).toHaveAttribute('data-inner-radius', '60%')
    expect(slices()).toEqual([
      ['phishing', 4],
      ['legitimate', 2],
    ])
    expect(legend()).toEqual(['Likely phishing: 4 (67%)', 'Likely legitimate: 2 (33%)'])
    expect(screen.getByText('6 checks')).toHaveAttribute('aria-hidden', 'true')
    expect(screen.getByRole('img')).toHaveAccessibleName('Donut chart of 6 checks: 4 likely phishing (67%), 2 likely legitimate (33%).')
  })

  test('all phishing: the zero legitimate slice is left out', () => {
    renderDonut(summary(3, 0, 100, 0))
    expect(slices()).toEqual([['phishing', 3]])
    expect(legend()).toEqual(['Likely phishing: 3 (100%)'])
    expect(screen.getByRole('img')).toHaveAccessibleName('Donut chart of 3 checks: 3 likely phishing (100%).')
  })

  test('all legitimate: the zero phishing slice is left out', () => {
    renderDonut(summary(0, 2, 0, 100))
    expect(slices()).toEqual([['legitimate', 2]])
    expect(legend()).toEqual(['Likely legitimate: 2 (100%)'])
    expect(screen.getByRole('img')).toHaveAccessibleName('Donut chart of 2 checks: 2 likely legitimate (100%).')
  })

  test('the table toggle works and lists counts and shares', async () => {
    const user = renderDonut(summary(1, 2, 33, 67))
    const toggle = screen.getByRole('button', { name: 'Show data as a table' })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(toggle).toHaveAccessibleName('Hide table')
    const table = screen.getByRole('table')
    expect(document.getElementById(toggle.getAttribute('aria-controls'))).toContainElement(table)
    // A narrow screen scrolls the table inside its own region, which keyboard users can focus.
    const region = screen.getByRole('region', { name: 'Results data table' })
    expect(region).toContainElement(table)
    expect(region).toHaveAttribute('tabindex', '0')
    expect(getComputedStyle(region).overflowX).toBe('auto')
    const rows = within(table)
      .getAllByRole('row')
      .map((r) => Array.from(r.querySelectorAll('th, td'), (c) => c.textContent))
    expect(rows).toEqual([
      ['Result', 'Checks', 'Share'],
      ['Likely phishing', '1', '33%'],
      ['Likely legitimate', '2', '67%'],
    ])

    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('table')).not.toBeInTheDocument()
  })

  test('slice colours are the semantic palette and reach 3:1 on the page background', () => {
    renderDonut(summary(4, 2, 67, 33))
    const colours = screen.getAllByTestId('slice').map((s) => s.dataset.color)
    expect(colours).toEqual([theme.palette.phishing.main, theme.palette.legitimate.main])
    for (const c of colours) {
      expect(getContrastRatio(c, theme.palette.background.default), c).toBeGreaterThanOrEqual(3)
    }
  })
})
