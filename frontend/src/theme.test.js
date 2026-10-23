import { createElement } from 'react'
import { render, screen } from '@testing-library/react'
import { Alert, CssBaseline, ThemeProvider } from '@mui/material'
import { decomposeColor, getContrastRatio, lighten } from '@mui/material/styles'
import { expect, test } from 'vitest'
import theme from './theme.js'

/** Flatten a colour with alpha onto an opaque background, so the ratio is what the eye sees. */
function over(colour, background) {
  const { values: [r, g, b, a = 1] } = decomposeColor(colour)
  const { values: [br, bg, bb] } = decomposeColor(background)
  const mix = (f, k) => Math.round(f * a + k * (1 - a))
  return `rgb(${mix(r, br)}, ${mix(g, bg)}, ${mix(b, bb)})`
}

const TEXT = 4.5
const LARGE_OR_GRAPHIC = 3

test('every text and background pair reaches 4.5:1', () => {
  const { palette: p } = theme
  const pairs = [
    [p.text.primary, p.background.default],
    [p.text.secondary, p.background.default],
    [p.text.primary, p.background.paper],
    [p.text.secondary, p.background.paper],
    ...['primary', 'phishing', 'legitimate'].flatMap((c) => [
      [p[c].main, p.background.default],
      [p[c].contrastText, p[c].main],
    ]),
    ...['phishing', 'legitimate'].flatMap((c) => [
      [p.text.primary, p[c].tint],
      [p.text.secondary, p[c].tint],
      [p[c].main, p[c].tint],
    ]),
  ]
  for (const [fg, bg] of pairs) {
    expect(getContrastRatio(fg, bg), `${fg} on ${bg}`).toBeGreaterThanOrEqual(4.5)
  }
})

test('every component colour pair meets its limit (text 4.5:1, large text and graphics 3:1)', () => {
  const { palette: p } = theme
  const page = p.background.default
  const focus = '#212121' // MuiButtonBase focus outline in theme.js
  const disabledBg = over(p.action.disabledBackground, page)
  const pairs = [
    // Verdict banners: heading, confidence and note text, icon and left border on the tint.
    ...['phishing', 'legitimate'].flatMap((c) => [
      [`verdict text on ${c} tint`, p.text.primary, p[c].tint, TEXT],
      [`verdict icon and border on ${c} tint`, p[c].main, p[c].tint, LARGE_OR_GRAPHIC],
      [`advice note text on ${c} tint`, p.text.primary, p[c].tint, TEXT],
      [`signal chip text on ${c} tint`, p.text.primary, p[c].tint, TEXT],
      [`signal chip icon on ${c} tint`, p[c].main, p[c].tint, LARGE_OR_GRAPHIC],
      [`highlight underline on ${c} tint`, p[c].main, p[c].tint, LARGE_OR_GRAPHIC],
      [`selected highlight outline on ${c} tint`, p.text.primary, p[c].tint, LARGE_OR_GRAPHIC],
      [`focus outline on ${c} tint`, focus, p[c].tint, LARGE_OR_GRAPHIC],
      [`chart bar ${c} on page`, p[c].main, page, LARGE_OR_GRAPHIC],
      [`faded chart bar ${c} on page`, lighten(p[c].main, 0.35), page, LARGE_OR_GRAPHIC],
    ]),
    // Signal cards.
    ['signal card text on paper', p.text.primary, p.background.paper, TEXT],
    ['signal card selected border on paper', p.text.primary, p.background.paper, LARGE_OR_GRAPHIC],
    ['quoted signal text on grey.100', p.text.primary, p.grey[100], TEXT],
    // Tinted notes: the loading tip.
    ['loading tip text on grey.100', p.text.primary, p.grey[100], TEXT],
    ['focus outline on grey.100', focus, p.grey[100], LARGE_OR_GRAPHIC],
    // Form: helper, error, focused field border, disabled submit.
    ['helper text on page', p.text.secondary, page, TEXT],
    ['error helper text on page', p.error.main, page, TEXT],
    ['focused field border on page', p.primary.main, page, LARGE_OR_GRAPHIC],
    ['disabled button text on disabled background', over(p.action.disabled, disabledBg), disabledBg, TEXT],
    // Header and navigation.
    ['header text on app bar', p.primary.contrastText, p.primary.main, TEXT],
    ['nav focus outline (currentColor) on app bar', p.primary.contrastText, p.primary.main, LARGE_OR_GRAPHIC],
    ['skip link on paper', p.primary.main, p.background.paper, TEXT],
    // Charts: axis and bar labels, donut centre, reference lines.
    ['chart axis and bar labels on page', p.text.primary, page, TEXT],
    ['chart reference line (trust score) on page', p.text.secondary, page, LARGE_OR_GRAPHIC],
    ['chart zero line (weights) on page', p.text.primary, page, LARGE_OR_GRAPHIC],
    // The focus indicator on plain backgrounds.
    ['focus outline on page', focus, page, LARGE_OR_GRAPHIC],
  ]
  for (const [name, fg, bg, limit] of pairs) {
    expect(getContrastRatio(fg, bg), name).toBeGreaterThanOrEqual(limit)
  }
})

test('the error alert text, icon and focus outline meet their limits as rendered', () => {
  render(createElement(ThemeProvider, { theme }, createElement(Alert, { severity: 'error' }, 'message')))
  const { color, backgroundColor } = getComputedStyle(screen.getByRole('alert'))
  expect(getContrastRatio(color, backgroundColor), 'alert text').toBeGreaterThanOrEqual(TEXT)
  // ErrorState's title outline is currentColor; the button's is the theme focus colour.
  expect(getContrastRatio('#212121', backgroundColor), 'focus outline on alert').toBeGreaterThanOrEqual(LARGE_OR_GRAPHIC)
  expect(getContrastRatio(theme.palette.error.main, backgroundColor), 'alert icon').toBeGreaterThanOrEqual(LARGE_OR_GRAPHIC)
})

test('CssBaseline turns animations and transitions off for prefers-reduced-motion', () => {
  render(createElement(ThemeProvider, { theme }, createElement(CssBaseline)))
  const css = Array.from(document.querySelectorAll('style'), (s) => s.textContent).join(' ')
  expect(css).toMatch(/@media \(prefers-reduced-motion: ?reduce\)/)
  expect(css).toMatch(/animation-duration: ?0\.01ms ?!important/)
  expect(css).toMatch(/transition-duration: ?0\.01ms ?!important/)
})
