import { getContrastRatio } from '@mui/material/styles'
import { expect, test } from 'vitest'
import theme from './theme.js'

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
