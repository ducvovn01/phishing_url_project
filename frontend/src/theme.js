import { createTheme } from '@mui/material/styles'

// Solid hex colours (no alpha) so contrast ratios are exact; theme.test.js checks every pair is 4.5:1 or better.
const base = createTheme({
  palette: {
    mode: 'light',
    contrastThreshold: 4.5,
    primary: { main: '#1565c0' },
    text: { primary: '#212121', secondary: '#555555' },
    background: { default: '#ffffff', paper: '#ffffff' },
  },
  typography: {
    fontFamily:
      'system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
    h1: { fontSize: '2rem', fontWeight: 600, lineHeight: 1.25 },
    h2: { fontSize: '1.5rem', fontWeight: 600, lineHeight: 1.3 },
    h3: { fontSize: '1.25rem', fontWeight: 600, lineHeight: 1.4 },
    body1: { fontSize: '1rem', lineHeight: 1.5 },
    body2: { fontSize: '0.875rem', lineHeight: 1.5 },
    button: { textTransform: 'none', fontWeight: 600 },
  },
  spacing: 8,
  shape: { borderRadius: 8 },
})

const theme = createTheme(base, {
  palette: {
    phishing: base.palette.augmentColor({ color: { main: '#b71c1c' }, name: 'phishing' }),
    legitimate: base.palette.augmentColor({ color: { main: '#1b5e20' }, name: 'legitimate' }),
  },
})

export default theme
