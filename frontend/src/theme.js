import { createTheme } from '@mui/material/styles'

// Solid hex colours (no alpha) so contrast ratios are exact; theme.test.js checks every pair is 4.5:1 or better.
const base = createTheme({
  palette: {
    mode: 'light',
    contrastThreshold: 4.5,
    primary: { main: '#1565c0' },
    text: { primary: '#212121', secondary: '#555555' },
    background: { default: '#ffffff', paper: '#ffffff' },
    // Disabled text (the "Analysing..." button) at 4.5:1 on the disabled background; MUI's default is about 1.8:1.
    action: { disabled: '#555555' },
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
  components: {
    // MUI's default keyboard focus is only a faint ripple; give every button a clear outline.
    MuiButtonBase: {
      styleOverrides: {
        root: { '&.Mui-focusVisible': { outline: '2px solid #212121', outlineOffset: 2 } },
      },
    },
    // Links are not ButtonBase, so they need their own visible focus ring (currentColor is 4.5:1 or better).
    MuiLink: {
      styleOverrides: { root: { '&:focus-visible': { outline: '2px solid', outlineOffset: 2 } } },
    },
    // 44px touch targets on phones; MUI's small and medium buttons are 31px and 37px tall.
    MuiButton: {
      styleOverrides: { root: ({ theme }) => ({ [theme.breakpoints.down('sm')]: { minHeight: 44 } }) },
    },
    // Stops the spinners, ripples and transitions when the user asks for less motion.
    MuiCssBaseline: {
      styleOverrides: {
        '@media (prefers-reduced-motion: reduce)': {
          '*, *::before, *::after': {
            animationDuration: '0.01ms !important',
            animationIterationCount: '1 !important',
            transitionDuration: '0.01ms !important',
            scrollBehavior: 'auto !important',
          },
        },
      },
    },
  },
})

const theme = createTheme(base, {
  palette: {
    // tint: light background for verdicts, highlights and chips, always used with dark text.
    phishing: { ...base.palette.augmentColor({ color: { main: '#b71c1c' }, name: 'phishing' }), tint: '#fdecea' },
    legitimate: { ...base.palette.augmentColor({ color: { main: '#1b5e20' }, name: 'legitimate' }), tint: '#e8f5e9' },
  },
})

export default theme
