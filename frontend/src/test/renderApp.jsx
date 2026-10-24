import { useEffect } from 'react'
import { render } from '@testing-library/react'
import { ThemeProvider } from '@mui/material'
import { MemoryRouter } from 'react-router-dom'
import App from '../App.jsx'
import { SessionProvider } from '../session/SessionContext.jsx'
import { useSession } from '../session/useSession.js'
import theme from '../theme.js'

/** Render the whole app at `path` with the same providers as main.jsx. `session.current` exposes the session context. */
export function renderApp(path = '/') {
  const session = { current: null }
  const capture = (value) => {
    session.current = value
  }
  function SessionProbe() {
    const value = useSession()
    useEffect(() => capture(value))
    return null
  }
  const utils = render(
    <ThemeProvider theme={theme}>
      <SessionProvider>
        <SessionProbe />
        <MemoryRouter initialEntries={[path]}>
          <App />
        </MemoryRouter>
      </SessionProvider>
    </ThemeProvider>,
  )
  return { ...utils, session }
}
