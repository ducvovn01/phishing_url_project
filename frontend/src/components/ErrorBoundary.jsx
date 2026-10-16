import { Component } from 'react'
import { Button, Stack, Typography } from '@mui/material'
import usePageTitle from '../hooks/usePageTitle.js'

function ErrorFallback() {
  usePageTitle('Something went wrong')
  return (
    <Stack spacing={2} sx={{ alignItems: 'flex-start' }}>
      <Typography variant="h1">Something went wrong</Typography>
      <Typography>The page could not be shown. Try reloading, or go back to the home page.</Typography>
      <Stack direction="row" spacing={2}>
        <Button variant="contained" onClick={() => window.location.reload()}>
          Reload
        </Button>
        {/* Full page load so the boundary's error state is cleared. */}
        <Button variant="outlined" href="/">
          Back to home
        </Button>
      </Stack>
    </Stack>
  )
}

export default class ErrorBoundary extends Component {
  state = { hasError: false }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  componentDidCatch(error, info) {
    // Details go to the console only, never to the page.
    console.error(error, info.componentStack)
  }

  render() {
    return this.state.hasError ? <ErrorFallback /> : this.props.children
  }
}
