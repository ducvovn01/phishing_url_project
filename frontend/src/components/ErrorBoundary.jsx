import { Component } from 'react'
import { Button, Stack, Typography } from '@mui/material'
import { Link as RouterLink } from 'react-router-dom'
import usePageTitle from '../hooks/usePageTitle.js'

function ErrorFallback({ onReset }) {
  usePageTitle('Something went wrong')
  return (
    <Stack spacing={2} sx={{ alignItems: 'flex-start' }}>
      <Typography variant="h1">Something went wrong</Typography>
      <Typography>The page could not be shown. Try reloading, or go back to the home page.</Typography>
      <Stack direction="row" spacing={2}>
        <Button variant="contained" onClick={() => window.location.reload()}>
          Reload
        </Button>
        {/* Router link that also clears the boundary's error state. */}
        <Button variant="outlined" component={RouterLink} to="/" onClick={onReset}>
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

  reset = () => this.setState({ hasError: false })

  render() {
    return this.state.hasError ? <ErrorFallback onReset={this.reset} /> : this.props.children
  }
}
