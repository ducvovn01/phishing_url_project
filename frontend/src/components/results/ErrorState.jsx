import { Alert, AlertTitle, Button, Typography } from '@mui/material'

const TITLES = {
  validation_error: 'Check the URL',
  service_busy: 'The checker is busy',
  backend_unavailable: "We can't reach the checker",
  payload_too_large: 'That request was too large',
}

// Shows only code-derived title, message, request_id and retry wait. Never the error object, stack or details.
export default function ErrorState({ error, onRetry, titleRef }) {
  const wait = error.code === 'service_busy' && Number.isFinite(error.retryAfterSeconds) ? error.retryAfterSeconds : null

  return (
    <Alert
      severity="error"
      role="alert"
      action={
        <Button color="inherit" size="small" onClick={onRetry}>
          Try again
        </Button>
      }
    >
      <AlertTitle
        component="h2"
        ref={titleRef}
        tabIndex={-1}
        sx={{ '&:focus': { outline: '2px solid', outlineColor: 'currentColor', outlineOffset: 2 } }}
      >
        {TITLES[error.code] ?? 'Something went wrong'}
      </AlertTitle>
      <Typography>{error.message}</Typography>
      {wait !== null && <Typography>Please wait about {wait} seconds, then try again.</Typography>}
      {error.request_id && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          Reference: {error.request_id}
        </Typography>
      )}
    </Alert>
  )
}
