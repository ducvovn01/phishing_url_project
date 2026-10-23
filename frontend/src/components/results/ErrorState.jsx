import { Alert, AlertTitle, Button, Typography } from '@mui/material'

const TITLES = {
  validation_error: 'Check the URL',
  service_busy: 'The checker is busy',
  backend_unavailable: "We can't reach the checker",
  payload_too_large: 'That request was too large',
}

// Shows only code-derived title, message, request_id and retry wait. Never the error object, stack or details.
export default function ErrorState({ error, onRetry, titleRef }) {
  const wait = error.code === 'service_busy' && Number.isFinite(error.retryAfterSeconds) && error.retryAfterSeconds > 0 ? error.retryAfterSeconds : null

  return (
    <Alert
      severity="error"
      role="alert"
      // MUI's message container has overflow: auto, which clips the title's focus outline at the sides.
      sx={{ '& .MuiAlert-message': { overflow: 'visible' } }}
    >
      <AlertTitle
        component="h2"
        ref={titleRef}
        tabIndex={-1}
        sx={{
          display: 'inline-block',
          px: 0.5,
          '&:focus': { outline: '2px solid', outlineColor: 'currentColor', outlineOffset: '4px' },
        }}
      >
        {TITLES[error.code] ?? 'Something went wrong'}
      </AlertTitle>
      <Typography>{error.message}</Typography>
      {wait !== null && <Typography>Please wait about {wait === 1 ? '1 second' : `${wait} seconds`}, then try again.</Typography>}
      {error.request_id && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          Reference: {error.request_id}
        </Typography>
      )}
      <Button variant="outlined" size="small" color="inherit" onClick={onRetry} sx={{ mt: 2 }}>
        Try again
      </Button>
    </Alert>
  )
}
