import { useEffect, useState } from 'react'
import { Box, CircularProgress, Stack, Typography, useMediaQuery } from '@mui/material'

const TIPS = [
  'Check the address bar, not the link text in a message.',
  'Banks and shops never ask for your password by email or text.',
  'Look for misspelt brand names, like paypa1 instead of paypal.',
  'A padlock only means the connection is encrypted, not that the site is honest.',
  'When in doubt, type the website address yourself instead of clicking.',
  'Urgent warnings like "your account will be closed" are a common phishing trick.',
]
const TIP_INTERVAL_MS = 5000

export default function LoadingState() {
  const reduceMotion = useMediaQuery('(prefers-reduced-motion: reduce)', { noSsr: true })
  const [tip, setTip] = useState(0)

  useEffect(() => {
    if (reduceMotion) return undefined
    const timer = setInterval(() => setTip((i) => (i + 1) % TIPS.length), TIP_INTERVAL_MS)
    return () => clearInterval(timer)
  }, [reduceMotion])

  return (
    <Stack spacing={1.5}>
      <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
        <CircularProgress size={28} aria-hidden="true" />
        {/* <output> has the implicit status role. */}
        <Typography component="output" sx={{ fontWeight: 600 }}>
          Analysing the link text...
        </Typography>
      </Stack>
      <Typography>Nothing is opened. Only the text is checked.</Typography>
      {/* Deliberately not a live region: a rotating tip must not interrupt screen readers. */}
      <Box sx={{ p: 2, borderRadius: 1, bgcolor: 'grey.100' }}>
        <Typography variant="body2">
          <Box component="span" sx={{ fontWeight: 600 }}>
            Tip:
          </Box>{' '}
          {TIPS[tip]}
        </Typography>
      </Box>
    </Stack>
  )
}
