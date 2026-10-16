import { useState } from 'react'
import { Box, Stack, Typography } from '@mui/material'
import UrlForm from '../components/UrlForm.jsx'
import usePageTitle from '../hooks/usePageTitle.js'

export default function HomePage() {
  usePageTitle('Check a URL')
  // Temporary: Task E replaces this with the real analysis call.
  const [submitted, setSubmitted] = useState(null)

  return (
    <Stack spacing={4}>
      <Box>
        <Typography variant="h1" gutterBottom>
          Check a link before you click it
        </Typography>
        <Typography>
          Paste a web address and we will tell you whether it looks like phishing. It takes a few seconds.
        </Typography>
      </Box>

      <Box>
        <UrlForm onSubmit={setSubmitted} onClear={() => setSubmitted(null)} />
        {submitted !== null && <Typography sx={{ mt: 2 }}>Ready to analyse: {submitted}</Typography>}
      </Box>

      <Box component="section" aria-labelledby="how-it-works">
        <Typography variant="h2" id="how-it-works" gutterBottom>
          How it works
        </Typography>
        <Box component="ol" sx={{ pl: 3, my: 1 }}>
          <li>Paste a link.</li>
          <li>We read only the text of the link and never open it.</li>
          <li>You get a verdict, a trust score and the parts that looked suspicious.</li>
        </Box>
        <Typography variant="body2" color="text.secondary">
          Trust score: 100 means no sign of phishing was found, 0 means very likely phishing.
        </Typography>
      </Box>
    </Stack>
  )
}
