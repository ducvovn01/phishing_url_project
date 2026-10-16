import { Box, Typography } from '@mui/material'

// Contract section 6.1: submitted_url is plain text only. Never a link and never used for navigation.
export default function SubmittedUrl({ url }) {
  return (
    <Typography>
      <Box component="span" sx={{ fontWeight: 600 }}>
        Checked:
      </Box>{' '}
      <Box component="span" sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>
        {url}
      </Box>
    </Typography>
  )
}
