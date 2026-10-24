import { Button, Stack, Typography } from '@mui/material'
import { Link as RouterLink } from 'react-router-dom'
import usePageTitle from '../hooks/usePageTitle.js'

export default function NotFoundPage() {
  usePageTitle('Page not found')
  return (
    <Stack spacing={2} sx={{ alignItems: 'flex-start' }}>
      <Typography variant="h1">Page not found</Typography>
      <Typography>We could not find the page you asked for.</Typography>
      <Button variant="contained" component={RouterLink} to="/">
        Back to the URL checker
      </Button>
    </Stack>
  )
}
