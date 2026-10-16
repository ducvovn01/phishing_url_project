import { Typography } from '@mui/material'
import usePageTitle from '../hooks/usePageTitle.js'

export default function HomePage() {
  usePageTitle('Check a URL')
  return <Typography variant="h1">Check a URL</Typography>
}
