import { Typography } from '@mui/material'
import usePageTitle from '../hooks/usePageTitle.js'

export default function SessionPage() {
  usePageTitle('This session')
  return <Typography variant="h1">This session</Typography>
}
