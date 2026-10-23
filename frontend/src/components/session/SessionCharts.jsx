import { Box } from '@mui/material'
import TrustScoreBars from './TrustScoreBars.jsx'
import VerdictDonut from './VerdictDonut.jsx'

/** Both session charts: side by side on a wide screen (donut narrower), stacked on a phone. */
export default function SessionCharts({ summary }) {
  return (
    <Box
      sx={{
        display: 'grid',
        gap: 3,
        alignItems: 'start',
        gridTemplateColumns: { xs: 'minmax(0, 1fr)', md: 'minmax(0, 2fr) minmax(0, 3fr)' },
      }}
    >
      <VerdictDonut summary={summary} />
      <TrustScoreBars summary={summary} />
    </Box>
  )
}
