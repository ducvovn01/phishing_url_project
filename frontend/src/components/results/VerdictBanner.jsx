import { Box, Stack, Typography } from '@mui/material'
import GppBadIcon from '@mui/icons-material/GppBad'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import { verdictText } from '../../content/verdictText.js'

export default function VerdictBanner({ result, headingRef }) {
  const tone = result.label === 'phishing' ? 'phishing' : 'legitimate'
  const Icon = tone === 'phishing' ? GppBadIcon : VerifiedUserIcon

  return (
    <Box
      component="section"
      aria-labelledby="verdict-heading"
      sx={{ bgcolor: `${tone}.tint`, borderLeft: 8, borderColor: `${tone}.main`, borderRadius: 1, p: { xs: 2, md: 3 } }}
    >
      <Stack direction="row" spacing={2} sx={{ alignItems: 'center' }}>
        <Icon aria-hidden="true" sx={{ fontSize: { xs: 48, md: 64 }, color: `${tone}.main` }} />
        <Box>
          <Typography
            component="h2"
            variant="h3"
            id="verdict-heading"
            ref={headingRef}
            tabIndex={-1}
            sx={{
              fontSize: { xs: '1.75rem', md: '2.5rem' },
              fontWeight: 700,
              lineHeight: 1.2,
              color: 'text.primary',
              '&:focus': { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: '4px' },
            }}
          >
            {verdictText(result.label)}
          </Typography>
          <Typography sx={{ fontSize: { xs: '1.5rem', md: '2rem' }, fontWeight: 700, color: 'text.primary' }}>
            {Math.round(result.confidence * 100)}% confidence
          </Typography>
        </Box>
      </Stack>
      <Typography sx={{ mt: 1 }}>This is an estimate based only on the text of the link.</Typography>
    </Box>
  )
}
