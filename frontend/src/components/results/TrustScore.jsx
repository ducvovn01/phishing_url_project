import { Box, Typography } from '@mui/material'
import { TRUST_SCORE_NOTE } from '../../content/trustScoreNote.js'

const ADVICE = {
  phishing: 'Do not open this link or enter any details. If it came in a message, delete it or report it.',
  legitimate:
    'No strong signs of phishing were found, but no check is perfect. Only enter personal details if you trust the sender and the address looks right.',
}

export default function TrustScore({ result }) {
  const score = result.trust_score
  const tone = result.label === 'phishing' ? 'phishing' : 'legitimate'

  return (
    <Box component="section" aria-labelledby="trust-heading">
      <Typography component="h2" variant="h3" id="trust-heading">
        Trust score
      </Typography>
      <Typography sx={{ my: 1 }}>
        <Box component="span" sx={{ fontSize: '1.75rem', fontWeight: 700, color: 'text.primary' }}>
          {score}
        </Box>{' '}
        out of 100
      </Typography>

      <Box sx={{ position: 'relative', mt: 3 }}>
        {/* Native <meter> (implicit role="meter"); its own fill is hidden so the gradient and marker show the value. */}
        <Box
          component="meter"
          min={0}
          max={100}
          value={score}
          aria-label="Trust score"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={score}
          aria-valuetext={`${score} out of 100`}
          sx={{
            display: 'block',
            width: '100%',
            height: 12,
            appearance: 'none',
            borderRadius: 1,
            border: 1,
            borderColor: 'text.secondary',
            background: (t) => `linear-gradient(to right, ${t.palette.phishing.main}, #f9a825, ${t.palette.legitimate.main})`,
            '&::-webkit-meter-bar': { background: 'transparent', border: 0, height: 12 },
            '&::-webkit-meter-optimum-value, &::-webkit-meter-suboptimum-value, &::-webkit-meter-even-less-good-value': {
              background: 'transparent',
            },
            '&::-moz-meter-bar': { background: 'transparent' },
          }}
        />
        {/* Marker at the value: a dark line with a triangle above, so it reads without colour. */}
        <Box
          aria-hidden="true"
          sx={{
            position: 'absolute',
            left: `${score}%`,
            top: -10,
            bottom: -4,
            width: 4,
            ml: '-2px',
            bgcolor: 'text.primary',
            borderRadius: 1,
            '&::before': {
              content: '""',
              position: 'absolute',
              top: -8,
              left: -6,
              borderLeft: '8px solid transparent',
              borderRight: '8px solid transparent',
              borderTop: '8px solid',
              borderTopColor: 'text.primary',
            },
          }}
        />
      </Box>
      <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 2, mt: 1 }}>
        <Typography variant="body2" color="text.secondary">
          0 very likely phishing
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'right' }}>
          100 no sign of phishing
        </Typography>
      </Box>
      <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
        {TRUST_SCORE_NOTE}
      </Typography>

      <Typography sx={{ mt: 2, p: 2, borderRadius: 1, bgcolor: `${tone}.tint`, color: 'text.primary' }}>
        {ADVICE[tone]}
      </Typography>
    </Box>
  )
}
