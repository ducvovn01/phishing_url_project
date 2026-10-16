import { useId, useState } from 'react'
import { Box, Button, Typography } from '@mui/material'

const CLAMP_AFTER_CODE_POINTS = 80

const clampSx = { display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden' }

// Contract section 6.1: submitted_url is plain text only. Never a link and never used for navigation.
// Long URLs are clamped with CSS only, so the full text always stays in the DOM.
export default function SubmittedUrl({ url }) {
  const urlId = useId()
  const [expanded, setExpanded] = useState(false)
  const long = Array.from(url).length > CLAMP_AFTER_CODE_POINTS

  return (
    <Box>
      <Typography component="div">
        <Box component="span" sx={{ fontWeight: 600 }}>
          Checked:
        </Box>{' '}
        <Box
          component="span"
          id={urlId}
          sx={{
            fontFamily: 'monospace',
            overflowWrap: 'anywhere',
            ...(long ? { display: 'block' } : {}),
            ...(long && !expanded ? clampSx : {}),
          }}
        >
          {url}
        </Box>
      </Typography>
      {long && (
        <Button
          variant="text"
          size="small"
          aria-expanded={expanded}
          aria-controls={urlId}
          onClick={() => setExpanded((e) => !e)}
          sx={{ mt: 0.5, px: 0.5 }}
        >
          {expanded ? 'Show less' : 'Show full address'}
        </Button>
      )}
    </Box>
  )
}
