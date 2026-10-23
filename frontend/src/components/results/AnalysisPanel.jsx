import { Box, ButtonBase, Chip, Typography } from '@mui/material'
import TrendingDownIcon from '@mui/icons-material/TrendingDown'
import TrendingUpIcon from '@mui/icons-material/TrendingUp'
import { segmentUrl } from '../../lib/segmentUrl.js'

// Each direction gets its own underline style as well as its tint, so meaning never relies on colour.
const markSx = {
  phishing: { bgcolor: 'phishing.tint', textDecoration: 'underline wavy', textDecorationColor: (t) => t.palette.phishing.main },
  legitimate: { bgcolor: 'legitimate.tint', textDecoration: 'underline double', textDecorationColor: (t) => t.palette.legitimate.main },
}
const baseMarkSx = { color: 'text.primary', textDecorationThickness: 2, textUnderlineOffset: 4, borderRadius: 0.5 }
const selectedMarkSx = { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: 1, fontWeight: 700 }

const CHIP = {
  phishing: { label: 'Raises risk', Icon: TrendingUpIcon },
  legitimate: { label: 'Lowers risk', Icon: TrendingDownIcon },
}

function Mark({ direction, selected, children }) {
  return (
    <Box component="mark" sx={{ ...baseMarkSx, ...markSx[direction], ...(selected ? selectedMarkSx : {}) }}>
      {children}
    </Box>
  )
}

// Controlled: the parent owns the selection. Selecting the selected signal again deselects it.
export default function AnalysisPanel({ result, selectedId, onSelect }) {
  const toggle = (id) => onSelect(selectedId === id ? null : id)

  const segments = segmentUrl(result.analysed_url, result.signals)

  return (
    <Box
      component="section"
      aria-label="Analysis details"
      tabIndex={0}
      sx={{
        maxHeight: { md: '60vh' },
        overflow: { md: 'auto' },
        pr: { md: 1 },
        '&:focus-visible': { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: 2 },
      }}
    >
      <Typography component="h2" variant="h3" gutterBottom>
        Why this result
      </Typography>

      <Typography sx={{ fontFamily: 'monospace', fontSize: '1.125rem', overflowWrap: 'anywhere', lineHeight: 2 }}>
        {segments.map((s, i) =>
          s.signalId === null ? (
            <span key={i}>{s.text}</span>
          ) : (
            <Mark key={i} direction={s.direction} selected={s.signalId === selectedId}>
              {s.text}
            </Mark>
          ),
        )}
      </Typography>

      <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2, my: 1 }}>
        <Typography variant="body2">
          <Mark direction="phishing">abc</Mark> wavy underline: raises risk
        </Typography>
        <Typography variant="body2">
          <Mark direction="legitimate">abc</Mark> double underline: lowers risk
        </Typography>
      </Box>

      {result.signals.length === 0 ? (
        <Typography>No single part of the link stood out.</Typography>
      ) : (
        <Box component="ul" sx={{ listStyle: 'none', p: 0, m: 0, display: 'grid', gap: 1 }}>
          {result.signals.map((signal) => {
            const { label, Icon } = CHIP[signal.direction]
            const selected = signal.id === selectedId
            return (
              <li key={signal.id}>
                {/* A native button gives Enter and Space for free. */}
                <ButtonBase
                  aria-pressed={selected}
                  onClick={() => toggle(signal.id)}
                  sx={{
                    display: 'block',
                    width: '100%',
                    textAlign: 'left',
                    p: 1.5,
                    border: selected ? 2 : 1,
                    borderColor: selected ? 'text.primary' : 'divider',
                    borderRadius: 1,
                  }}
                >
                  <Box component="span" sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 1 }}>
                    <Typography component="span" sx={{ fontWeight: 600 }}>
                      {signal.title}
                    </Typography>
                    <Chip
                      component="span"
                      size="small"
                      label={label}
                      icon={<Icon aria-hidden="true" />}
                      sx={{
                        bgcolor: `${signal.direction}.tint`,
                        color: 'text.primary',
                        '& .MuiChip-icon': { color: `${signal.direction}.main` },
                      }}
                    />
                  </Box>
                  {signal.text !== null && (
                    <Box
                      component="code"
                      sx={{ display: 'inline-block', mt: 0.5, px: 0.5, bgcolor: 'grey.100', fontFamily: 'monospace', overflowWrap: 'anywhere' }}
                    >
                      &ldquo;{signal.text}&rdquo;
                    </Box>
                  )}
                  <Typography component="span" variant="body2" sx={{ display: 'block', mt: 0.5 }}>
                    {signal.explanation}
                  </Typography>
                </ButtonBase>
              </li>
            )
          })}
        </Box>
      )}
    </Box>
  )
}
