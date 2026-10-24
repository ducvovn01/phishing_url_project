import { useId, useState } from 'react'
import { Box, Button, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import { PieChart } from '@mui/x-charts/PieChart'

const SIZE = 220
const checks = (n) => (n === 1 ? '1 check' : `${n} checks`)

/** Share of phishing and legitimate verdicts in this session. `summary` comes from summariseSession. */
export default function VerdictDonut({ summary }) {
  const theme = useTheme()
  const tableId = useId()
  const [showTable, setShowTable] = useState(false)
  const total = summary?.total ?? 0

  const slices = [
    { id: 'phishing', label: 'Likely phishing', count: summary?.phishingCount ?? 0, percent: summary?.phishingPercent ?? 0 },
    { id: 'legitimate', label: 'Likely legitimate', count: summary?.legitimateCount ?? 0, percent: summary?.legitimatePercent ?? 0 },
  ]
    .filter((s) => s.count > 0)
    .map((s) => ({ ...s, color: theme.palette[s.id].main, text: `${s.label}: ${s.count} (${s.percent}%)` }))
  const ariaLabel = `Donut chart of ${checks(total)}: ${slices.map((s) => `${s.count} ${s.label.toLowerCase()} (${s.percent}%)`).join(', ')}.`

  return (
    <Box component="section" aria-labelledby={`${tableId}-heading`}>
      <Typography component="h2" variant="h3" id={`${tableId}-heading`} gutterBottom>
        Results at a glance
      </Typography>

      {total < 2 ? (
        <Typography>Check at least two links to compare results here.</Typography>
      ) : (
        <>
          {/* An <img> element cannot wrap the chart's SVG, so the role is the only way to name it as one image. */}
          {/* oxlint-disable-next-line jsx-a11y/prefer-tag-over-role */}
          <Box role="img" aria-label={ariaLabel} sx={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 3 }}>
            <Box sx={{ position: 'relative', width: '100%', maxWidth: SIZE, aspectRatio: '1' }}>
              {/* No width or height: the chart fills this square box, which shrinks with the container. */}
              {/* No skipAnimation: x-charts already skips animation when the user prefers reduced motion. */}
              <PieChart
                hideLegend
                margin={0}
                series={[{ data: slices.map(({ id, count, label, color }) => ({ id, value: count, label, color })), innerRadius: '60%', paddingAngle: 2 }]}
              />
              {/* Inside role="img", so screen readers get the total from the aria-label only. */}
              <Box
                aria-hidden="true"
                sx={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', pointerEvents: 'none', typography: 'h3' }}
              >
                {checks(total)}
              </Box>
            </Box>
            <Box component="ul" sx={{ listStyle: 'none', p: 0, m: 0, display: 'grid', gap: 1 }}>
              {slices.map((s) => (
                <Box component="li" key={s.id} sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                  <Box aria-hidden="true" sx={{ width: 16, height: 16, borderRadius: 0.5, bgcolor: s.color, flexShrink: 0 }} />
                  <span>{s.text}</span>
                </Box>
              ))}
            </Box>
          </Box>

          <Button variant="text" aria-expanded={showTable} aria-controls={tableId} onClick={() => setShowTable((v) => !v)} sx={{ mt: 1 }}>
            {showTable ? 'Hide table' : 'Show data as a table'}
          </Button>
          <Box
            component="section"
            id={tableId}
            hidden={!showTable}
            aria-label="Results data table"
            tabIndex={0}
            sx={{ overflowX: 'auto', '&:focus-visible': { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: 2 } }}
          >
            {showTable && (
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell component="th" scope="col">Result</TableCell>
                    <TableCell component="th" scope="col" align="right">Checks</TableCell>
                    <TableCell component="th" scope="col" align="right">Share</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {slices.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell>{s.label}</TableCell>
                      <TableCell align="right">{s.count}</TableCell>
                      <TableCell align="right">{s.percent}%</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </Box>
        </>
      )}
    </Box>
  )
}
