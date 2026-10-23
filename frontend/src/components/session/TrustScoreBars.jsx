import { useId, useState } from 'react'
import { Box, Button, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import { useTheme } from '@mui/material/styles'
import { BarChart } from '@mui/x-charts/BarChart'
import { ChartsReferenceLine } from '@mui/x-charts/ChartsReferenceLine'
import { verdictText } from '../../content/verdictText.js'

// More bars than this get too thin to read on a phone.
const MAX_BARS = 12
const HEIGHT = 280

function summary(rows) {
  // Strict comparisons, so on a tie the first (oldest) check wins.
  const lowest = rows.reduce((a, b) => (b.trustScore < a.trustScore ? b : a))
  const highest = rows.reduce((a, b) => (b.trustScore > a.trustScore ? b : a))
  return `Bar chart of trust scores for ${rows.length} checks. Lowest: check ${lowest.number} at ${lowest.trustScore}. Highest: check ${highest.number} at ${highest.trustScore}.`
}

/** Trust score per check, oldest first. `summary` comes from summariseSession. */
export default function TrustScoreBars({ summary: session }) {
  const theme = useTheme()
  const tableId = useId()
  const [showTable, setShowTable] = useState(false)
  const allRows = session?.rows ?? []
  const rows = allRows.slice(-MAX_BARS)
  const byNumber = new Map(rows.map((r) => [r.number, r]))

  return (
    <Box component="section" aria-labelledby={`${tableId}-heading`}>
      <Typography component="h2" variant="h3" id={`${tableId}-heading`} gutterBottom>
        Trust score for each check
      </Typography>
      <Typography variant="body2" gutterBottom>
        Higher is safer. 100 means no sign of phishing was found, 0 means very likely phishing.
      </Typography>
      <Typography variant="body2" gutterBottom>
        The dashed line marks a trust score of 50.
      </Typography>

      {allRows.length < 2 ? (
        <Typography>Check at least two links to compare trust scores here.</Typography>
      ) : (
        <>
          {allRows.length > MAX_BARS && (
            <Typography variant="body2">
              Showing the {MAX_BARS} most recent of {allRows.length} checks.
            </Typography>
          )}
          {/* An <img> element cannot wrap the chart's SVG, so the role is the only way to name it as one image. */}
          {/* oxlint-disable-next-line jsx-a11y/prefer-tag-over-role */}
          <Box role="img" aria-label={summary(rows)} sx={{ width: '100%', minWidth: 0 }}>
            {/* No width: the chart fills its container. No skipAnimation: x-charts already honours prefers-reduced-motion. */}
            <BarChart
              height={HEIGHT}
              hideLegend
              xAxis={[
                {
                  scaleType: 'band',
                  data: rows.map((r) => r.number),
                  valueFormatter: (n, ctx) => (ctx.location === 'tooltip' ? `#${n} ${byNumber.get(n)?.fullLabel ?? ''}` : `#${n}`),
                },
              ]}
              yAxis={[{ min: 0, max: 100, tickInterval: [0, 25, 50, 75, 100], width: 32 }]}
              series={[
                {
                  data: rows.map((r) => r.trustScore),
                  colorGetter: ({ dataIndex }) => theme.palette[rows[dataIndex].verdict === 'phishing' ? 'phishing' : 'legitimate'].main,
                  valueFormatter: (v, { dataIndex }) => `${verdictText(rows[dataIndex].verdict)}, trust score ${v}`,
                  barLabel: 'value',
                  barLabelPlacement: 'outside',
                },
              ]}
            >
              <ChartsReferenceLine y={50} lineStyle={{ stroke: theme.palette.text.secondary, strokeDasharray: '4 4' }} />
            </BarChart>
          </Box>

          <Button variant="text" aria-expanded={showTable} aria-controls={tableId} onClick={() => setShowTable((v) => !v)} sx={{ mt: 1 }}>
            {showTable ? 'Hide table' : 'Show data as a table'}
          </Button>
          <Box
            component="section"
            id={tableId}
            hidden={!showTable}
            aria-label="Trust scores data table"
            tabIndex={0}
            sx={{ overflowX: 'auto', '&:focus-visible': { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: 2 } }}
          >
            {showTable && (
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell component="th" scope="col">#</TableCell>
                    <TableCell component="th" scope="col">Link</TableCell>
                    <TableCell component="th" scope="col">Result</TableCell>
                    <TableCell component="th" scope="col" align="right">Trust score</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow key={r.id}>
                      <TableCell>{r.number}</TableCell>
                      {/* Plain text only: a submitted URL is never turned into a link. */}
                      <TableCell sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere', minWidth: 160 }}>{r.fullLabel}</TableCell>
                      <TableCell>{verdictText(r.verdict)}</TableCell>
                      <TableCell align="right">{r.trustScore}</TableCell>
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
