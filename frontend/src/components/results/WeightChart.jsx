import { useId, useState } from 'react'
import { Box, Button, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import { lighten, useTheme } from '@mui/material/styles'
import { BarChart } from '@mui/x-charts/BarChart'
import { ChartsReferenceLine } from '@mui/x-charts/ChartsReferenceLine'
import { buildWeightChartData } from '../../lib/weightChartData.js'

const BAR_PX = 44
const AXIS_PX = 50
// Unselected bars when one is selected; still 3:1 on white (WeightChart.test.jsx checks it).
const FADE = 0.35
const DIRECTION_WORDS = { phishing: 'Raises risk', legitimate: 'Lowers risk' }

function barColor(theme, direction, faded) {
  const main = theme.palette[direction === 'legitimate' ? 'legitimate' : 'phishing'].main
  return faded ? lighten(main, FADE) : main
}

function summary(rows) {
  const top = rows[0]
  const verb = top.weight >= 0 ? 'raising' : 'lowering'
  const count = rows.length === 1 ? '1 signal' : `${rows.length} signals`
  return `Bar chart of ${count}. The largest is ${top.fullLabel}, ${verb} risk by ${Math.abs(top.weight).toFixed(1)}.`
}

/** Weight per signal as horizontal bars. A mouse and touch convenience; the keyboard path is the signal list. */
export default function WeightChart({ signals, selectedId, onSelect }) {
  const theme = useTheme()
  const tableId = useId()
  const [showTable, setShowTable] = useState(false)
  const { rows, skippedCount } = buildWeightChartData(signals)
  const byId = new Map(rows.map((r) => [r.id, r]))
  // Symmetric domain keeps zero in the middle, so "left" and "right" always mean the same thing.
  const extent = Math.max(...rows.map((r) => Math.abs(r.weight)), 1)

  return (
    <Box component="section" aria-labelledby={`${tableId}-heading`}>
      <Typography component="h2" variant="h3" id={`${tableId}-heading`} gutterBottom>
        How much each part counted
      </Typography>
      <Typography variant="body2" gutterBottom>
        Bars to the right push the result towards phishing. Bars to the left push it towards legitimate. Longer bars
        counted more.
      </Typography>

      {rows.length === 0 ? (
        <Typography>No weighted parts to show for this result.</Typography>
      ) : (
        <>
          {/* No skipAnimation: x-charts already skips animation when the user prefers reduced motion. */}
          {/* An <img> element cannot wrap the chart's SVG, so the role is the only way to name it as one image. */}
          {/* oxlint-disable-next-line jsx-a11y/prefer-tag-over-role */}
          <Box role="img" aria-label={summary(rows)} sx={{ width: '100%', minWidth: 0 }}>
            <BarChart
              layout="horizontal"
              height={rows.length * BAR_PX + AXIS_PX}
              hideLegend
              margin={{ left: 0, right: 8, top: 8, bottom: 0 }}
              yAxis={[
                {
                  scaleType: 'band',
                  data: rows.map((r) => r.id),
                  width: 'auto',
                  valueFormatter: (id, ctx) => (ctx.location === 'tooltip' ? byId.get(id)?.fullLabel : byId.get(id)?.label),
                },
              ]}
              xAxis={[{ min: -extent, max: extent }]}
              series={[
                {
                  data: rows.map((r) => r.weight),
                  colorGetter: ({ dataIndex }) =>
                    barColor(theme, rows[dataIndex].direction, selectedId != null && rows[dataIndex].id !== selectedId),
                  valueFormatter: (v, { dataIndex }) =>
                    `${DIRECTION_WORDS[rows[dataIndex].direction] ?? ''}, weight ${v.toFixed(1)}`,
                },
              ]}
              slotProps={{
                bar: ({ dataIndex }) => ({
                  'data-selected': String(rows[dataIndex]?.id === selectedId),
                  style: { cursor: 'pointer' },
                  ...(rows[dataIndex]?.id === selectedId ? { stroke: theme.palette.text.primary, strokeWidth: 2 } : {}),
                }),
              }}
              onItemClick={(_, item) => onSelect(rows[item.dataIndex].id)}
            >
              <ChartsReferenceLine x={0} lineStyle={{ stroke: theme.palette.text.primary, strokeWidth: 1.5 }} />
            </BarChart>
          </Box>
          <Box aria-hidden="true" sx={{ display: 'flex', justifyContent: 'space-between', typography: 'body2', fontWeight: 600 }}>
            <span>&larr; Lowers risk</span>
            <span>Raises risk &rarr;</span>
          </Box>
        </>
      )}

      {skippedCount > 0 && (
        <Typography variant="body2" sx={{ mt: 1 }}>
          {skippedCount === 1
            ? '1 rule-based check has no weight and is not shown here; it is listed above.'
            : `${skippedCount} rule-based checks have no weight and are not shown here; they are listed above.`}
        </Typography>
      )}

      {rows.length > 0 && (
        <>
          <Button variant="text" aria-expanded={showTable} aria-controls={tableId} onClick={() => setShowTable((s) => !s)} sx={{ mt: 1 }}>
            {showTable ? 'Hide table' : 'Show data as a table'}
          </Button>
          <Box id={tableId} hidden={!showTable} sx={{ overflowX: 'auto' }}>
            {showTable && (
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell component="th" scope="col">Part</TableCell>
                    <TableCell component="th" scope="col">Direction</TableCell>
                    <TableCell component="th" scope="col" align="right">Weight</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {rows.map((r) => (
                    <TableRow key={r.id} selected={r.id === selectedId}>
                      <TableCell sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere' }}>{r.fullLabel}</TableCell>
                      <TableCell>{DIRECTION_WORDS[r.direction] ?? ''}</TableCell>
                      <TableCell align="right">{r.weight.toFixed(1)}</TableCell>
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
