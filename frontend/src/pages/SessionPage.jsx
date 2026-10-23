import { useRef } from 'react'
import { Link as RouterLink } from 'react-router-dom'
import { Box, Button, Link, Stack, Table, TableBody, TableCell, TableHead, TableRow, Typography } from '@mui/material'
import GppBadIcon from '@mui/icons-material/GppBad'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import { verdictText } from '../content/verdictText.js'
import usePageTitle from '../hooks/usePageTitle.js'
import { summariseSession } from '../lib/sessionSummary.js'
import { useSession } from '../session/useSession.js'

const focusSx = { '&:focus': { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: '4px' } }
const formatTime = (date) => date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })

export default function SessionPage() {
  usePageTitle('This session')
  const { results, clear } = useSession()
  const headingRef = useRef(null)
  const { total, phishingCount, legitimateCount, rows } = summariseSession(results)

  function handleClear() {
    clear()
    // The h1 stays mounted, so focus lands on it instead of on the removed button.
    headingRef.current?.focus()
  }

  return (
    <>
      <Typography variant="h1" ref={headingRef} tabIndex={-1} gutterBottom sx={focusSx}>
        This session
      </Typography>
      <Typography sx={{ mb: 3 }}>
        Links you check in this browser tab are listed here. Nothing is saved: the list is cleared when you refresh or
        close the tab.
      </Typography>

      {total === 0 ? (
        <Typography>
          You haven&apos;t checked any links yet.{' '}
          <Link component={RouterLink} to="/">
            Check a URL
          </Link>
        </Typography>
      ) : (
        <>
          <Typography sx={{ mb: 2, fontWeight: 600 }}>
            {total === 1 ? '1 check' : `${total} checks`}: {phishingCount} likely phishing, {legitimateCount} likely legitimate
          </Typography>

          <Box
            component="section"
            aria-label="Checked links table"
            tabIndex={0}
            sx={{ overflowX: 'auto', '&:focus-visible': { outline: '2px solid', outlineColor: 'text.primary', outlineOffset: 2 } }}
          >
            <Table size="small">
              <caption>Links checked in this session</caption>
              <TableHead>
                <TableRow>
                  <TableCell component="th" scope="col">#</TableCell>
                  <TableCell component="th" scope="col">Link</TableCell>
                  <TableCell component="th" scope="col">Result</TableCell>
                  <TableCell component="th" scope="col" align="right">Trust score</TableCell>
                  <TableCell component="th" scope="col">Time</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((row) => {
                  const Icon = row.verdict === 'phishing' ? GppBadIcon : VerifiedUserIcon
                  return (
                    <TableRow key={row.id}>
                      <TableCell>{row.number}</TableCell>
                      {/* Plain text only: a submitted URL is never turned into a link. */}
                      <TableCell sx={{ fontFamily: 'monospace', overflowWrap: 'anywhere', minWidth: 160 }}>{row.fullLabel}</TableCell>
                      <TableCell>
                        <Stack direction="row" spacing={1} sx={{ alignItems: 'center', whiteSpace: 'nowrap' }}>
                          <Icon aria-hidden="true" fontSize="small" sx={{ color: `${row.verdict}.main` }} />
                          <span>{verdictText(row.verdict)}</span>
                        </Stack>
                      </TableCell>
                      <TableCell align="right">{row.trustScore}</TableCell>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>
                        {row.checkedAt instanceof Date && <time dateTime={row.checkedAt.toISOString()}>{formatTime(row.checkedAt)}</time>}
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </Box>

          <Button variant="outlined" onClick={handleClear} sx={{ mt: 3 }}>
            Clear session
          </Button>
        </>
      )}
    </>
  )
}
