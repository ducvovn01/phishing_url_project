import { useEffect, useMemo, useRef } from 'react'
import { Box, Typography } from '@mui/material'
import UrlForm from '../components/UrlForm.jsx'
import AnalysisPanel from '../components/results/AnalysisPanel.jsx'
import ErrorState from '../components/results/ErrorState.jsx'
import LoadingState from '../components/results/LoadingState.jsx'
import SubmittedUrl from '../components/results/SubmittedUrl.jsx'
import TrustScore from '../components/results/TrustScore.jsx'
import VerdictBanner from '../components/results/VerdictBanner.jsx'
import { TRUST_SCORE_NOTE } from '../content/trustScoreNote.js'
import { verdictText } from '../content/verdictText.js'
import useAnalysis from '../hooks/useAnalysis.js'
import usePageTitle from '../hooks/usePageTitle.js'
import { useSession } from '../session/useSession.js'

// DOM order is the phone order: form, submitted URL, verdict, trust score, analysis.
const AREAS = {
  idle: { xs: '"form" "explainer"' },
  loading: { xs: '"form" "status"' },
  error: { xs: '"form" "status"' },
  success: {
    xs: '"form" "url" "verdict" "score" "analysis"',
    md: '"url url" "verdict verdict" "analysis form" "analysis score"',
  },
}

export default function HomePage() {
  const { addResult } = useSession()
  const { state, submit, reset } = useAnalysis({ onSuccess: addResult })
  const { status, result, error } = state
  const success = status === 'success'

  usePageTitle(success ? verdictText(result.label) : 'Check a URL')

  // Move focus to the outcome so keyboard and screen reader users land on it.
  const verdictRef = useRef(null)
  const errorTitleRef = useRef(null)
  useEffect(() => {
    if (result) verdictRef.current?.focus()
  }, [result])
  useEffect(() => {
    if (error) errorTitleRef.current?.focus()
  }, [error])

  // Memoised so UrlForm sees one object per error and can dismiss it once the user edits.
  const serverError = useMemo(() => {
    const detail = error?.code === 'validation_error' && error.details.find((d) => d.field === 'url')
    return detail ? { message: detail.message } : null
  }, [error])

  return (
    <>
      <Box sx={{ mb: 3, textAlign: success ? 'left' : 'center' }}>
        <Typography variant="h1" sx={success ? { fontSize: '1.25rem' } : undefined} gutterBottom={!success}>
          Check a link before you click it
        </Typography>
        {status === 'idle' && (
          <Typography>
            Paste a web address and we will tell you whether it looks like phishing. It takes a few seconds.
          </Typography>
        )}
      </Box>

      <Box
        sx={{
          display: 'grid',
          gap: 3,
          alignItems: 'start',
          gridTemplateColumns: success ? { xs: 'minmax(0, 1fr)', md: 'minmax(0, 7fr) minmax(0, 5fr)' } : 'minmax(0, 1fr)',
          gridTemplateAreas: AREAS[status],
          // Grid items default to min-width: auto, which lets a long URL push the page wider than the screen.
          '& > *': { minWidth: 0 },
        }}
      >
        {/* Always the first child, so the same UrlForm instance stays mounted in every state. */}
        <Box sx={{ gridArea: 'form', width: '100%', maxWidth: success ? undefined : 720, justifySelf: 'center' }}>
          <UrlForm onSubmit={submit} loading={status === 'loading'} serverError={serverError} onClear={reset} />
        </Box>

        {status === 'loading' && (
          <Box sx={{ gridArea: 'status', width: '100%', maxWidth: 720, justifySelf: 'center' }}>
            <LoadingState />
          </Box>
        )}
        {status === 'error' && (
          <Box sx={{ gridArea: 'status', width: '100%', maxWidth: 720, justifySelf: 'center' }}>
            <ErrorState error={error} onRetry={() => submit(state.submittedValue)} titleRef={errorTitleRef} />
          </Box>
        )}

        {success && (
          <Box sx={{ gridArea: 'url' }}>
            <SubmittedUrl url={result.submitted_url} />
          </Box>
        )}
        {success && (
          <Box sx={{ gridArea: 'verdict' }}>
            <VerdictBanner result={result} headingRef={verdictRef} />
          </Box>
        )}
        {success && (
          <Box sx={{ gridArea: 'score' }}>
            <TrustScore result={result} />
          </Box>
        )}
        {success && (
          <Box sx={{ gridArea: 'analysis' }}>
            <AnalysisPanel result={result} />
          </Box>
        )}

        {status === 'idle' && (
          <Box component="section" aria-labelledby="how-it-works" sx={{ gridArea: 'explainer', width: '100%', maxWidth: 720, justifySelf: 'center' }}>
            <Typography variant="h2" id="how-it-works" gutterBottom>
              How it works
            </Typography>
            <Box component="ol" sx={{ pl: 3, my: 1 }}>
              <li>Paste a link.</li>
              <li>We read only the text of the link and never open it.</li>
              <li>You get a verdict, a trust score and the parts that looked suspicious.</li>
            </Box>
            <Typography variant="body2" color="text.secondary">
              {TRUST_SCORE_NOTE}
            </Typography>
          </Box>
        )}
      </Box>
    </>
  )
}
