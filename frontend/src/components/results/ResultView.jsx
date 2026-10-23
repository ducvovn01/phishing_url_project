import { useState } from 'react'
import { Box } from '@mui/material'
import AnalysisPanel from './AnalysisPanel.jsx'
import SubmittedUrl from './SubmittedUrl.jsx'
import TrustScore from './TrustScore.jsx'
import VerdictBanner from './VerdictBanner.jsx'

/**
 * The success cells of HomePage's grid. A fragment, so the cells stay direct grid children and
 * UrlForm (owned by HomePage) keeps its single mounted instance. Owns the selected signal so the
 * analysis panel and a chart can share it.
 */
export default function ResultView({ result, verdictRef }) {
  // Selection resets when a new result arrives; clearing the form unmounts this view.
  const [selection, setSelection] = useState({ result, id: null })
  const selectedSignalId = selection.result === result ? selection.id : null
  const onSelect = (id) => setSelection({ result, id })

  return (
    <>
      <Box sx={{ gridArea: 'url' }}>
        <SubmittedUrl url={result.submitted_url} />
      </Box>
      <Box sx={{ gridArea: 'verdict' }}>
        <VerdictBanner result={result} headingRef={verdictRef} />
      </Box>
      <Box sx={{ gridArea: 'score' }}>
        <TrustScore result={result} />
      </Box>
      <Box sx={{ gridArea: 'analysis' }}>
        <AnalysisPanel result={result} selectedId={selectedSignalId} onSelect={onSelect} />
      </Box>
    </>
  )
}
