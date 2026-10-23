const MAX_LABEL = 20
const VERDICTS = new Set(['phishing', 'legitimate'])

/** Host part of the analysed URL (text before the first "/", "?" or "#"), cut to 20 code points. */
function hostLabel(analysedUrl) {
  const points = Array.from(String(analysedUrl ?? '').split(/[/?#]/)[0])
  return points.length > MAX_LABEL ? points.slice(0, MAX_LABEL).join('') + '...' : points.join('')
}

/**
 * Whole-number percentages that add up to 100 (largest remainder method).
 * A tie (exactly .5 each) goes to phishing, so the summary never understates risk.
 */
function percentages(phishing, total) {
  if (total === 0) return [0, 0]
  const exact = (100 * phishing) / total
  const p = Math.floor(exact)
  const l = Math.floor(100 - exact)
  const leftover = 100 - p - l // 0 or 1
  return exact - p >= 100 - exact - l ? [p + leftover, l] : [p, l + leftover]
}

/** Summary of this session's checks for the session page; entries that are not a usable result are skipped. */
export function summariseSession(entries) {
  const rows = []
  for (const entry of Array.isArray(entries) ? entries : []) {
    const result = entry?.result
    if (!VERDICTS.has(result?.label)) continue
    rows.push({
      id: entry.id,
      number: rows.length + 1,
      label: hostLabel(result.analysed_url),
      fullLabel: result.submitted_url,
      trustScore: result.trust_score,
      verdict: result.label,
      confidence: result.confidence,
      checkedAt: entry.checkedAt,
    })
  }
  const phishingCount = rows.filter((r) => r.verdict === 'phishing').length
  const legitimateCount = rows.length - phishingCount
  const [phishingPercent, legitimatePercent] = percentages(phishingCount, rows.length)
  return { total: rows.length, phishingCount, legitimateCount, phishingPercent, legitimatePercent, rows }
}
