/**
 * Chart rows from response signals (api-contract 3.4): only signals with a finite weight,
 * largest absolute weight first. Rules (weight null) are counted in skippedCount.
 * @returns {{ rows: { id, label, fullLabel, weight, direction, title }[], skippedCount: number }}
 */
export function buildWeightChartData(signals, maxLabelLength = 14) {
  if (!Array.isArray(signals)) return { rows: [], skippedCount: 0 }

  const rows = []
  for (const s of signals) {
    if (typeof s?.weight !== 'number' || !Number.isFinite(s.weight)) continue
    const fullLabel = String(s.text ?? s.title ?? '')
    // Cut by code point so an emoji or other astral character is never split in half.
    const points = Array.from(fullLabel)
    const label = points.length > maxLabelLength ? points.slice(0, maxLabelLength).join('') + '...' : fullLabel
    rows.push({ id: s.id, label, fullLabel, weight: s.weight, direction: s.direction, title: s.title })
  }
  rows.sort((a, b) => Math.abs(b.weight) - Math.abs(a.weight))
  return { rows, skippedCount: signals.length - rows.length }
}
