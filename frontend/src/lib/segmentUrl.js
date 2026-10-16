// Rules have no learned weight, so they rank below every ngram.
const rank = (signal) => (typeof signal.weight === 'number' ? Math.abs(signal.weight) : -1)

/**
 * Split analysedUrl into pieces that cover it in order, cutting by Unicode code point.
 * Each code point goes to the covering signal with the largest absolute weight; ties go
 * to the earlier signal. Signals without integer, in-bounds start < end are ignored.
 * @param {string} analysedUrl
 * @param {import('../api/types.js').Signal[]} signals
 * @returns {{ text: string, signalId: string | null, direction: 'phishing' | 'legitimate' | null }[]}
 */
export function segmentUrl(analysedUrl, signals = []) {
  const codePoints = Array.from(analysedUrl ?? '')
  const owners = new Array(codePoints.length).fill(null)

  for (const s of signals ?? []) {
    const { start, end } = s ?? {}
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end > codePoints.length || start >= end) {
      continue
    }
    for (let i = start; i < end; i++) {
      if (owners[i] === null || rank(s) > rank(owners[i])) owners[i] = s
    }
  }

  const pieces = []
  owners.forEach((owner, i) => {
    const last = pieces.at(-1)
    if (last && last.owner === owner) last.text += codePoints[i]
    else pieces.push({ owner, text: codePoints[i] })
  })
  return pieces.map(({ owner, text }) => ({
    text,
    signalId: owner?.id ?? null,
    direction: owner?.direction ?? null,
  }))
}
