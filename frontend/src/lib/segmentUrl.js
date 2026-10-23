// Rules have no learned weight, so they rank below every ngram.
const rank = (signal) => (typeof signal.weight === 'number' ? Math.abs(signal.weight) : -1)

/** True when start and end are integers with 0 <= start < end <= length (code points). */
const hasRange = (s, length) =>
  Number.isInteger(s?.start) && Number.isInteger(s?.end) && s.start >= 0 && s.end <= length && s.start < s.end

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
    if (!hasRange(s, codePoints.length)) continue
    for (let i = s.start; i < s.end; i++) {
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

/**
 * Split pieces at the selected signal's start and end (code points) and set selected: true on
 * the pieces inside its range, whichever signal owns them. Owners and directions are unchanged.
 * A missing signal or invalid range returns the pieces as they are.
 */
export function markSelected(pieces, signal) {
  const length = pieces.reduce((n, p) => n + Array.from(p.text).length, 0)
  if (!hasRange(signal, length)) return pieces
  let pos = 0
  return pieces.flatMap((p) => {
    const codePoints = Array.from(p.text)
    const from = pos
    pos += codePoints.length
    const a = Math.min(Math.max(signal.start - from, 0), codePoints.length)
    const b = Math.min(Math.max(signal.end - from, 0), codePoints.length)
    return [
      { ...p, text: codePoints.slice(0, a).join(''), selected: false },
      { ...p, text: codePoints.slice(a, b).join(''), selected: true },
      { ...p, text: codePoints.slice(b).join(''), selected: false },
    ].filter((q) => q.text !== '')
  })
}
