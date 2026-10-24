/**
 * Confidence (0 to 1) as text. Anything that would round to 100% reads "Over 99%", because a
 * model is never 100% sure. Bad input (not a number, outside 0 to 1) gives "0%" and never throws.
 */
export function formatConfidence(confidence) {
  if (typeof confidence !== 'number' || !(confidence >= 0 && confidence <= 1)) return '0%'
  return confidence * 100 >= 99.5 ? 'Over 99%' : `${Math.round(confidence * 100)}%`
}
