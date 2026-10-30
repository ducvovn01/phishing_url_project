import { describe, expect, test } from 'vitest'
import { buildWeightChartData } from './weightChartData.js'

const sig = (id, weight, text = id, title = `title ${id}`, direction = weight < 0 ? 'legitimate' : 'phishing') => ({
  id,
  weight,
  text,
  title,
  direction,
})

describe('buildWeightChartData', () => {
  test('sorts by absolute weight, largest first, whatever the sign', () => {
    const { rows } = buildWeightChartData([sig('a', 5), sig('b', -29.4), sig('c', 37.1), sig('d', -0.5)])
    expect(rows.map((r) => r.id)).toEqual(['c', 'b', 'a', 'd'])
  })

  test('null and non-finite weights are skipped and counted', () => {
    const { rows, skippedCount } = buildWeightChartData([
      sig('keep', 1),
      sig('rule', null),
      sig('nan', NaN),
      sig('inf', Infinity),
      sig('str', '3'),
      { id: 'missing' },
    ])
    expect(rows.map((r) => r.id)).toEqual(['keep'])
    expect(skippedCount).toBe(5)
  })

  test('row shape', () => {
    expect(buildWeightChartData([sig('ngram-1', 37.1, '.top', 'Pattern')]).rows).toEqual([
      { id: 'ngram-1', label: '.top', fullLabel: '.top', weight: 37.1, direction: 'phishing', title: 'Pattern' },
    ])
  })

  test('truncates by code point and keeps fullLabel', () => {
    const text = '😀😀😀abc'
    const [row] = buildWeightChartData([sig('e', 1, text)], 4).rows
    expect(row.label).toBe('😀😀😀a...')
    expect(row.fullLabel).toBe(text)
    expect(buildWeightChartData([sig('e', 1, text)], 6).rows[0].label).toBe(text)
  })

  test('label falls back to the title when text is null', () => {
    const [row] = buildWeightChartData([sig('t', 2, null, 'Very long URL title')]).rows
    expect(row.fullLabel).toBe('Very long URL title')
    expect(row.label).toBe('Very long URL ...')
  })

  test('odd input never throws', () => {
    for (const bad of [undefined, null, 'x', 42, {}]) {
      expect(buildWeightChartData(bad)).toEqual({ rows: [], skippedCount: 0 })
    }
    expect(buildWeightChartData([null, undefined, 7, sig('ok', 1)])).toEqual({
      rows: [expect.objectContaining({ id: 'ok' })],
      skippedCount: 3,
    })
    expect(buildWeightChartData([{ weight: 3 }]).rows[0]).toMatchObject({ label: '', fullLabel: '', weight: 3 })
  })
})
