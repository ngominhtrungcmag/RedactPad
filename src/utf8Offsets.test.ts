import { describe, expect, it } from 'vitest'
import { utf16RangeToUtf8Bytes, utf8ByteLength, utf8SpansToUtf16 } from './utf8Offsets'

describe('UTF-8 offsets', () => {
  it.each(['ASCII', 'Tiếng Việt', '漢字', '🔐🚀', '👨‍👩‍👧‍👦', 'e\u0301', '\ud800'])(
    'round-trips a span inside mixed text (%s)',
    (sample) => {
      const prefix = 'é🔐 '
      const text = prefix + sample + '終'
      const encoder = new TextEncoder()
      const start = encoder.encode(prefix).length
      const end = start + encoder.encode(sample).length
      expect(utf8ByteLength(text)).toBe(encoder.encode(text).length)
      expect(utf16RangeToUtf8Bytes(text, prefix.length, prefix.length + sample.length)).toEqual({ start, end })
      expect(utf8SpansToUtf16(text, [{ start, end }])).toEqual([
        { start, end, utf16Start: prefix.length, utf16End: prefix.length + sample.length },
      ])
    },
  )

  it.each([[0, 0], [2, 1], [-1, 1], [0, 6], [1, 2], [2, 4], [0.5, 2], [NaN, 4]])(
    'rejects invalid selection [%s, %s)',
    (start, end) => expect(utf16RangeToUtf8Bytes('a🔐🚀', start, end)).toBeNull(),
  )

  it('maps adjacent and separated sorted ranges', () => {
    expect(utf8SpansToUtf16('🔐é南x🚀', [
      { start: 0, end: 4 }, { start: 4, end: 6 }, { start: 9, end: 14 },
    ])).toEqual([
      { start: 0, end: 4, utf16Start: 0, utf16End: 2 },
      { start: 4, end: 6, utf16Start: 2, utf16End: 3 },
      { start: 9, end: 14, utf16Start: 4, utf16End: 7 },
    ])
  })

  it.each([
    [[1, 4]], [[0, 3]], [[4, 7]], [[4, 4]], [[6, 4]], [[-1, 4]],
    [[0.5, 4]], [[0, NaN]], [[0, 6], [4, 6]], [[4, 6], [0, 4]],
  ].map((ranges) => ({ ranges })))('rejects invalid highlight ranges $ranges', ({ ranges }) => {
    expect(() => utf8SpansToUtf16('🔐é', ranges.map(([start, end]) => ({ start, end }))))
      .toThrow('Invalid UTF-8 span.')
  })

  it('maps 1,600 spans across 100 KiB in under 5 ms at p95', () => {
    const text = ('🔐' + 'x'.repeat(60)).repeat(1600)
    const spans = Array.from({ length: 1600 }, (_, index) => ({
      start: index * 64, end: index * 64 + 4,
    }))
    const timings = Array.from({ length: 21 }, () => {
      const start = performance.now()
      const mapped = utf8SpansToUtf16(text, spans)
      const elapsed = performance.now() - start
      expect(mapped.at(-1)?.utf16End).toBe(1599 * 62 + 2)
      return elapsed
    })
    expect(timings.slice(1).sort((a, b) => a - b)[18]).toBeLessThan(5)
  })
})
