function byteWidth(point: number) {
  if (point <= 0x7f) return 1
  if (point <= 0x7ff) return 2
  return point <= 0xffff ? 3 : 4
}

export function utf8ByteLength(text: string): number {
  let bytes = 0
  for (let index = 0; index < text.length; index++) {
    const point = text.codePointAt(index)!
    bytes += byteWidth(point)
    if (point > 0xffff) index++
  }
  return bytes
}

export function utf8SpansToUtf16<T extends { start: number; end: number }>(
  text: string,
  spans: readonly T[],
): Array<T & { utf16Start: number; utf16End: number }> {
  let index = 0
  let bytes = 0
  function advanceTo(target: number) {
    while (bytes < target && index < text.length) {
      const point = text.codePointAt(index)!
      bytes += byteWidth(point)
      index += point > 0xffff ? 2 : 1
    }
    if (bytes !== target) throw new Error('Invalid UTF-8 span.')
    return index
  }

  return spans.map((span) => {
    const { start, end } = span
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < bytes || start >= end) {
      throw new Error('Invalid UTF-8 span.')
    }
    return { ...span, utf16Start: advanceTo(start), utf16End: advanceTo(end) }
  })
}

export function utf16RangeToUtf8Bytes(
  text: string,
  utf16Start: number,
  utf16End: number,
): { start: number; end: number } | null {
  if (!Number.isInteger(utf16Start) || !Number.isInteger(utf16End) ||
      utf16Start < 0 || utf16Start >= utf16End || utf16End > text.length) return null

  function splitsSurrogate(index: number) {
    return index > 0 && text.codePointAt(index - 1)! > 0xffff
  }

  if (splitsSurrogate(utf16Start) || splitsSurrogate(utf16End)) return null

  const start = utf8ByteLength(text.slice(0, utf16Start))
  return { start, end: start + utf8ByteLength(text.slice(utf16Start, utf16End)) }
}
