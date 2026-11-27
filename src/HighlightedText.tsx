import { memo, useMemo } from 'react'
import type { EffectiveSpan, WorkbenchSnapshot } from './workbenchClient'

export default memo(function HighlightedText({
  text,
  snapshot,
  spans,
}: {
  text: string
  snapshot: WorkbenchSnapshot | undefined
  spans: readonly (EffectiveSpan & { utf16Start: number; utf16End: number })[] | undefined
}) {
  const content = useMemo(() => {
    if (!spans?.length) return text
    let cursor = 0
    const segments = spans.map((span) => {
      const prefix = text.slice(cursor, span.utf16Start)
      cursor = span.utf16End
      return (
        <span key={span.id}>
          {prefix}
          <mark className={span.action}>
            {text.slice(span.utf16Start, span.utf16End)}
            <span className="highlight-label">
              {span.action === 'redact' ? 'Redacted' : 'Allowed'} · {span.reason_label}
            </span>
          </mark>
        </span>
      )
    })
    return <>{segments}{text.slice(cursor)}</>
  }, [text, spans])

  return (
    <section className="panel" aria-labelledby="highlights-label">
      <h2 id="highlights-label">Highlighted text</h2>
      <pre
        role="region"
        aria-label="Source highlights"
        tabIndex={text ? 0 : undefined}
        data-draft-revision={snapshot?.draft_revision}
        data-review-revision={snapshot?.review_revision}
      >
        {content || 'Highlighted matches will appear here.'}
      </pre>
    </section>
  )
})
