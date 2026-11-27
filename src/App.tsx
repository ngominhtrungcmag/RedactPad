import { useCallback, useRef, useState } from 'react'
import FileScrubber from './FileScrubber'
import { tauriScrubberClient } from './scrubberClient'
import type { ScrubberClient } from './scrubberClient'
import HighlightedText from './HighlightedText'
import { utf16RangeToUtf8Bytes, utf8ByteLength, utf8SpansToUtf16 } from './utf8Offsets'
import { MAX_INPUT_BYTES, tauriWorkbenchClient } from './workbenchClient'
import type { WorkbenchClient, WorkbenchSnapshot } from './workbenchClient'
import './styles.css'

const oversized = 'Text exceeds the 1 MiB limit.'
const selectionError = 'Select a valid range of source text to redact.'

const SYNTHETIC_SAMPLE = `# Demo ticket: checkout diagnostics
release=v2.4.0
request_id=00000000-0000-4000-8000-000000000001
stripe_key=sk_test_FAKEsample00000000000001
Authorization: Bearer synthetic_bearer_demo_9876543210
database=postgres://demo:fake-pass@db.example.test:5432/app
contact=alex@example.test`

function validateSnapshot(text: string, byteLength: number, snapshot: WorkbenchSnapshot) {
  if (snapshot.byte_length !== byteLength) throw new Error('Invalid snapshot byte length.')
  if (typeof snapshot.redacted_preview !== 'string') throw new Error('Invalid snapshot preview.')

  const highlights = utf8SpansToUtf16(text, snapshot.effective_spans)
  const parts: string[] = []
  let offset = 0
  for (const span of highlights) {
    if (span.action !== 'redact') continue
    parts.push(text.slice(offset, span.utf16Start))
    parts.push(span.reason_id === 'manual.selection' ? '[REDACTED_MANUAL]' : `[REDACTED:${span.reason_id}]`)
    offset = span.utf16End
  }
  parts.push(text.slice(offset))
  const expectedPreview = parts.join('')
  if (snapshot.redacted_preview !== expectedPreview) throw new Error('Invalid snapshot preview.')
  return { text, snapshot, highlights }
}

type Processing = 'idle' | 'analyzing' | 'reviewing' | 'clearing' | 'failed'

export default function App({
  client = tauriWorkbenchClient,
  scrubberClient = tauriScrubberClient,
}: { client?: WorkbenchClient; scrubberClient?: ScrubberClient } = {}) {
  const [mode, setMode] = useState<'text' | 'file'>('text')
  const fileMode = useRef<HTMLButtonElement>(null)

  const showDrop = useCallback(() => {
    const wasOnTextWorkbench = fileMode.current?.getAttribute('aria-pressed') === 'false'
    setMode('file')
    if (wasOnTextWorkbench) fileMode.current?.focus()
  }, [])

  return (
    <main>
      <header className="topbar row">
        <h1>RedactPad</h1>
        <nav className="segments" aria-label="Workbench mode">
          <button type="button" aria-pressed={mode === 'text'} onClick={() => setMode('text')}>Text</button>
          <button type="button" ref={fileMode} aria-pressed={mode === 'file'} onClick={() => setMode('file')}>File</button>
        </nav>
      </header>
      <div hidden={mode !== 'text'}><TextWorkbench client={client} /></div>
      <div hidden={mode !== 'file'}><FileScrubber client={scrubberClient} onDrop={showDrop} /></div>
    </main>
  )
}

function TextWorkbench({ client }: { client: WorkbenchClient }) {
  const [view, setView] = useState<'source' | 'preview'>('source')
  const previewTab = useRef<HTMLButtonElement>(null)
  const editor = useRef<HTMLTextAreaElement>(null)
  const selectionControl = useRef<HTMLButtonElement>(null)
  const latestDraftRequestId = useRef(0)
  const latestReviewRequestId = useRef(0)
  const [accepted, setAccepted] = useState<ReturnType<typeof validateSnapshot>>()
  const [draft, setDraft] = useState('')
  const [processing, setProcessing] = useState<Processing>('idle')
  const [copying, setCopying] = useState(false)
  const [alert, setAlert] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const snapshot = accepted?.snapshot
  const byteCount = utf8ByteLength(draft)
  const allowedCount = snapshot?.matches.filter((match) => match.action === 'allow' && !match.overridden_by_manual).length ?? 0
  const progress = {
    idle: '',
    failed: '',
    analyzing: 'Analyzing text…',
    reviewing: 'Updating review…',
    clearing: 'Clearing draft…',
  }[processing]
  const canReview = processing === 'idle' && !!snapshot?.byte_length && accepted?.text === draft

  async function changeDraft(text: string, clear = false) {
    setConfirmation('')
    const byteLength = utf8ByteLength(text)
    if (byteLength > MAX_INPUT_BYTES) {
      setAlert(oversized)
      return
    }

    const requestId = ++latestDraftRequestId.current
    ++latestReviewRequestId.current
    setDraft(text)
    setAlert('')
    setProcessing(clear ? 'clearing' : 'analyzing')
    try {
      const next = await (clear ? client.clearDraft() : client.analyzeDraft(text, null))
      if (requestId !== latestDraftRequestId.current) return
      setAccepted(validateSnapshot(text, byteLength, next))
      setProcessing('idle')
    } catch (error) {
      if (requestId !== latestDraftRequestId.current) return
      if (typeof error === 'object' && error !== null && 'code' in error && error.code === 'InputTooLarge') {
        const previousText = accepted?.text ?? ''
        setDraft(previousText)
        setAlert(oversized)
        // A rejected edit can retain copy eligibility only for a previously current review.
        setProcessing(processing === 'idle' ? 'idle' : 'failed')
        return
      }
      setProcessing('failed')
      setAlert(clear ? 'Could not clear the draft. Try again.' : 'Could not analyze the text. Edit the source to try again.')
    }
  }

  async function review(
    update: (draftRevision: number) => Promise<WorkbenchSnapshot>,
    removedControl?: HTMLButtonElement,
  ) {
    if (!canReview || !accepted) return
    const requestId = ++latestReviewRequestId.current
    setAlert('')
    setConfirmation('')
    setProcessing('reviewing')
    try {
      const next = await update(accepted.snapshot.draft_revision)
      if (requestId !== latestReviewRequestId.current) return
      if (next.draft_revision !== accepted.snapshot.draft_revision ||
          next.review_revision <= accepted.snapshot.review_revision) {
        setProcessing('failed')
        setAlert('The review changed. Edit the source to refresh it.')
        return
      }
      const validated = validateSnapshot(accepted.text, accepted.snapshot.byte_length, next)
      if (removedControl && document.activeElement === removedControl) {
        const focusTarget = previewTab.current?.getAttribute('aria-pressed') === 'true' ? previewTab : selectionControl
        focusTarget.current?.focus()
      }
      setAccepted(validated)
      setProcessing('idle')
    } catch {
      if (requestId !== latestReviewRequestId.current) return
      setProcessing('failed')
      setAlert('Could not update the review. Edit the source to refresh it.')
    }
  }

  function redactSelection() {
    if (!canReview || !editor.current || !accepted) return
    const { selectionStart, selectionEnd } = editor.current
    const range = utf16RangeToUtf8Bytes(accepted.text, selectionStart, selectionEnd)
    if (!range) {
      setAlert(selectionError)
      return
    }
    void review((revision) => client.addManualRedaction(revision, range.start, range.end))
  }

  async function copy() {
    if (!canReview || !snapshot || copying) return
    const requestId = latestReviewRequestId.current
    setCopying(true)
    setAlert('')
    setConfirmation('')
    try {
      await client.copyRedactedText(snapshot.draft_revision, snapshot.review_revision)
      if (requestId === latestReviewRequestId.current) setConfirmation('Redacted text copied.')
    } catch {
      if (requestId === latestReviewRequestId.current) {
        setAlert('Could not copy the redacted text to the clipboard. Try again.')
      }
    } finally {
      setCopying(false)
    }
  }

  return (
    <div className="layout text-workbench">
      <div className="editor-switch">
        <div className="segments" role="group" aria-label="Editor view">
          <button type="button" aria-controls="source-column" aria-pressed={view === 'source'} onClick={() => setView('source')}>Source</button>
          <button type="button" ref={previewTab} aria-controls="text-preview" aria-pressed={view === 'preview'} onClick={() => setView('preview')}>Preview</button>
        </div>
      </div>

      <div className="stack editor-column">
        <div className="stack" id="source-column" hidden={view !== 'source'}>
          <section className="panel" aria-labelledby="source-label">
            <div className="row between">
              <h2><label id="source-label" htmlFor="source-text">Source</label></h2>
              <span id="source-help" className="muted">{`${byteCount.toLocaleString()} B / 1 MiB`}</span>
            </div>
            <textarea
              className="editor"
              id="source-text"
              ref={editor}
              value={draft}
              placeholder="Paste or type text to review"
              aria-describedby="source-help"
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="off"
              spellCheck={false}
              onChange={(event) => void changeDraft(event.currentTarget.value)}
              onKeyDown={(event) => {
                if ((event.metaKey || event.ctrlKey) && event.shiftKey && event.key.toLowerCase() === 'r') {
                  event.preventDefault()
                  redactSelection()
                }
              }}
            />
            <div className="row">
              {!draft && (
                <button type="button" onClick={() => {
                  editor.current?.focus()
                  void changeDraft(SYNTHETIC_SAMPLE)
                }}>Load synthetic sample</button>
              )}
              <button
                type="button"
                ref={selectionControl}
                aria-disabled={!canReview}
                aria-keyshortcuts="Meta+Shift+R Control+Shift+R"
                onClick={redactSelection}
              >
                Redact selection
              </button>
              <kbd className="muted" aria-hidden="true">⌘/Ctrl⇧R</kbd>
            </div>
          </section>

          <HighlightedText text={accepted?.text ?? ''} snapshot={snapshot} spans={accepted?.highlights} />
        </div>

        <section className="panel preview" id="text-preview" aria-labelledby="preview-label" hidden={view !== 'preview'}>
          <h2 id="preview-label">Redacted preview</h2>
          <pre
            role="region"
            aria-label="Preview text"
            tabIndex={snapshot?.byte_length ? 0 : undefined}
          >{snapshot?.byte_length ? snapshot.redacted_preview : 'Redacted text will appear here.'}</pre>
          <div className="row">
            <button type="button" className="primary" disabled={!canReview} aria-disabled={copying} onClick={() => void copy()}>
              <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="8" y="8" width="12" height="12" rx="2" />
                <path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2" />
              </svg>
              Copy redacted text
            </button>
            <button type="button" onClick={() => {
              void changeDraft('', true)
              previewTab.current?.focus()
            }}>
              <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round">
                <path d="m6 6 12 12M18 6 6 18" />
              </svg>
              Clear
            </button>
          </div>
          <p className="muted"><span>Unflagged text can still be sensitive</span> — review before sharing.</p>
        </section>
        {alert && <p className="error" role="alert">{alert}</p>}
        <p className="muted status" role="status">{progress || (copying ? 'Copying…' : confirmation)}</p>
      </div>

      <section className="panel matches" aria-labelledby="matches-label">
        <h2 id="matches-label">Matches</h2>
        {snapshot && (snapshot.matches.length > 0 || snapshot.manual_redactions.length > 0) && (
          <p className="muted">{snapshot.matches.length - allowedCount} redacted · {allowedCount} allowed · {snapshot.manual_redactions.length} manual</p>
        )}
        {snapshot?.warnings.includes('OversizedPemBlock') && (
          <p className="warning">A PEM private key block exceeded 16 KiB and was skipped.</p>
        )}
        {snapshot && (snapshot.matches.length > 0 || snapshot.manual_redactions.length > 0) ? (
          <ul>
            {snapshot.matches.map((match, index) => {
              const action = match.action === 'redact' ? 'allow' : 'redact'
              const title = action === 'allow' ? 'Allow' : 'Redact'
              const partiallyCovered = !match.overridden_by_manual && snapshot.manual_redactions.some(
                (manual) => manual.start < match.end && match.start < manual.end,
              )
              return (
                <li key={match.id}>
                  <div>
                    {match.reason_label}
                    <p className="muted match-state">{match.reason_id}</p>
                    <p className="muted match-state">
                      {match.overridden_by_manual ? 'Covered by manual redaction' : match.action === 'redact' ? 'Redacted' : 'Allowed'}
                    </p>
                    {partiallyCovered && <p className="muted match-state">Partially covered by manual redaction</p>}
                  </div>
                  <button
                    type="button"
                    aria-label={`${title} ${match.reason_label} (match ${index + 1})`}
                    aria-disabled={!canReview || match.overridden_by_manual}
                    onClick={() => {
                      if (!match.overridden_by_manual) {
                        void review((revision) => client.setMatchAction(revision, match.id, action))
                      }
                    }}
                  >
                    {title}
                  </button>
                </li>
              )
            })}
            {snapshot.manual_redactions.map((manual, index) => (
              <li key={manual.id}>
                <div>
                  {manual.reason_label}
                  <p className="muted match-state">{manual.reason_id}</p>
                  <p className="muted match-state">Redacted</p>
                </div>
                <button
                  type="button"
                  aria-label={`Remove manual redaction ${index + 1}`}
                  aria-disabled={!canReview}
                  onClick={(event) => void review(
                    (revision) => client.removeManualRedaction(revision, manual.id),
                    event.currentTarget,
                  )}
                >
                  Remove
                </button>
              </li>
            ))}
          </ul>
        ) : draft ? (
          <p className="muted">{progress || (snapshot?.byte_length ? 'No matches found.' : 'Matches will appear after analysis.')}</p>
        ) : (
          <p className="muted">Paste text to scan for secrets and personal data.</p>
        )}
      </section>
    </div>
  )
}
