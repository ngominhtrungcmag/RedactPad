import { useCallback, useEffect, useRef, useState } from 'react'
import type { ExportJobSnapshot, FileLimitation, PreviewPage, ScrubberClient, ScrubberSessionSummary } from './scrubberClient'

const explanations: Record<FileLimitation, string> = {
  OversizedPemBlock: 'A PEM private key block exceeds the supported size.',
  UnclosedPemBlock: 'A PEM private key block is unclosed.',
  UnsupportedMultilineCandidate: 'A quoted credential spans multiple lines.',
  OversizedRuleCandidate: 'A candidate exceeds the supported size.',
  OversizedOverlapCluster: 'Overlapping candidates exceed the supported size.',
}

function errorMessage(error: unknown, fallback: string) {
  return error && typeof error === 'object' && 'code' in error && typeof error.code === 'string' &&
    'message' in error && typeof error.message === 'string' ? error.message : fallback
}

function fileSize(bytes: number) {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']
  const unit = bytes < 1024 ? 0 : Math.min(Math.floor(Math.log2(bytes) / 10), units.length - 1)
  return `${(bytes / 1024 ** unit).toLocaleString(undefined, { maximumFractionDigits: 1 })} ${units[unit]}`
}

const cleanupNotice = ' Temporary output cleanup could not be confirmed.'

function ExportFeedback({ job }: { job: ExportJobSnapshot }) {
  switch (job.state) {
    case 'Running':
      return <p role="status">Exporting redacted copy…</p>
    case 'Published':
      return <p role="status">Redacted copy exported.</p>
    case 'PublishedWithWarning':
      return <p className="warning" role="alert">Redacted copy was published. {job.warning}</p>
    case 'Cancelled':
      return <p role="status">Export cancelled before publication.{job.cleanupWarning ? cleanupNotice : ''}</p>
    case 'Failed':
      return <p className="error" role="alert">{job.message}{job.cleanupWarning ? cleanupNotice : ''}</p>
  }
}

export default function FileScrubber({ client, onDrop }: { client: ScrubberClient; onDrop: () => void }) {
  const [session, setSession] = useState<ScrubberSessionSummary | null>(null)
  const [currentPage, setCurrentPage] = useState<PreviewPage | null>(null)
  const [loading, setLoading] = useState(false)
  const [job, setJob] = useState<ExportJobSnapshot | null>(null)
  const [pending, setPending] = useState<'pick' | 'clear' | 'save' | 'cancel' | null>(null)
  const [alert, setAlert] = useState('')
  const [pollFailed, setPollFailed] = useState(false)
  const requests = useRef({ activeSessionId: null as number | null, latestSessionId: 0, previewRequestId: 0 })
  const preview = useRef<HTMLDivElement>(null)
  const select = useRef<HTMLButtonElement>(null)
  const exportButton = useRef<HTMLButtonElement>(null)

  const runningJobId = job?.state === 'Running' ? job.jobId : null
  const exporting = runningJobId !== null
  const blocked = !!currentPage?.warnings.length
  const canExport = session !== null && currentPage !== null && !blocked && !loading && !exporting && !pending

  const loadPage = useCallback(async (sessionId: number, pageIndex: number) => {
    const requestId = ++requests.current.previewRequestId
    const isCurrent = () => requestId === requests.current.previewRequestId && requests.current.activeSessionId === sessionId
    setLoading(true)
    setAlert('')
    try {
      const page = await client.getPreviewPage(sessionId, pageIndex)
      if (isCurrent()) {
        setCurrentPage(page)
        if (preview.current) preview.current.scrollTop = 0
      }
    } catch (error) {
      if (isCurrent()) {
        setCurrentPage(null)
        setAlert(errorMessage(error, 'Could not read the preview. Try again.'))
      }
    } finally {
      if (isCurrent()) setLoading(false)
    }
  }, [client])

  const openSession = useCallback((next: ScrubberSessionSummary) => {
    if (next.sessionId <= requests.current.latestSessionId) return
    requests.current.latestSessionId = next.sessionId
    requests.current.activeSessionId = next.sessionId
    setSession(next)
    setCurrentPage(null)
    setJob(next.activeJobId === null
      ? null
      : { jobId: next.activeJobId, sessionId: next.sessionId, state: 'Running' })
    setPollFailed(false)
    void loadPage(next.sessionId, 0)
  }, [loadPage])

  useEffect(() => {
    let disposed = false
    let unlisten: (() => void) | undefined
    const sessionRequests = requests.current
    const initialRequestId = sessionRequests.previewRequestId

    async function connect() {
      try {
        unlisten = await client.listenForDrop((drop) => {
          if (disposed) return
          onDrop()
          if ('sessionId' in drop) openSession(drop)
          else setAlert(drop.message)
        })
      } catch {
        // The event bridge is unavailable outside Tauri.
        return
      }
      if (disposed) {
        unlisten()
        return
      }

      try {
        const existing = await client.getSession()
        if (!disposed && existing && initialRequestId === requests.current.previewRequestId) openSession(existing)
      } catch (error) {
        if (!disposed && initialRequestId === requests.current.previewRequestId) {
          setAlert(errorMessage(error, 'Could not load the selected file.'))
        }
      }
    }

    void connect()
    return () => {
      disposed = true
      ++sessionRequests.previewRequestId
      unlisten?.()
    }
  }, [client, onDrop, openSession])

  useEffect(() => {
    if (pending === 'cancel' || runningJobId === null) return
    const jobId = runningJobId
    const sessionId = session?.sessionId
    let disposed = false
    let timer = window.setTimeout(poll, 200)

    async function poll() {
      const isCurrent = () => !disposed && requests.current.activeSessionId === sessionId
      try {
        const next = await client.getExportStatus(jobId)
        if (!isCurrent()) return
        setPollFailed(false)
        if (next.state !== 'Running') {
          if (document.activeElement?.id === 'cancel-file-export') exportButton.current?.focus()
          setJob(next)
          return
        }
      } catch {
        if (!isCurrent()) return
        setPollFailed(true)
      }
      timer = window.setTimeout(poll, 200)
    }

    return () => {
      disposed = true
      window.clearTimeout(timer)
    }
  }, [client, pending, runningJobId, session?.sessionId])

  async function pickInput() {
    if (exporting || pending) return
    setPending('pick')
    setAlert('')
    try {
      const next = await client.pickInput()
      if (next) openSession(next)
    } catch (error) {
      setAlert(errorMessage(error, 'Could not select a file. Try again.'))
    } finally {
      setPending(null)
    }
  }

  async function clearFile() {
    if (!session || exporting || pending) return
    setPending('clear')
    setAlert('')
    try {
      await client.clearSession(session.sessionId)
      if (requests.current.activeSessionId !== session.sessionId) return
      requests.current.activeSessionId = null
      ++requests.current.previewRequestId
      setSession(null)
      setCurrentPage(null)
      setLoading(false)
      setJob(null)
    } catch (error) {
      setAlert(errorMessage(error, 'Could not clear the selected file. Try again.'))
    } finally {
      setPending(null)
    }
  }

  async function exportFile() {
    if (!session || !canExport) return
    setPending('save')
    setAlert('')
    setJob(null)
    setPollFailed(false)
    try {
      const next = await client.exportToPickedDestination(session.sessionId)
      if (next && next.sessionId === requests.current.activeSessionId) setJob(next)
    } catch (error) {
      setAlert(errorMessage(error, 'Could not start the export. Try again.'))
    } finally {
      setPending(null)
    }
  }

  async function cancelExport() {
    if (runningJobId === null || pending) return
    exportButton.current?.focus()
    setPending('cancel')
    setAlert('')
    setPollFailed(false)
    try {
      const next = await client.cancelExport(runningJobId)
      if (next.sessionId === requests.current.activeSessionId) setJob(next)
    } catch (error) {
      setAlert(errorMessage(error, 'Could not request cancellation. Try again.'))
    } finally {
      setPending(null)
    }
  }

  function changePage(pageIndex: number) {
    if (!session || loading || exporting || pending) return
    preview.current?.focus()
    void loadPage(session.sessionId, pageIndex)
  }

  return (
    <section className="file-scrubber" aria-label="File Scrubber">
      <div className="panel file-intake">
        <div className="drop-zone">
          <div className="file-icon">
            <svg className="icon" viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
              <path d="M11 21H5V3h9l4 4v3m-5-7v5h5M8 11h3m-3 4h2" />
              <path d="M17 11l4 1.5v3c0 2.5-1.6 4.2-4 5.5-2.4-1.3-4-3-4-5.5v-3L17 11Z" />
            </svg>
          </div>
          <h2>Scrub plain-text files locally</h2>
          <p className="hint">Streams .log and .txt files directly from disk with bounded memory and writes a separate redacted copy without modifying the original.</p>
          <button type="button" className="primary" ref={select} aria-disabled={exporting || !!pending} onClick={() => void pickInput()}>
            Select .log or .txt file
          </button>
          <p className="hint">Or drop a .log or .txt file onto this window.</p>
          <div className="chips">
            <span className="badge allow">Supported: .log, .txt</span>
            <span className="badge">v0.2+: .json, .jsonl, .csv, .sql, .env</span>
          </div>
          {pending === 'pick' && <p role="status">Choosing a file…</p>}
        </div>
        {session && (
          <div className="scrubber-file">
            <div>
              <h2>{session.displayName}</h2>
              <p className="hint">{fileSize(session.byteSize)}</p>
            </div>
            <button type="button" disabled={exporting || !!pending} onClick={() => {
              select.current?.focus()
              void clearFile()
            }}>Clear file</button>
          </div>
        )}
      </div>

      {alert && <p className="error" role="alert">{alert}</p>}
      {blocked && (
        <div className="warning" role="alert">
          <strong>Export is blocked because the file contains candidates that cannot be safely redacted.</strong>
          <ul>{currentPage.warnings.map((warning) => <li key={warning}>{explanations[warning]}</li>)}</ul>
        </div>
      )}

      <div className="panel">
        <div className="panel-heading">
          <h2>Redacted preview</h2>
          <span className="badge">1 bounded page in memory (≤ 256 KiB IPC)</span>
        </div>
        <div
          className="text-view scrubber-preview"
          role="region"
          aria-label="Redacted preview text"
          aria-busy={loading}
          ref={preview}
          tabIndex={currentPage ? 0 : undefined}
        >
          {currentPage ? currentPage.text || 'This file is empty.' : (
            <p className="hint">{session ? 'No preview available.' : 'Select a file to preview its redacted text.'}</p>
          )}
        </div>
        {loading && <p role="status">Loading preview…</p>}
        {currentPage && (
          <div className="actions" aria-label="Preview pagination" role="group">
            <button type="button" disabled={currentPage.pageIndex === 0 || loading || exporting || !!pending}
              onClick={() => changePage(currentPage.pageIndex - 1)}>Previous page</button>
            <p role="status">Page {currentPage.pageIndex + 1}</p>
            <button type="button" disabled={!currentPage.hasNext || loading || exporting || !!pending}
              onClick={() => changePage(currentPage.pageIndex + 1)}>Next page</button>
          </div>
        )}
        {session && !currentPage && !loading && (
          <div><button type="button" disabled={exporting || !!pending} onClick={() => changePage(0)}>Retry preview</button></div>
        )}
      </div>

      <footer className="panel">
        <div className="panel-heading">
          <p className="hint">File exports use irreversible markers and cannot be restored.</p>
          <div className="actions">
            <button type="button" className="primary" ref={exportButton}
              disabled={!session || !currentPage || blocked || loading}
              aria-disabled={!canExport} onClick={() => void exportFile()}>Export redacted copy</button>
            {runningJobId !== null && (
              <button type="button" id="cancel-file-export" disabled={pending === 'cancel'} onClick={() => void cancelExport()}>
                Cancel export
              </button>
            )}
          </div>
        </div>
        {pending === 'save' && <p role="status">Choosing an export destination…</p>}
        {pending === 'cancel' && <p role="status">Requesting cancellation…</p>}
        {job && <ExportFeedback job={job} />}
        {pollFailed && <p className="error" role="alert">Could not check export status. Retrying…</p>}
      </footer>
    </section>
  )
}
