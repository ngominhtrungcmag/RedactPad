import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'

export interface ScrubberSessionSummary {
  sessionId: number
  displayName: string
  byteSize: number
  hasActiveExport: boolean
  activeJobId: number | null
}

export interface ScrubberCommandError {
  code: string
  message: string
}

export type FileLimitation =
  | 'OversizedPemBlock'
  | 'UnclosedPemBlock'
  | 'UnsupportedMultilineCandidate'
  | 'OversizedRuleCandidate'
  | 'OversizedOverlapCluster'

export interface PreviewPage {
  text: string
  warnings: FileLimitation[]
  hasNext: boolean
  pageIndex: number
  totalBytes: number
  pageInputEnd: number
}

export type ExportJobSnapshot = { jobId: number; sessionId: number } & (
  | { state: 'Running' }
  | { state: 'Cancelled'; cleanupWarning: boolean }
  | { state: 'Published' }
  | { state: 'PublishedWithWarning'; warning: string }
  | ({ state: 'Failed'; cleanupWarning: boolean } & ScrubberCommandError)
)

export type ScrubberDrop = ScrubberSessionSummary | ScrubberCommandError

export interface ScrubberClient {
  pickInput(): Promise<ScrubberSessionSummary | null>
  getSession(): Promise<ScrubberSessionSummary | null>
  getPreviewPage(sessionId: number, pageIndex: number): Promise<PreviewPage>
  exportToPickedDestination(sessionId: number): Promise<ExportJobSnapshot | null>
  getExportStatus(jobId: number): Promise<ExportJobSnapshot>
  cancelExport(jobId: number): Promise<ExportJobSnapshot>
  clearSession(sessionId: number | null): Promise<null>
  listenForDrop(onDrop: (drop: ScrubberDrop) => void): Promise<() => void>
}

export const tauriScrubberClient: ScrubberClient = {
  pickInput: () => invoke('scrubber_pick_input'),
  getSession: () => invoke('scrubber_get_session'),
  getPreviewPage: (sessionId, pageIndex) => invoke('scrubber_get_preview_page', { sessionId, pageIndex }),
  exportToPickedDestination: (sessionId) => invoke('scrubber_export_to_picked_destination', { sessionId }),
  getExportStatus: (jobId) => invoke('scrubber_get_export_status', { jobId }),
  cancelExport: (jobId) => invoke('scrubber_cancel_export', { jobId }),
  clearSession: (sessionId) => invoke('scrubber_clear_session', { sessionId }),
  listenForDrop: (onDrop) => listen<ScrubberDrop>('scrubber://drop', ({ payload }) => onDrop(payload)),
}
