import { invoke } from '@tauri-apps/api/core'

export const MAX_INPUT_BYTES = 1_048_576

export type MatchAction = 'redact' | 'allow'

export interface ManualRedaction {
  id: string
  start: number
  end: number
  reason_id: string
  reason_label: string
}

export interface EffectiveSpan extends ManualRedaction {
  action: MatchAction
}

export interface AutomaticMatch extends EffectiveSpan {
  overridden_by_manual: boolean
}

interface Revisions {
  draft_revision: number
  review_revision: number
}

export interface WorkbenchSnapshot extends Revisions {
  byte_length: number
  max_bytes: number
  matches: AutomaticMatch[]
  manual_redactions: ManualRedaction[]
  effective_spans: EffectiveSpan[]
  redacted_preview: string
  warnings: 'OversizedPemBlock'[]
}

export interface WorkbenchClient {
  analyzeDraft(text: string, options: { phone_locales?: string[] } | null): Promise<WorkbenchSnapshot>
  setMatchAction(draftRevision: number, matchId: string, action: MatchAction): Promise<WorkbenchSnapshot>
  addManualRedaction(draftRevision: number, start: number, end: number): Promise<WorkbenchSnapshot>
  removeManualRedaction(draftRevision: number, manualId: string): Promise<WorkbenchSnapshot>
  clearDraft(): Promise<WorkbenchSnapshot>
  copyRedactedText(draftRevision: number, reviewRevision: number): Promise<Revisions>
}

let commandQueue = Promise.resolve()

// Preserve user action order across IPC so a stale analysis cannot replace the Rust draft.
function send<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const result = commandQueue.then(() => invoke<T>(command, args))
  commandQueue = result.then(() => undefined, () => undefined)
  return result
}

export const tauriWorkbenchClient: WorkbenchClient = {
  analyzeDraft: (text, options) => send('analyze_draft', { text, options }),
  setMatchAction: (draftRevision, matchId, action) =>
    send('set_match_action', { draftRevision, matchId, action }),
  addManualRedaction: (draftRevision, start, end) =>
    send('add_manual_redaction', { draftRevision, start, end }),
  removeManualRedaction: (draftRevision, manualId) =>
    send('remove_manual_redaction', { draftRevision, manualId }),
  clearDraft: () => send('clear_draft'),
  copyRedactedText: (draftRevision, reviewRevision) =>
    send('copy_redacted_text', { draftRevision, reviewRevision }),
}
