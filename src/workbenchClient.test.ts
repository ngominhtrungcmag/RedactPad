import { invoke } from '@tauri-apps/api/core'
import { expect, it, vi } from 'vitest'
import { tauriWorkbenchClient as client } from './workbenchClient'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }))

it('sends ordered commands with exact Tauri arguments and continues after rejection', async () => {
  const ipc = vi.mocked(invoke)
  let rejectFirst!: (reason: unknown) => void
  ipc.mockImplementationOnce(() => new Promise((_, reject) => { rejectFirst = reject }))
  const first = client.analyzeDraft('draft', null)
  const firstError = expect(first).rejects.toEqual({ code: 'InputTooLarge' })
  const later = [
    client.setMatchAction(7, 'auto', 'allow'),
    client.addManualRedaction(7, 2, 3),
    client.removeManualRedaction(7, 'manual'),
    client.copyRedactedText(7, 3),
    client.clearDraft(),
  ]
  await Promise.resolve()
  expect(ipc).toHaveBeenCalledExactlyOnceWith('analyze_draft', { text: 'draft', options: null })
  rejectFirst({ code: 'InputTooLarge' })
  await firstError
  await Promise.all(later)
  expect(ipc.mock.calls).toEqual([
    ['analyze_draft', { text: 'draft', options: null }],
    ['set_match_action', { draftRevision: 7, matchId: 'auto', action: 'allow' }],
    ['add_manual_redaction', { draftRevision: 7, start: 2, end: 3 }],
    ['remove_manual_redaction', { draftRevision: 7, manualId: 'manual' }],
    ['copy_redacted_text', { draftRevision: 7, reviewRevision: 3 }],
    ['clear_draft', undefined],
  ])
})
