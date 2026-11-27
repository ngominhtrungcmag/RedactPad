import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { expect, it, vi } from 'vitest'
import { tauriScrubberClient as client } from './scrubberClient'

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }))
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn() }))

it('invokes only the scrubber commands with camelCase identifiers', async () => {
  await client.pickInput()
  await client.getSession()
  await client.getPreviewPage(4, 2)
  await client.exportToPickedDestination(4)
  await client.getExportStatus(7)
  await client.cancelExport(7)
  await client.clearSession(4)
  await client.clearSession(null)

  expect(vi.mocked(invoke).mock.calls).toEqual([
    ['scrubber_pick_input'],
    ['scrubber_get_session'],
    ['scrubber_get_preview_page', { sessionId: 4, pageIndex: 2 }],
    ['scrubber_export_to_picked_destination', { sessionId: 4 }],
    ['scrubber_get_export_status', { jobId: 7 }],
    ['scrubber_cancel_export', { jobId: 7 }],
    ['scrubber_clear_session', { sessionId: 4 }],
    ['scrubber_clear_session', { sessionId: null }],
  ])
})

it('queries File Scrubber support through the platform capability command', async () => {
  vi.mocked(invoke).mockResolvedValueOnce(true)

  expect(await client.isSupported()).toBe(true)
  expect(invoke).toHaveBeenLastCalledWith('file_scrubber_supported')
})

it('subscribes to sanitized drop payloads and returns the unsubscribe function', async () => {
  const unlisten = vi.fn()
  const onDrop = vi.fn()
  vi.mocked(listen).mockResolvedValue(unlisten)

  expect(await client.listenForDrop(onDrop)).toBe(unlisten)
  const [[event, handler]] = vi.mocked(listen).mock.calls
  expect(event).toBe('scrubber://drop')
  const summary = { sessionId: 4, displayName: 'sample.log', byteSize: 40, hasActiveExport: false }
  const error = { code: 'UnsupportedFormat', message: 'Choose a .log or .txt file.' }
  handler({ event, id: 1, payload: summary })
  handler({ event, id: 1, payload: error })
  expect(onDrop.mock.calls).toEqual([[summary], [error]])
})
