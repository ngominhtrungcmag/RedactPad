import { act, fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import App from './App'
import { utf8ByteLength } from './utf8Offsets'
import { MAX_INPUT_BYTES } from './workbenchClient'
import type { EffectiveSpan, WorkbenchClient, WorkbenchSnapshot } from './workbenchClient'

const auto: EffectiveSpan = {
  id: 'auto-1-0', start: 5, end: 11, reason_id: 'credential.field', reason_label: 'Credential field', action: 'redact',
}
const manual = { id: 'manual-1', start: 0, end: 4, reason_id: 'manual.selection', reason_label: 'Manual selection' }
const sample = '🔐 secret'
const rejected = '[REDACTED:credential.field]'

function snapshot(text: string, draftRevision = 1, reviewRevision = 0): WorkbenchSnapshot {
  return {
    draft_revision: draftRevision,
    review_revision: reviewRevision,
    byte_length: utf8ByteLength(text),
    max_bytes: MAX_INPUT_BYTES,
    matches: [],
    manual_redactions: [],
    effective_spans: [],
    redacted_preview: text,
    warnings: [],
  }
}

function matched(allowed = false, revision = 0): WorkbenchSnapshot {
  const span: EffectiveSpan = { ...auto, action: allowed ? 'allow' : 'redact' }
  return {
    ...snapshot(sample, 1, revision),
    matches: [{ ...span, overridden_by_manual: false }],
    effective_spans: [span],
    redacted_preview: allowed ? sample : `🔐 ${rejected}`,
  }
}

function mockClient() {
  return {
    analyzeDraft: vi.fn<WorkbenchClient['analyzeDraft']>().mockResolvedValue(matched()),
    setMatchAction: vi.fn<WorkbenchClient['setMatchAction']>().mockResolvedValue(matched(true, 1)),
    addManualRedaction: vi.fn<WorkbenchClient['addManualRedaction']>(),
    removeManualRedaction: vi.fn<WorkbenchClient['removeManualRedaction']>(),
    clearDraft: vi.fn<WorkbenchClient['clearDraft']>().mockResolvedValue(snapshot('', 2)),
    copyRedactedText: vi.fn<WorkbenchClient['copyRedactedText']>()
      .mockImplementation(async (draft_revision, review_revision) => ({ draft_revision, review_revision })),
  }
}

function deferred() {
  let resolve!: (value: WorkbenchSnapshot) => void
  const promise = new Promise<WorkbenchSnapshot>((complete) => { resolve = complete })
  return { promise, resolve }
}

const source = () => screen.getByRole<HTMLTextAreaElement>('textbox', { name: 'Source' })
const copyButton = () => screen.getByRole('button', { name: 'Copy redacted text' })
const preview = () => screen.getByRole('region', { name: 'Redacted preview' })
const highlights = () => screen.getByRole('region', { name: 'Highlighted text' })
const selectionButton = () => screen.getByRole('button', { name: 'Redact selection' })
const allowButton = () => screen.getByRole('button', { name: 'Allow Credential field (match 1)' })
const editorView = (name: 'Source' | 'Preview') => within(
  screen.getByRole('group', { name: 'Editor view' }),
).getByRole('button', { name })
const showPreview = () => fireEvent.click(editorView('Preview'))
const showSource = () => fireEvent.click(editorView('Source'))
const edit = (value: string) => fireEvent.change(source(), { target: { value } })

it('renders untrusted source and exact preview literally and shows the persistent warning', async () => {
  const client = mockClient()
  const payload = '<img src=x onerror=alert(1)>\n<script>alert(1)</script>'
  client.analyzeDraft.mockResolvedValue(snapshot(payload))
  const { container } = render(<App client={client} />)
  showPreview()
  expect(copyButton()).toBeDisabled()
  expect(client.copyRedactedText).not.toHaveBeenCalled()

  showSource()
  edit(payload)
  await act(async () => {})
  expect(source()).toHaveValue(payload)
  expect(highlights()).toHaveTextContent('<img src=x onerror=alert(1)>')
  showPreview()
  expect(preview().querySelector('pre')?.textContent).toBe(payload)
  expect(container.querySelector('img, script, a, [style], style')).toBeNull()
  expect(screen.getByText('Unflagged text can still be sensitive')).toBeVisible()
  expect(client.copyRedactedText).not.toHaveBeenCalled()
})

it('analyzes the fabricated sample through the regular review flow', async () => {
  const client = mockClient()
  const user = userEvent.setup()
  const key = 'sk_test_FAKEsample00000000000001'
  const stripe = { ...auto, reason_id: 'provider.stripe_key', reason_label: 'Stripe key' }
  client.analyzeDraft.mockImplementationOnce(async (text) => {
    const start = text.indexOf(key)
    const span = { ...stripe, start, end: start + key.length }
    return {
      ...snapshot(text),
      matches: [{ ...span, overridden_by_manual: false }],
      effective_spans: [span],
      redacted_preview: text.replace(key, '[REDACTED:provider.stripe_key]'),
    }
  })
  render(<App client={client} />)

  await user.click(screen.getByRole('button', { name: 'Load synthetic sample' }))
  const text = source().value
  expect(client.analyzeDraft).toHaveBeenCalledExactlyOnceWith(text, null)
  expect(text).toContain(key)
  expect(text).toContain('Authorization: Bearer synthetic_bearer_demo_9876543210')
  expect(text).toContain('postgres://demo:fake-pass@db.example.test:5432/app')
  expect(text).toContain('alex@example.test')
  expect(highlights().querySelector('mark')).toHaveTextContent(key)
  expect(screen.getByRole('button', { name: 'Allow Stripe key (match 1)' })).toBeEnabled()
  expect(source()).toHaveFocus()
  await user.click(editorView('Preview'))
  expect(preview()).toHaveTextContent('[REDACTED:provider.stripe_key]')
  expect(preview()).not.toHaveTextContent(key)
  expect(preview()).toHaveTextContent('00000000-0000-4000-8000-000000000001')
  expect(preview()).toHaveTextContent('v2.4.0')
  expect(copyButton()).toBeEnabled()
})

it('supports paste, selection, match actions, copy, and clear by keyboard', async () => {
  const client = mockClient()
  function withManualRedaction(allowed: boolean, revision: number): WorkbenchSnapshot {
    const base = matched(allowed, revision)
    return {
      ...base,
      manual_redactions: [manual],
      effective_spans: [{ ...manual, action: 'redact' }, ...base.effective_spans],
      redacted_preview: `[REDACTED_MANUAL] ${allowed ? 'secret' : rejected}`,
    }
  }
  client.addManualRedaction.mockResolvedValue(withManualRedaction(false, 1))
  client.setMatchAction
    .mockResolvedValueOnce(withManualRedaction(true, 2))
    .mockResolvedValueOnce(withManualRedaction(false, 3))
  client.removeManualRedaction.mockResolvedValue(matched(false, 4))
  const user = userEvent.setup()
  render(<App client={client} />)

  await user.tab()
  expect(screen.getByRole('button', { name: 'Text' })).toHaveFocus()
  await user.tab()
  expect(screen.getByRole('button', { name: 'File' })).toHaveFocus()
  await user.tab()
  expect(editorView('Source')).toHaveFocus()
  await user.tab()
  expect(editorView('Preview')).toHaveFocus()
  await user.tab()
  expect(source()).toHaveFocus()
  await user.tab()
  expect(screen.getByRole('button', { name: 'Load synthetic sample' })).toHaveFocus()
  await user.tab({ shift: true })
  expect(source()).toHaveFocus()
  await user.paste(sample)
  expect(client.analyzeDraft).toHaveBeenCalledWith(sample, null)
  expect(highlights().querySelector('mark')).toHaveTextContent('secretRedacted · Credential field')
  expect(within(screen.getByRole('list')).getByText('credential.field')).toBeVisible()
  await user.keyboard('{Home}{Shift>}{ArrowRight}{/Shift}')
  // jsdom models selection offsets in UTF-16 code units, so select the entire emoji.
  source().setSelectionRange(0, 2)
  await user.tab()
  expect(selectionButton()).toHaveFocus()
  await user.keyboard('{Enter}')
  expect(client.addManualRedaction).toHaveBeenCalledWith(1, 0, 4)
  await user.tab()
  expect(screen.getByRole('region', { name: 'Source highlights' })).toHaveFocus()
  await user.tab()
  expect(allowButton()).toHaveFocus()
  await user.keyboard(' ')
  expect(client.setMatchAction).toHaveBeenLastCalledWith(1, auto.id, 'allow')
  expect(screen.getByText('Allowed')).toBeVisible()
  await user.keyboard('{Enter}')
  expect(client.setMatchAction).toHaveBeenLastCalledWith(1, auto.id, 'redact')

  await user.tab()
  expect(screen.getByRole('button', { name: 'Remove manual redaction 1' })).toHaveFocus()
  await user.keyboard('{Enter}')
  expect(client.removeManualRedaction).toHaveBeenCalledWith(1, manual.id)
  expect(client.copyRedactedText).not.toHaveBeenCalled()

  expect(selectionButton()).toHaveFocus()
  await user.tab({ shift: true })
  await user.tab({ shift: true })
  expect(editorView('Preview')).toHaveFocus()
  await user.keyboard('{Enter}')
  await user.tab()
  expect(screen.getByRole('region', { name: 'Preview text' })).toHaveFocus()
  await user.tab()
  expect(copyButton()).toHaveFocus()
  await user.keyboard('{Enter}')
  expect(client.copyRedactedText).toHaveBeenCalledExactlyOnceWith(1, 4)
  expect(screen.getByRole('status')).toHaveTextContent('Redacted text copied.')
  await user.tab()
  expect(screen.getByRole('button', { name: 'Clear' })).toHaveFocus()
  await user.keyboard(' ')
  expect(client.clearDraft).toHaveBeenCalledOnce()
  expect(editorView('Preview')).toHaveFocus()
  expect(editorView('Preview')).toHaveAttribute('aria-pressed', 'true')
  expect(copyButton()).toBeDisabled()
  expect(preview()).toHaveTextContent('Redacted text will appear here.')
  await user.tab({ shift: true })
  await user.keyboard('{Enter}')
  expect(source()).toHaveValue('')
})

it('ignores out-of-order analyze results and shows only the latest rendered pair', async () => {
  const client = mockClient()
  const older = deferred()
  const newer = deferred()
  client.analyzeDraft.mockReturnValueOnce(older.promise).mockReturnValueOnce(newer.promise)
  render(<App client={client} />)
  edit('older')
  edit('newer')
  showPreview()
  expect(copyButton()).toBeDisabled()
  expect(screen.getByRole('status')).toHaveTextContent('Analyzing text')
  await act(async () => newer.resolve(snapshot('newer', 2)))
  expect(copyButton()).toBeEnabled()
  await act(async () => older.resolve(snapshot('older')))
  expect(preview()).toHaveTextContent('newer')
  showSource()
  expect(highlights().querySelector('[data-draft-revision]')).toHaveAttribute('data-draft-revision', '2')
  showPreview()
  fireEvent.click(copyButton())
  expect(client.copyRedactedText).toHaveBeenCalledExactlyOnceWith(2, 0)
})

it.each(['toggle', 'manual'] as const)('ignores a late %s response after a new draft has rendered', async (operation) => {
  const client = mockClient()
  const late = deferred()
  const fresh = deferred()
  client.analyzeDraft.mockResolvedValueOnce(matched()).mockReturnValueOnce(fresh.promise)
  client.setMatchAction.mockReturnValueOnce(late.promise)
  client.addManualRedaction.mockReturnValueOnce(late.promise)
  render(<App client={client} />)
  edit(sample)
  await act(async () => {})
  if (operation === 'toggle') {
    fireEvent.click(allowButton())
    expect(client.setMatchAction).toHaveBeenCalledOnce()
  } else {
    source().setSelectionRange(0, 2)
    fireEvent.keyDown(source(), { key: 'R', ctrlKey: true, shiftKey: true })
    expect(client.addManualRedaction).toHaveBeenCalledExactlyOnceWith(1, 0, 4)
  }
  showPreview()
  expect(copyButton()).toBeDisabled()
  expect(screen.getByRole('status')).toHaveTextContent('Updating review')
  showSource()
  edit('new draft')
  showPreview()
  expect(copyButton()).toBeDisabled()
  await act(async () => fresh.resolve(snapshot('new draft', 2)))
  await act(async () => late.resolve(matched(true, 1)))
  expect(copyButton()).toBeEnabled()
  expect(preview()).toHaveTextContent('new draft')
  expect(screen.queryByRole('list')).not.toBeInTheDocument()
  expect(client.copyRedactedText).not.toHaveBeenCalled()
})

it('clears previously applied overrides on edit and gates copy until the new preview returns', async () => {
  const client = mockClient()
  const fresh = deferred()
  client.analyzeDraft.mockResolvedValueOnce(matched()).mockReturnValueOnce(fresh.promise)
  render(<App client={client} />)
  edit(sample)
  await act(async () => {})
  fireEvent.click(allowButton())
  await act(async () => {})
  showPreview()
  expect(preview()).toHaveTextContent(sample)
  showSource()
  edit(sample + '!')
  showPreview()
  expect(copyButton()).toBeDisabled()
  await act(async () => fresh.resolve({ ...matched(), draft_revision: 2, byte_length: 12, redacted_preview: `🔐 ${rejected}!` }))
  expect(allowButton()).toBeVisible()
  expect(preview()).toHaveTextContent(rejected)
  expect(copyButton()).toBeEnabled()
})

it.each(['analysis', 'review'] as const)('surfaces %s failures without rendering raw IPC errors or enabling copy', async (operation) => {
  const client = mockClient()
  const failure = { message: 'sensitive IPC detail' }
  if (operation === 'analysis') client.analyzeDraft.mockRejectedValueOnce(failure)
  client.setMatchAction.mockRejectedValueOnce(failure)
  render(<App client={client} />)
  edit(sample)
  await act(async () => {})
  if (operation === 'review') {
    fireEvent.click(allowButton())
    await act(async () => {})
  }
  expect(screen.getByRole('alert')).toHaveTextContent(/Could not (analyze|update)/)
  expect(screen.queryByText(failure.message)).not.toBeInTheDocument()
  expect(source()).toHaveValue(sample)
  showPreview()
  expect(copyButton()).toBeDisabled()
})

it.each(['UI', 'Rust'] as const)('preserves the accepted reviewed draft after %s oversize rejection', async (origin) => {
  const client = mockClient()
  client.analyzeDraft.mockResolvedValueOnce(matched()).mockRejectedValueOnce({ code: 'InputTooLarge' })
  render(<App client={client} />)
  edit(sample)
  await act(async () => {})
  fireEvent.click(allowButton())
  await act(async () => {})
  edit(origin === 'UI' ? '🔐'.repeat(MAX_INPUT_BYTES / 4 + 1) : 'rejected by Rust')
  await act(async () => {})
  expect(screen.getByRole('alert')).toHaveTextContent('1 MiB')
  expect(source()).toHaveValue(sample)
  showPreview()
  expect(preview()).toHaveTextContent(sample)
  expect(client.analyzeDraft).toHaveBeenCalledTimes(origin === 'UI' ? 1 : 2)
  expect(copyButton()).toBeEnabled()
  fireEvent.click(copyButton())
  expect(client.copyRedactedText).toHaveBeenCalledExactlyOnceWith(1, 1)
})

it.each([
  { label: 'missing', fields: {} },
  { label: 'inconsistent', fields: { redacted_preview: sample } },
])('rejects a snapshot with a $label preview and blocks copy', async ({ fields }) => {
  const client = mockClient()
  const { redacted_preview: validPreview, ...rest } = matched()
  client.analyzeDraft.mockResolvedValueOnce({ ...rest, ...fields } as WorkbenchSnapshot)
  render(<App client={client} />)

  edit(sample)
  expect(await screen.findByRole('alert')).toHaveTextContent('Could not analyze the text.')
  expect(screen.getByRole('alert')).not.toHaveTextContent(sample)
  showPreview()
  expect(preview()).not.toHaveTextContent(validPreview)
  expect(preview()).not.toHaveTextContent(sample)
  expect(copyButton()).toBeDisabled()
  fireEvent.click(copyButton())
  expect(client.copyRedactedText).not.toHaveBeenCalled()
})

it.each(['analysis', 'review', 'clear'] as const)('rejects a malformed %s snapshot and blocks copy', async (operation) => {
  const client = mockClient()
  const invalidPreview = 'Unvalidated preview'
  if (operation === 'analysis') {
    client.analyzeDraft.mockResolvedValueOnce({
      ...matched(), effective_spans: [{ ...auto, start: 1 }], redacted_preview: invalidPreview,
    })
  }
  client.setMatchAction.mockResolvedValueOnce({
    ...matched(true, 1), byte_length: 12, redacted_preview: invalidPreview,
  })
  client.clearDraft.mockResolvedValueOnce({ ...snapshot('', 2), byte_length: 1, redacted_preview: invalidPreview })
  render(<App client={client} />)
  edit(sample)
  await act(async () => {})
  showPreview()
  if (operation !== 'analysis') {
    expect(copyButton()).toBeEnabled()
    fireEvent.click(operation === 'review' ? allowButton() : screen.getByRole('button', { name: 'Clear' }))
    await act(async () => {})
    expect(preview()).toHaveTextContent(rejected)
  }
  expect(screen.getByRole('alert')).toHaveTextContent(/Could not (analyze|update|clear)/)
  expect(screen.getByRole('alert')).not.toHaveTextContent(sample)
  expect(preview()).not.toHaveTextContent(invalidPreview)
  expect(copyButton()).toBeDisabled()
  fireEvent.click(copyButton())
  expect(client.copyRedactedText).not.toHaveBeenCalled()
})

it.each([false, true])('labels manual coverage and gates the match action (fully covered: %s)', async (fullyCovered) => {
  const client = mockClient()
  const entry = { ...manual, start: 5, end: fullyCovered ? 11 : 8 }
  const original = matched(true)
  client.analyzeDraft.mockResolvedValueOnce({
    ...original,
    matches: [{ ...original.matches[0], overridden_by_manual: fullyCovered }],
    manual_redactions: [entry],
    redacted_preview: fullyCovered ? '🔐 [REDACTED_MANUAL]' : '🔐 [REDACTED_MANUAL]ret',
    effective_spans: [
      { ...entry, action: 'redact' },
      ...(!fullyCovered ? [{ ...original.effective_spans[0], start: entry.end }] : []),
    ],
  })
  render(<App client={client} />)
  edit(sample)
  await act(async () => {})
  const action = screen.getByRole('button', { name: 'Redact Credential field (match 1)' })
  const match = within(screen.getAllByRole('listitem')[0])
  expect(match.getByText(fullyCovered ? 'Covered by manual redaction' : 'Partially covered by manual redaction')).toBeVisible()
  expect(action).toHaveAttribute('aria-disabled', String(fullyCovered))
})

it('keeps the reviewed pair copyable after clipboard rejection and retries it unchanged', async () => {
  const client = mockClient()
  client.copyRedactedText.mockRejectedValueOnce({ code: 'ClipboardWriteFailed' })
  render(<App client={client} />)
  edit(sample)
  await act(async () => {})
  fireEvent.click(allowButton())
  await act(async () => {})
  showPreview()
  fireEvent.click(copyButton())
  await act(async () => {})
  expect(screen.getByRole('alert')).toHaveTextContent('clipboard')
  showSource()
  expect(source()).toHaveValue(sample)
  showPreview()
  expect(preview()).toHaveTextContent(sample)
  expect(copyButton()).toBeEnabled()
  fireEvent.click(copyButton())
  await act(async () => {})
  expect(client.copyRedactedText.mock.calls).toEqual([[1, 1], [1, 1]])
  expect(screen.getByRole('status')).toHaveTextContent('Redacted text copied.')
})

it('surfaces the oversized PEM warning and rejects an invalid selection without changing the review', async () => {
  const client = mockClient()
  client.analyzeDraft.mockResolvedValue({ ...matched(), warnings: ['OversizedPemBlock'] })
  render(<App client={client} />)
  edit(sample)
  await act(async () => {})
  source().setSelectionRange(1, 2)
  fireEvent.click(selectionButton())
  expect(screen.getByRole('alert')).toHaveTextContent('Select a valid range')
  expect(screen.getByText('A PEM private key block exceeded 16 KiB and was skipped.')).toBeVisible()
  expect(client.addManualRedaction).not.toHaveBeenCalled()
  showPreview()
  expect(copyButton()).toBeEnabled()
})

it('defaults to Text Workbench and preserves the text draft when switching modes', async () => {
  const user = userEvent.setup()
  render(<App client={mockClient()} />)
  const modes = within(screen.getByRole('navigation', { name: 'Workbench mode' }))
  const text = modes.getByRole('button', { name: 'Text' })
  const file = modes.getByRole('button', { name: 'File' })
  expect(text).toHaveAttribute('aria-pressed', 'true')
  await act(async () => { edit(sample) })
  await user.click(file)
  expect(file).toHaveAttribute('aria-pressed', 'true')
  expect(screen.queryByRole('textbox', { name: 'Source' })).toBeNull()
  await user.click(text)
  expect(source()).toHaveValue(sample)
})

it('keeps the textarea and its value when switching editor views', async () => {
  const user = userEvent.setup()
  render(<App client={mockClient()} />)
  await act(async () => { edit(sample) })
  const textarea = source()
  textarea.setSelectionRange(0, 2)
  const views = within(screen.getByRole('group', { name: 'Editor view' }))
  await user.click(views.getByRole('button', { name: 'Preview' }))
  expect(textarea).not.toBeVisible()
  await user.click(views.getByRole('button', { name: 'Source' }))
  expect(source()).toBe(textarea)
  expect(textarea).toHaveValue(sample)
  expect(textarea.selectionStart).toBe(0)
  expect(textarea.selectionEnd).toBe(2)
})
