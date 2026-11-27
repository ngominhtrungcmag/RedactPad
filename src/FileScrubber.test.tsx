import { act, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { expect, it, vi } from 'vitest'
import App from './App'
import type { ExportJobSnapshot, PreviewPage, ScrubberClient, ScrubberDrop, ScrubberSessionSummary } from './scrubberClient'

const file: ScrubberSessionSummary = { sessionId: 1, displayName: 'sample.log', byteSize: 2048, hasActiveExport: false, activeJobId: null }
const running = { jobId: 8, sessionId: 1, state: 'Running' } as const
const unsupported = { code: 'UnsupportedFormat', message: 'Choose a .log or .txt file.' }
const literal = '<script>alert(1)</script><img src=x onerror=alert(1)>'

function page(pageIndex = 0, text = literal): PreviewPage {
  return { text, pageIndex, hasNext: pageIndex === 0, warnings: [], totalBytes: 2048, pageInputEnd: 2048 }
}

function setup(initialSession: typeof file | null = null) {
  let onDrop!: (value: ScrubberDrop) => void
  const client = {
    isSupported: () => Promise.resolve(true),
    pickInput: vi.fn<ScrubberClient['pickInput']>().mockResolvedValue(file),
    getSession: vi.fn<ScrubberClient['getSession']>().mockResolvedValueOnce(initialSession).mockResolvedValue(file),
    getPreviewPage: vi.fn<ScrubberClient['getPreviewPage']>()
      .mockImplementation(async (_, index) => index === 0 ? page() : page(index, 'Second page')),
    exportToPickedDestination: vi.fn<ScrubberClient['exportToPickedDestination']>().mockResolvedValue(running),
    getExportStatus: vi.fn<ScrubberClient['getExportStatus']>().mockResolvedValue(running),
    cancelExport: vi.fn<ScrubberClient['cancelExport']>()
      .mockResolvedValue({ ...running, state: 'Cancelled', cleanupWarning: false }),
    clearSession: vi.fn<ScrubberClient['clearSession']>().mockResolvedValue(null),
    listenForDrop: vi.fn<ScrubberClient['listenForDrop']>().mockImplementation(async (handler) => {
      onDrop = handler
      return () => {}
    }),
  } satisfies ScrubberClient
  const view = render(<App scrubberClient={client} />)
  return { ...view, client, user: userEvent.setup(), drop: (value: ScrubberDrop) => act(() => onDrop(value)) }
}

const button = (name: string) => screen.getByRole('button', { name })
const preview = () => screen.getByRole('region', { name: 'Redacted preview text' })

async function open(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole('button', { name: 'File' }))
  await user.click(button('Select .log or .txt file'))
  await screen.findByText(literal)
}

it('renders literal text, replaces each page, and uses no inline styles', async () => {
  const { user, client, container } = setup()
  await open(user)
  expect(screen.getByText('sample.log')).toBeVisible()
  expect(screen.getByText('2 KiB')).toBeVisible()
  expect(preview().textContent).toBe(literal)
  expect(preview().children).toHaveLength(0)
  expect(container.querySelector('[style]')).toBeNull()
  expect(button('Previous page')).toBeDisabled()
  await user.click(button('Next page'))
  expect(await screen.findByText('Second page')).toBeVisible()
  expect(screen.queryByText(literal)).toBeNull()
  expect(button('Next page')).toBeDisabled()
  await user.click(button('Previous page'))
  expect(await screen.findByText(literal)).toBeVisible()
  expect(screen.queryByText('Second page')).toBeNull()
  expect(client.getPreviewPage.mock.calls).toEqual([[1, 0], [1, 1], [1, 0]])
})

it('surfaces picker and drop errors and preserves the active file', async () => {
  const { client, user, drop } = setup()
  await open(user)
  client.pickInput.mockRejectedValueOnce(unsupported)
  await user.click(button('Select .log or .txt file'))
  expect(await screen.findByRole('alert')).toHaveTextContent(unsupported.message)
  drop({ ...file, sessionId: 2, displayName: 'replacement.txt' })
  expect(await screen.findByText('replacement.txt')).toBeVisible()
  drop(unsupported)
  expect(screen.getByRole('alert')).toHaveTextContent(unsupported.message)
  expect(screen.getByText('replacement.txt')).toBeVisible()
})

it('switches modes for a sanitized drop and ignores a superseded preview response', async () => {
  const { client, drop } = setup()
  let resolve!: (value: PreviewPage) => void
  client.getPreviewPage.mockImplementationOnce(() => new Promise((complete) => { resolve = complete }))
  await screen.findByRole('button', { name: 'File' })
  drop(file)
  expect(await screen.findByText('Loading preview…')).toBeVisible()
  drop({ ...file, sessionId: 2, displayName: 'new.txt' })
  expect(await screen.findByText(literal)).toBeVisible()
  await act(async () => resolve(page(0, 'stale preview')))
  expect(preview().textContent).toBe(literal)
  expect(screen.getByText('new.txt')).toBeVisible()
})

it('explains every blocking limitation and prevents export', async () => {
  const { client, user } = setup()
  client.getPreviewPage.mockResolvedValueOnce({
    ...page(), warnings: [
      'OversizedPemBlock', 'UnclosedPemBlock', 'UnsupportedMultilineCandidate',
      'OversizedRuleCandidate', 'OversizedOverlapCluster',
    ],
  })
  await open(user)
  const warning = screen.getByRole('alert')
  for (const message of [
    'Export is blocked', 'A PEM private key block exceeds the supported size.',
    'A PEM private key block is unclosed.', 'A quoted credential spans multiple lines.',
    'A candidate exceeds the supported size.', 'Overlapping candidates exceed the supported size.',
  ]) expect(warning).toHaveTextContent(message)
  expect(button('Export redacted copy')).toBeDisabled()
  await user.click(button('Export redacted copy'))
  expect(client.exportToPickedDestination).not.toHaveBeenCalled()
})

it.each([
  [{ ...running, state: 'Published' }, 'Redacted copy exported.', 'status'],
  [{ ...running, state: 'PublishedWithWarning', warning: 'Directory sync failed.' }, 'Redacted copy was published. Directory sync failed.', 'alert'],
  [{ ...running, state: 'Failed', code: 'AlreadyExists', message: 'Choose a destination that does not exist.', cleanupWarning: false }, 'Choose a destination that does not exist.', 'alert'],
] satisfies [ExportJobSnapshot, string, string][])('polls and shows the %j terminal result', async (result, message, role) => {
  const { client, user } = setup()
  await open(user)
  client.getExportStatus.mockResolvedValueOnce(result)
  await user.click(button('Export redacted copy'))
  expect(button('Clear file')).toBeDisabled()
  expect(button('Cancel export')).toBeEnabled()
  expect(await screen.findByText(message)).toHaveAttribute('role', role)
  expect(client.getExportStatus).toHaveBeenCalledWith(8)
  expect(screen.getByText('sample.log')).toBeVisible()
  expect(button('Export redacted copy')).toBeEnabled()
})

it.each([
  [{ ...running, state: 'Cancelled', cleanupWarning: true }, 'Export cancelled before publication. Temporary output cleanup could not be confirmed.'],
  [{ ...running, state: 'Published' }, 'Redacted copy exported.'],
  [{ ...running, state: 'PublishedWithWarning', warning: 'Directory sync failed.' }, 'Redacted copy was published. Directory sync failed.'],
] satisfies [ExportJobSnapshot, string][])('reports the actual outcome when cancel returns %j', async (result, message) => {
  const { client, user } = setup()
  await open(user)
  client.cancelExport.mockResolvedValueOnce(result)
  await user.click(button('Export redacted copy'))
  await user.click(button('Cancel export'))
  expect(await screen.findByText(message)).toBeVisible()
  expect(client.cancelExport).toHaveBeenCalledWith(8)
})

it('keeps the file when the save dialog is dismissed', async () => {
  const { client, user } = setup()
  client.exportToPickedDestination.mockResolvedValueOnce(null)
  await open(user)
  await user.click(button('Export redacted copy'))
  expect(screen.getByText('sample.log')).toBeVisible()
  expect(button('Export redacted copy')).toBeEnabled()
  expect(screen.queryByRole('alert')).toBeNull()
})

it('supports tab, Enter and Space through mode switching, selection, pagination, export, cancel and clear', async () => {
  const { user, client } = setup()
  await screen.findByRole('button', { name: 'File' })
  await user.tab()
  expect(button('Text')).toHaveFocus()
  await user.tab()
  expect(button('File')).toHaveFocus()
  await user.tab()
  expect(button('Source')).toHaveFocus()
  await user.tab()
  expect(button('Preview')).toHaveFocus()
  await user.tab()
  expect(screen.getByRole('textbox', { name: 'Source' })).toHaveFocus()
  await user.tab({ shift: true })
  await user.tab({ shift: true })
  await user.tab({ shift: true })
  expect(button('File')).toHaveFocus()
  await user.keyboard('{Enter}')
  await user.tab()
  expect(button('Select .log or .txt file')).toHaveFocus()
  await user.keyboard(' ')
  await screen.findByText(literal)
  await user.tab()
  expect(button('Clear file')).toHaveFocus()
  await user.tab()
  expect(preview()).toHaveFocus()
  await user.tab()
  expect(button('Next page')).toHaveFocus()
  await user.keyboard('{Enter}')
  await screen.findByText('Second page')
  await user.tab()
  expect(button('Previous page')).toHaveFocus()
  await user.tab()
  expect(button('Export redacted copy')).toHaveFocus()
  await user.keyboard(' ')
  await user.tab()
  expect(button('Cancel export')).toHaveFocus()
  await user.keyboard('{Enter}')
  await screen.findByText('Export cancelled before publication.')
  await user.tab({ shift: true })
  await user.tab({ shift: true })
  await user.tab({ shift: true })
  expect(button('Clear file')).toHaveFocus()
  await user.keyboard(' ')
  expect(client.clearSession).toHaveBeenCalledWith(1)
  expect(screen.queryByText('sample.log')).toBeNull()
  expect(button('Select .log or .txt file')).toHaveFocus()
})

it('ignores an in-flight poll after cancellation settles', async () => {
  const { client, user } = setup()
  let settlePoll!: (value: ExportJobSnapshot) => void
  client.getExportStatus.mockImplementationOnce(() => new Promise((resolve) => { settlePoll = resolve }))
  await open(user)
  await user.click(button('Export redacted copy'))
  await vi.waitFor(() => expect(client.getExportStatus).toHaveBeenCalledWith(8))
  await user.click(button('Cancel export'))
  expect(await screen.findByText('Export cancelled before publication.')).toBeVisible()
  await act(async () => settlePoll(running))
  expect(screen.queryByRole('button', { name: 'Cancel export' })).toBeNull()
  expect(screen.getByText('Export cancelled before publication.')).toBeVisible()
})

const restoredJob = { ...running, jobId: 42 }

it('resumes polling and cancels an export restored on reload', async () => {
  const { client, user } = setup({ ...file, hasActiveExport: true, activeJobId: 42 })
  client.getExportStatus.mockResolvedValue(restoredJob)
  client.cancelExport.mockResolvedValue({ ...restoredJob, state: 'Cancelled', cleanupWarning: false })

  await user.click(await screen.findByRole('button', { name: 'File' }))
  const cancel = await screen.findByRole('button', { name: 'Cancel export' })
  expect(cancel).toBeEnabled()
  expect(button('Clear file')).toBeDisabled()
  await vi.waitFor(() => expect(client.getExportStatus).toHaveBeenCalledWith(42))
  await user.click(cancel)

  expect(client.cancelExport).toHaveBeenCalledWith(42)
  expect(await screen.findByText('Export cancelled before publication.')).toBeVisible()
  expect(screen.queryByRole('button', { name: 'Cancel export' })).toBeNull()
  expect(button('Clear file')).toBeEnabled()
})

it('re-enables actions when a restored export finishes during polling', async () => {
  const { client, user } = setup({ ...file, hasActiveExport: true, activeJobId: 42 })
  client.getExportStatus.mockResolvedValue({ ...restoredJob, state: 'Published' })

  await user.click(await screen.findByRole('button', { name: 'File' }))
  expect(await screen.findByText('Redacted copy exported.')).toBeVisible()
  expect(client.getExportStatus).toHaveBeenCalledWith(42)
  expect(button('Clear file')).toBeEnabled()
})
