# Task 00 — Week 1 kickoff

Build the v0.1 detector and keyboard-first Text Workbench on macOS Apple
silicon. The deliverable is a local development build that can paste a
snippet, review matches and reasons, override them, and copy the result.

Read the [MVP specification](docs/SPEC.md) and [security contract](SECURITY.md).

## Stack and layout

Use Tauri 2, React 19, TypeScript, Vite, pnpm, and Rust stable.
Use pnpm for dependency management and track both dependency lockfiles
in the implementation changes. Record the toolchain versions used for
verification. Keep the Rust application in the `src-tauri` workspace.

```text
src/                         React workbench and UI tests
src-tauri/src/
  detector/                  Rules, spans, precedence, detector tests
  workbench/                 Draft review and replacement logic
  commands/                  Validated Tauri command boundaries
fixtures/corpus/              Synthetic text and expected spans/reasons
```

## Step 1 — Scaffold the offline baseline

- Use bundled Vite assets for release builds and a default-deny CSP
  with only required local assets and Tauri IPC sources.
- Deny remote navigation and new windows. Grant minimal clipboard and
  command permissions and exclude HTTP, updater, and telemetry plugins.
- Keep the development server on loopback. Build and open the release
  app offline as a Week 1 smoke test. Process-attributed verification
  of the shipping artifact is a Week 3 gate.
- Configure `lint`, `typecheck`, `test`, and `build` pnpm scripts.

## Step 2 — Label the synthetic corpus

- Record expected half-open UTF-8 byte spans and rule IDs for supported
  provider shapes and mixed logs, tickets, and config excerpts.
- Cover AWS, GitHub, OpenAI, Anthropic, Slack, and Stripe, plus JWT,
  Bearer/Basic auth, database URIs, bounded PEM, credential fields,
  email, Luhn with payment context, and labeled or locale-opt-in phones.
- Include near misses, Unicode, overlapping candidates, and ordinary
  UUIDs, Git SHAs, timestamps, semver, and bare high-entropy values.
- Use fabricated nonfunctional secrets. Label expected spans before
  running the detector and document how to reproduce corpus scoring.

## Step 3 — Implement the Rust detector

- Return deterministic, non-overlapping byte spans and stable reason
  IDs. Define rule and replacement precedence and test it.
- Enforce the 1 MiB UTF-8 cap at the Tauri boundary. Return explicit
  validation and processing errors without including raw input.
- Reject stale revisions and invalid replacement ranges. Apply manual
  redactions ahead of overlapping automatic matches.
- Unit-test supported shapes, canonical negatives, context, overlaps,
  invalid overrides, and limits. Property-test that emitted spans are
  ordered, disjoint, and valid UTF-8 boundaries and that applying
  replacements preserves all untouched bytes.

## Step 4 — Implement keyboard-first review

- Provide a labeled editor, highlighted spans, and an accessible list
  with reasons and allow/redact controls. Use visible focus and labels
  alongside color.
- Start detection on paste or edit. Keep the latest accepted draft on
  oversize rejection and ignore responses from previous revisions.
- Allow manual redaction of a text selection. Clear overrides on
  source edits and require a fresh preview before copy.
- Use **Copy redacted text** and perform clipboard writes only on user
  action. Surface clipboard errors and preserve the draft for retry.
- Display “Unflagged text can still be sensitive” during review.
- Verify the full path using the keyboard, including toggling, manual
  selection redaction, copying, and clearing.

## Verification

Run from the repository root after installing the locked dependencies.

```sh
cargo test --manifest-path src-tauri/Cargo.toml
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
pnpm lint
pnpm typecheck
pnpm test
pnpm build
pnpm exec tauri dev
pnpm exec tauri build
```

Use `tauri dev` for the manual desktop exercise, then exit it before
building the release package. Record the commands, outcomes, and
baseline hardware and OS in the work report.

Measure paste event to rendered highlights on a synthetic 100 KiB
UTF-8 snippet. Record the Apple silicon model, build type, trial count,
and p95. Use repeated pastes in the packaged app to include IPC and
rendering time.

Score precision as correct span-and-reason detections divided by all
emitted matches after overlap resolution. Report supported-provider
detection and canonical negative hits separately.

## Week 1 exit gate

- [ ] Rust tests and Clippy pass.
- [ ] Frontend lint, typecheck, tests, and build pass.
- [ ] The packaged app launches offline with bundled assets.
- [ ] Labeled synthetic corpus precision is at least 99%.
- [ ] Supported provider fixture detection is 100%.
- [ ] Canonical negative fixtures produce zero hits.
- [ ] Paste-to-rendered-preview p95 is at most 200 ms at 100 KiB.
- [ ] Keyboard review, overrides, manual redaction, and copy work.
- [ ] Input caps, stale results, and clipboard errors are exercised.

## Out of scope for Week 1

Streaming file export, preview, and cancellation belong to Week 2.
Reversible Restore, which reserves `[[RP_<session>_<counter>]]`, and
the full packaged network verification belong to Week 3. Structured
JSONL, JSON, CSV, SQL, and dotenv parsers, shared `.redactpad.toml`,
and Windows/Linux packages belong to v0.2+. Network plugins stay
outside v0.1. Keep changes local and obtain explicit approval before
creating any commit or pushing.
