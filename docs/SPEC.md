# RedactPad v0.1 MVP specification

## Problem and audience

Developers and support engineers routinely share snippets from terminals,
configuration files, and tickets. Reviewing these manually costs time,
especially when a snippet mixes known credential shapes with names and
contact details. RedactPad provides an offline review step before sharing.

The first release targets macOS Apple silicon. A daily snippet should fit
a roughly ten-second paste, review, and copy loop. The release usability
gate gives first-time users up to 30 seconds.

## Scope

- Text and Clipboard Workbench for UTF-8 snippets.
- Streaming plain-text File Scrubber for `.log` and `.txt`.
- Optional, release-gated Reversible Restore for text sessions.
- Packaged and verified zero-network macOS ARM64 build.

OCR, local ML/NER, live proxies, and cloud sync are outside v0.1.
Format-aware parsing, shared CLI configuration, and other OS packages
are on the v0.2+ roadmap.

## Text and Clipboard Workbench

Accept up to 1 MiB of UTF-8, measured in bytes. Reject oversized input
with a visible error and leave the last accepted draft intact. Validate
at the Rust command boundary as well as in the UI.

Start detection on paste or edit. At 100 KiB, paste to rendered preview
must take at most 200 ms at p95. Bind results to the draft revision so a
late response cannot overwrite the current preview. Disable copying while
the current revision is awaiting detection or if detection failed.

Highlight matching spans and display the detector reason for each.
Provide accessible labels, visible focus, and a keyboard path from editor
to matches and the **Copy redacted text** action. Use labels as well as
color to communicate state.

Matches start in the redact state. The user can allow or re-redact a
match, or mark a missed secret by selecting text. Clear overrides on a
source edit and show the refreshed review before enabling copy again.
An explicit manual redaction takes precedence over automatic matches
it overlaps. Use deterministic precedence for overlapping rules.

Copy the current reviewed output only in response to a user action.
Show clipboard write failures and keep the current draft available for
retry. Display “Unflagged text can still be sensitive” during review.

## Detection defaults

| Category | Default match criteria |
| --- | --- |
| Provider credentials | Supported prefixes and shapes for AWS, GitHub, OpenAI, Anthropic, Slack, and Stripe |
| Authentication | JWT structure and Bearer or Basic credentials in authorization context |
| Connection strings | Credential-bearing database connection strings |
| Private keys | PEM private key blocks within a documented byte bound |
| Credential fields | Recognized key-value contexts such as password, API key, and client secret |
| Email | Plausible email address shape |
| Payment card | Valid Luhn checksum plus nearby payment context |
| Phone | A phone label or explicit locale opt-in |

Bare UUIDs, Git SHAs, timestamps, semantic versions, and bare high-entropy
strings are ordinary text unless an explicit credential context applies.
Keep reason IDs stable across runs and cover their mappings in fixtures.

Rust returns half-open UTF-8 byte ranges and reason IDs for text.
The UI converts byte offsets to JavaScript UTF-16 indices for display.
Rust checks replacement ranges and applies them against the matching
draft revision. Render pasted text literally.

## File Scrubber

Accept only regular `.log` and `.txt` files through user selection or
drop. Validate paths and reject an export targeting the input, including
aliases. Use a separate user-selected destination and report I/O errors.
Rust owns input, preview, and output file handles.

Scan raw byte buffers. Retain bounded overlap and left context, handle
UTF-8 and CRLF splits, and copy unmatched bytes unchanged. Keep file
processing independent of line length. Report unsupported or oversized
multiline candidates, including PEM blocks past the supported bound,
and block export when such a candidate cannot be safely handled.
Show which limitation triggered the block without logging the secret.

Show paginated redacted preview and file-level warnings. Each serialized
preview IPC response, including metadata and escaping, is at most
256 KiB. Bound the amount of redacted file data retained by the WebView.

Write to an exclusive, private temporary file beside the destination.
Flush and sync it before atomically publishing the complete output.
Use no-clobber publication for v0.1 and report an existing destination.
Cancel up to the publication boundary, close handles, and remove the
temporary output. A cancellation after publication reports completion.
File exports use irreversible markers and create no restore entries.

## Reversible Restore

Expose an explicit opt-in for the Text Workbench. Use a Rust-owned,
RAM-only session map. Each placeholder has the fixed ASCII form
`[[RP_<session>_<counter>]]`, with a random session ID and a monotonic
counter. Use an OS CSPRNG for the session ID. Allocate a unique token for
each distinct value and reuse that token on exact repeats.

Before copying, check for token collisions with literal input. If a
generated token already occurs literally, block reversible copy and
allow the user to start a new restore session. Check that the counter
cannot wrap. Keep the original values out of reversible IPC output.

Restore only exact, active-session tokens in an explicit restore action.
Perform a single pass so substituted values cannot trigger further
restoration. Leave recognizable edited, unknown, expired, or foreign
tokens untouched and flag them. Tokens edited beyond recognition remain
literal. Use generic diagnostics when the reason cannot be determined.

Expire sessions after the documented inactivity timeout. Keep one live
session per workbench and zeroize owned values on clear, expiry, or
orderly exit. Surface restoration results locally and require a separate
user action to copy them. Ship the feature only if the round-trip,
edited-token, expired-session, and cross-session tests pass.

## Six engineering invariants

### 1. Preserve detection across chunk boundaries

Specify each streaming rule's maximum match length and lookaround
requirements. Keep enough right overlap and left context for those bounds.
Commit only bytes whose classification is final. Use absolute byte offsets
to apply a spanning replacement once. Resolve EOF explicitly.
A bounded PEM state machine must flag blocks that exceed the cap.

For representative fixtures, compare streamed output with detection over
the same complete buffer across every possible split point. Include
CRLF, split UTF-8, header context, multiple adjacent matches, matches at
EOF, long unbroken input, and PEM at and beyond the cap. Generate random
chunk partitions in property tests.

### 2. Measure precision on a synthetic corpus

Label expected byte spans and reasons independently of detector output.
Include supported provider fixtures and realistic mixed snippets with
true negatives. Use synthetic values only. Keep UUIDs, Git SHAs,
timestamps, semver, and bare entropy in the canonical negative set.

Score exact span plus reason. Precision is true positives divided by
all emitted matches after overlap resolution. Count supported provider
detection separately so an empty detector cannot pass. Give each rule
positive, near-miss, and boundary coverage.

### 3. Preserve format semantics

File mode treats `.log` and `.txt` as plain text. Bytes outside selected
spans must round-trip exactly. The workbench can review pasted snippets,
but copying a structured snippet carries no format-validity guarantee.

Defer JSONL, JSON, CSV, SQL, and dotenv file import to real parsers.
Their quoting, escaping, types, and references require format-aware
replacements. Reject unsupported formats and report future parser errors
explicitly without a silent raw-regex fallback. Test extension rejection
and byte-for-byte preservation on plain-text fixtures.

### 4. Bound the lifetime and claims of reversibility

Scope restore lookups to the current session. Test repeated values,
literal collisions, Unicode, exact round-trip, edited tokens, expiry,
and cross-session isolation. Use a controlled clock for expiry tests.
Ensure recognizable invalid tokens are reported and left untouched.

Use `zeroize` on owned Rust secret buffers and map entries. Test that
reset and expiry invalidate restore and exercise the orderly-exit cleanup
path. WebView memory, clipboard history, swap, and crash reports are
outside Rust's erasure control. See [Security](../SECURITY.md).

### 5. Bound IPC and publish atomically

Use bounded buffers throughout Rust and send only preview pages and
summary metadata over IPC. Test worst-case serialized page sizes,
including escape expansion, at the 256 KiB limit.

Inject cancellation, short writes, and disk-full failures before publish.
Verify that the input is unchanged, no partial destination appears,
and the temporary file is cleaned up on handled failures. Test races at
publication and verify the destination collision path. Record elapsed
time and Rust host peak RSS growth against the pre-job baseline.

### 6. Verify the packaged Tauri 2 app has zero network activity

Bundle release assets. Use a default-deny CSP with only local assets
and required IPC, deny remote navigation and new windows, grant minimal
capabilities, and exclude HTTP, updater, and telemetry plugins.
Review locked Cargo and pnpm dependencies.

Test the built macOS ARM64 app offline, then with network access under
process-attributed DNS and socket monitoring. Include WebView helpers.
Publish the artifact hash, system and tool versions, exercised paths,
and observations per release. See [Security](../SECURITY.md).

## Three iterations

### Week 1 — Detection core and Text Workbench

Deliver the Rust detector, synthetic labeled positive and negative
corpus, and keyboard-first paste, review, and copy flow.

- At least 99% precision on the labeled synthetic corpus.
- 100% detection on supported provider fixtures.
- Zero hits on canonical negative fixtures.
- Paste-to-rendered-preview p95 at most 200 ms at 100 KiB.
- See the [Week 1 kickoff](../TASK-00-KICKOFF.md) for the check procedure.

### Week 2 — File Scrubber

Deliver streaming export, paginated redacted preview, and cancellation.

- Process a 500 MiB fixture in at most 20 s, through publication.
- Use at most 64 MiB Rust host peak RSS growth on the recorded
  Apple silicon baseline.
- Stay at or below 256 KiB per serialized preview IPC response.
- Preserve bytes exactly outside replacement spans.
- Publish no partial file on cancellation or disk full.

### Week 3 — Verified macOS release and user trials

Package macOS ARM64 and publish the reproducible zero-network check.
Run five first-time trials with target users. At least four of five
must complete paste, review, and copy unaided in at most 30 s.

Include Reversible Restore only if its release tests pass. Measure
artifact size and cold startup on the recorded baseline before
advertising the targets of under 15 MB and under 1 s. Record the tested
artifact type and the timing endpoint.

## v0.2 and later

- Parser-backed JSONL, JSON, CSV, SQL, and dotenv.
- Dialect- and schema-aware SQL pseudonyms with consistent values across
  references so related rows retain referential integrity.
- CLI with shared `.redactpad.toml` configuration.
- Windows and Linux builds and packages.
