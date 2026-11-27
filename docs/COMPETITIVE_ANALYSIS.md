# RedactPad competitive analysis

## The workflow being compared

A developer or support engineer has a log excerpt, config snippet, or
ticket to share. They need to see what will be redacted, allow specific
values, and catch sensitive text the detector missed. They may need to
export a large plain-text log once in a while.

RedactPad v0.1 is designed around that review step on macOS Apple silicon.
The table compares operating models. Competitor capabilities are based
on the kickoff research and should be checked against the version being
evaluated. RedactPad's entries describe the planned MVP.

| Option | Approach | Best fit | Trade-off for this workflow |
| --- | --- | --- | --- |
| RedactPad | Offline keyboard-first desktop workbench and plain-text file scrubber | Daily mixed snippets that benefit from visual review | macOS ARM64 initially, with structured parsers deferred |
| `redacter-rs` | Rust CLI for bulk local, S3, and GCS processing with optional NER/GLiNER | Scripted jobs and bulk processing across storage systems | CLI-oriented workflow lacks an instant visual review and override workbench. Model-backed scans add runtime weight |
| `local-redact` | Python CLI using Presidio and Tesseract OCR | Scripted PII detection or documents needing OCR | Python and OCR system dependencies increase setup. Review takes place outside the static CLI flow |
| `contextio` / `cordon` | Local HTTP proxies for CLI or LLM agent traffic | Repeated redaction on a configured agent request path | Proxy setup or command wrapping is required. The model does not provide an ad hoc ticket or log review workbench |
| `cloakLLM` / `repo-cloak` | Browser extension or IDE integration | Redaction inside a supported browser or editor | Coverage depends on the host integration |
| DataVeil | JS/TS programmatic redaction library | Embedding redaction into an existing product or script | The integrator supplies the UI, review policy, and deployment |
| Manual find and replace | Editor search, selection, and replacement | Known values in a short snippet | Reviewing many patterns is repetitive and misses depend on the reviewer |
| Direct paste into AI chat | Submit unreviewed text | Material already approved for that destination | Sensitive values may reach the service before the user notices them |

## Where the workbench fits

### Day-to-day text review

Mixed snippets span terminal output, an editor, a ticket tracker, and
chat. A standalone paste surface works the same way across those sources.
Highlights and reason tags let the user inspect why a value matched.
Per-match overrides allow legitimate values through, and manual redaction
covers items that a rule missed.

A keyboard-first loop avoids configuring a proxy, adding an editor
extension, or writing a script before the first review. After installation,
routine use needs no account, network, or downloaded model. The Week 1
latency gate and Week 3 user trials will test that design. See the
[MVP specification](SPEC.md).

### Plain-text log exports

A bounded preview and separate output file suit occasional cleanup of
a large log. The target workflow includes cancellation, preserved line
endings, and byte-for-byte preservation outside replaced spans.
RedactPad v0.1 supports `.log` and `.txt` with irreversible file exports.

### Optional restore

Text sessions can use `[[RP_<session>_<counter>]]` placeholders if the
release tests pass. Exact active-session tokens let users restore an AI
reply locally. This suits a reviewed exchange when the destination does
not need original values. The user still evaluates which context they
can share.

## Where alternatives fit better

- Choose a Rust CLI such as `redacter-rs` for scheduled or bulk jobs,
  especially when input lives in S3 or GCS.
- Choose an OCR-capable tool such as `local-redact` for image-derived text
  or documents with no text layer.
- Choose a local proxy such as `contextio` or `cordon` when a configured
  request path serves recurring CLI or agent interactions.
- Choose a browser or IDE integration when sensitive input is
  consistently entered through that host.
- Choose DataVeil when redaction belongs inside an existing JS/TS
  application and the team controls the integration.
- Use manual find and replace for a few known values when inspection
  is straightforward.

## How to compare on your own workflow

Use the same synthetic ticket and log excerpt across tools. Include
ordinary identifiers, a supported credential shape, and one sensitive
value with no recognizable pattern. Record setup time separately from
review time. Check which tools show the proposed replacements before
sharing, allow individual overrides, and let the reviewer cover the
missed value. For recurring jobs, measure unattended throughput and
failure handling separately from the interactive workflow.

## Scope boundaries

RedactPad prioritizes precision on recognizable credentials and common
PII. Unflagged text can still be sensitive. A manual review remains part
of the workflow, and no performance or coverage claim extends beyond
the measured workload.

JSONL, JSON, CSV, SQL, and dotenv support are v0.2+ because safe rewriting
requires parsers and format-specific semantics. A shared
`.redactpad.toml` CLI and Windows/Linux packaging also belong to v0.2+.
OCR, local ML, proxying, and cloud sync are outside v0.1.
