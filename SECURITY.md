# Security

## Threat model

RedactPad reduces accidental disclosure when developers and support
engineers share text, logs, configuration excerpts, and tickets.
It treats pasted text, dropped files, and pasted AI replies as
untrusted input. The packaged app processes them locally.

- Render input as literal text. Never execute content or follow URLs
  found in it.
- Keep source text, matches, and restored values out of logs, analytics,
  preferences, and application-managed crash reporting.
- Access files through explicit selection and keep handles in Rust.
- Write to the clipboard only on an explicit copy action.
- Show redaction reasons and provide a review step before output leaves
  the workbench.

Unflagged text can still be sensitive. RedactPad offers heuristic
assistance rather than a formal data loss prevention guarantee. Its
threat model assumes a trusted OS and user account. Malware, privileged
local access, and what a recipient does with copied text are outside it.

## Release network contract

- Bundle scripts, styles, fonts, and other UI assets in the app.
- Default to `default-src 'none'` in the release CSP and explicitly
  permit only required local asset and Tauri IPC sources. Keep remote
  origins out of every directive.
- Deny remote top-level and frame navigation and deny new windows.
- Grant only the Tauri capabilities needed for the workbench and file
  workflow. Keep file access scoped to user-selected paths in Rust.
- Exclude HTTP, updater, and telemetry plugins. Avoid linked runtime
  services that make outbound connections.
- Build with locked Cargo and pnpm dependencies. Audit both resolved
  dependency graphs and review release capabilities and CSP changes.

Development tooling may use a loopback Vite server. The release gate
applies to the packaged build and its effective runtime configuration.

## Reproduce the packaged app verification

1. Build the macOS ARM64 release with locked dependencies. Record the
   source revision, artifact SHA-256, macOS version, machine, and build
   and monitoring tool versions.
2. Use a clean test account with synthetic data. Disable all external
   network interfaces, launch the packaged `.app`, and exercise paste,
   review, copy, file preview, export, and cancel. Exercise Reversible
   Restore if it ships. Verify that these flows work offline.
3. Enable connectivity and begin capture before launching the same app.
   Use a macOS process-aware DNS/socket monitor that records attempted
   connections, such as an approved Network Extension flow monitor.
   Confirm capture coverage with a separate known DNS/socket probe.
4. Attribute traffic by app identity, launch time, and process IDs.
   Include WebKit WebContent and Networking helpers associated with
   the app session even if their parent is a system service. Include
   resolver-mediated DNS and connections to numeric IP addresses.
   Repeat the workflows, observe idle operation, and quit under capture.
5. Require zero external DNS queries and socket attempts attributable
   to RedactPad or its WebView helpers. Record any local IPC observed.
   Unresolved attribution or missing capture coverage leaves the gate
   open.
6. Publish the artifact hash, build and capture commands or settings,
   test steps, capture duration, helper attribution method, and observed
   results with each release. Use only synthetic data in captures.

## Retention and memory limits

Reversible Restore is opt-in and available only in the Text Workbench.
Its `[[RP_<session>_<counter>]]` map lives in Rust RAM for the active
session. Rust uses `zeroize` on owned secret buffers at reset, expiry,
and orderly exit. File exports contain irreversible replacement markers.

The WebView, OS clipboard history, swap, and crash reports can hold
copies outside Rust's control. Whole-process erasure is unavailable.
Force termination or crashes can bypass cleanup. Copying moves data
into the OS clipboard, where other permitted applications may read it.

## Vulnerability disclosure

Use GitHub's private vulnerability reporting feature when the project
repository enables it. If no private channel is available, open a
minimal public issue asking maintainers for a private contact. Keep
reproduction details private until a disclosure timeline is agreed.

Include the affected version, OS, impact, and reproducible steps with
synthetic input. Remove credentials, raw customer logs, and personal
data from attachments.
