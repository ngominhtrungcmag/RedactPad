# RedactPad

RedactPad is a 100% offline, local-first desktop workbench for reviewing
and redacting sensitive text before you paste it into an AI chat or share
it with a teammate. It is designed for developers and support engineers
who work with logs, configuration excerpts, and tickets every day.

The v0.1 target is macOS on Apple silicon (ARM64), built with Tauri 2,
Rust, and React 19. This repository currently contains the MVP design
and implementation brief.

## Install

Download the installer for your platform from [GitHub Releases](https://github.com/ngominhtrungcmag/RedactPad/releases).

- **macOS** — Choose `*_aarch64.dmg` for Apple Silicon or `*_x64.dmg`
  for Intel. Open the disk image and drag RedactPad to Applications.
- **Windows** — Run `*-setup.exe`.
- **Linux** — Install the `.deb` on Debian or Ubuntu, or make the
  `.AppImage` executable and run it.

Builds are currently unsigned. On macOS, right-click RedactPad in
Applications and choose **Open** if Gatekeeper offers that option, or run
`xattr -dr com.apple.quarantine /Applications/RedactPad.app` and open
the app. If Windows SmartScreen appears, choose **More info** › **Run anyway**.

## Releasing

Bump the version in `src-tauri/tauri.conf.json`, `src-tauri/Cargo.toml`,
and `package.json`. Update `src-tauri/Cargo.lock` to match the Rust
package version. Once the version changes are on `main`, run
`git tag vX.Y.Z && git push origin vX.Y.Z` on that commit. Review the
draft release and its installers, then publish it.

## The 10-second loop

1. Paste a snippet into the Text Workbench, or drop a `.log` or `.txt`
   file into the File Scrubber.
2. Review highlighted matches and their reasons, such as a provider
   credential, authorization header, or email address.
3. In the Text Workbench, toggle individual matches between allow and
   redact, and mark any sensitive text the detector missed.
4. Choose **Copy redacted text** for a snippet. For a file, review the
   paginated preview and export a separate redacted copy.
5. If Reversible Restore is available and you enabled it before copying,
   paste the AI reply back into the Text Workbench to restore exact
   placeholders from the active session.

Unflagged text can still be sensitive. Review the output before sharing,
including values you explicitly allowed. Heuristic redaction cannot
guarantee complete coverage.

## v0.1 scope

### Text and clipboard

- Paste up to 1 MiB of UTF-8 text.
- Review rule tags, override individual matches, and redact selections.
- Use the keyboard to move between the editor, matches, and copy action.
- Clear the workbench when you finish.

### Plain-text files

- Stream `.log` and `.txt` files with a bounded preview.
- Export to a separate destination and cancel before publication.
- Preserve original bytes outside replacements, including line endings.
- File exports are irreversible.

### Reversible Restore

- Opt in for a Text Workbench session.
- Share placeholders such as `[[RP_<session>_<counter>]]` and restore
  exact tokens locally while that session is active.
- The mapping lives in Rust RAM and is cleared on reset, expiry, or
  orderly exit. This feature ships only if its release tests pass.

### Offline release

The packaged app uses bundled UI assets and needs no account, server,
or model download. Each release publishes the results of offline
operation and process-attributed network checks. See [Security](SECURITY.md).

## v0.2 and later

- Parser-backed JSONL, JSON, CSV, SQL, and dotenv support.
- Consistent SQL pseudonyms informed by the dialect and schema.
- A CLI with shared `.redactpad.toml` configuration.
- Windows and Linux packages.

OCR, local ML/NER, live proxying, and cloud sync are outside v0.1.

## Project documents

- [MVP specification](docs/SPEC.md) covers behavior and acceptance gates.
- [Competitive analysis](docs/COMPETITIVE_ANALYSIS.md) compares workflows.
- [Security](SECURITY.md) describes the threat model and verification.
- [Week 1 kickoff](TASK-00-KICKOFF.md) gives implementation steps and checks.

## License and sustainability

The core is 100% open source under [Apache-2.0](LICENSE), including its
patent grant. Voluntary donations through GitHub Sponsors are planned.
Future funding options include paid convenience installers with signing
and notarization, Mac App Store distribution, and corporate sponsorships.
