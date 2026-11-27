use std::{
    fs::{File, Metadata},
    io,
    os::unix::fs::{FileExt, MetadataExt},
};

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::detector::{
    stream::{FileLimitation, Scanner, CHUNK_SIZE},
    DetectOptions,
};

use super::{ScrubberError, ScrubberSession};

pub const MAX_PREVIEW_IPC_BYTES: usize = 262_144;
// Reserve space for the serialized metadata and every possible limitation.
const TEXT_BUDGET: usize = MAX_PREVIEW_IPC_BYTES - 1024;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreviewPage {
    pub text: String,
    pub warnings: Vec<FileLimitation>,
    pub has_next: bool,
    pub page_index: u64,
    pub total_bytes: u64,
    pub page_input_end: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}

impl From<Metadata> for Stamp {
    fn from(metadata: Metadata) -> Self {
        Self {
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

#[derive(Clone, Default)]
struct Pager {
    index: u64,
    cost: usize,
    utf8_prefix: Vec<u8>,
}

impl Pager {
    fn push(&mut self, bytes: &[u8], target: u64, output: &mut String, eof: bool) {
        let mut combined = Vec::new();
        let mut bytes = if self.utf8_prefix.is_empty() {
            bytes
        } else {
            combined.append(&mut self.utf8_prefix);
            combined.extend_from_slice(bytes);
            &combined
        };

        while !bytes.is_empty() {
            match std::str::from_utf8(bytes) {
                Ok(text) => {
                    self.push_text(text, target, output);
                    break;
                }
                Err(error) => {
                    let (valid, rest) = bytes.split_at(error.valid_up_to());
                    self.push_text(std::str::from_utf8(valid).unwrap(), target, output);
                    if let Some(len) = error.error_len() {
                        self.push_text("\u{fffd}", target, output);
                        bytes = &rest[len..];
                    } else {
                        if eof {
                            self.push_text("\u{fffd}", target, output);
                        } else {
                            self.utf8_prefix.extend_from_slice(rest);
                        }
                        break;
                    }
                }
            }
        }
    }

    fn push_text(&mut self, text: &str, target: u64, output: &mut String) {
        for character in text.chars() {
            let escaped = match character {
                '"' | '\\' | '\u{8}' | '\t' | '\n' | '\u{c}' | '\r' => 2,
                '\0'..='\u{1f}' => 6,
                _ => character.len_utf8(),
            };
            if self.cost + escaped > TEXT_BUDGET {
                self.cost = 0;
                self.index += 1;
            }
            self.cost += escaped;
            if self.index == target {
                output.push(character);
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct Checkpoint {
    stamp: Stamp,
    scanner: Scanner,
    digest: Sha256,
    offset: u64,
    pager: Pager,
}

fn read_digest(file: &File, end: u64, buffer: &mut [u8]) -> io::Result<Option<Sha256>> {
    let mut digest = Sha256::new();
    let mut offset = 0;
    while offset < end {
        let limit = (end - offset).min(buffer.len() as u64) as usize;
        let count = file.read_at(&mut buffer[..limit], offset)?;
        if count == 0 {
            return Ok(None);
        }
        digest.update(&buffer[..count]);
        offset += count as u64;
    }
    Ok(Some(digest))
}

fn verified(
    file: &File,
    checkpoint: &Checkpoint,
    buffer: &mut [u8],
) -> Result<bool, ScrubberError> {
    let expected = checkpoint.digest.clone().finalize();
    Ok(Stamp::from(file.metadata()?) == checkpoint.stamp
        && read_digest(file, checkpoint.offset, buffer)?
            .is_some_and(|digest| digest.finalize() == expected)
        && Stamp::from(file.metadata()?) == checkpoint.stamp)
}

pub fn get_preview_page(
    session: &ScrubberSession,
    page_index: u64,
) -> Result<PreviewPage, ScrubberError> {
    get_preview_page_with_hook(session, page_index, |_| {})
}

/// Runs the hook after generation and before the independent verification read.
pub fn get_preview_page_with_hook(
    session: &ScrubberSession,
    page_index: u64,
    after_scan: impl Fn(u64),
) -> Result<PreviewPage, ScrubberError> {
    let file = &session.file;
    let mut buffer = vec![0; CHUNK_SIZE];
    for _ in 0..3 {
        let stamp = Stamp::from(file.metadata()?);
        let cached = session.checkpoint.lock().unwrap().clone();
        let mut state = match cached {
            Some(state) if state.stamp == stamp && state.pager.index < page_index => {
                if !verified(file, &state, &mut buffer)? {
                    *session.checkpoint.lock().unwrap() = None;
                    continue;
                }
                state
            }
            _ => Checkpoint {
                stamp,
                scanner: Scanner::new(&DetectOptions::default()),
                digest: Sha256::new(),
                offset: 0,
                pager: Pager::default(),
            },
        };
        let mut next = None;
        let mut text = String::new();
        let mut page_input_end = None;
        let mut reached_eof = true;
        while state.offset < stamp.len {
            let limit = (stamp.len - state.offset).min(CHUNK_SIZE as u64) as usize;
            let count = file.read_at(&mut buffer[..limit], state.offset)?;
            if count == 0 {
                reached_eof = false;
                break;
            }
            state.offset += count as u64;
            state.digest.update(&buffer[..count]);
            state.scanner.push(&buffer[..count], |bytes, _| {
                state.pager.push(bytes, page_index, &mut text, false);
                Ok(())
            })?;
            if state.pager.index > page_index {
                page_input_end.get_or_insert(state.offset);
            } else if state.scanner.checkpoint_bytes() <= 768 * 1024 {
                next = Some(state.clone());
            }
        }
        if reached_eof {
            state.scanner.finish(|bytes, _| {
                state.pager.push(bytes, page_index, &mut text, false);
                Ok(())
            })?;
            state.pager.push(&[], page_index, &mut text, true);
        }
        let page_input_end = page_input_end.unwrap_or(state.offset);
        after_scan(page_input_end);
        // The verification covers the entire scan because warnings are file-level.
        if !reached_eof || !verified(file, &state, &mut buffer)? {
            *session.checkpoint.lock().unwrap() = None;
            continue;
        }
        if state.pager.index < page_index {
            return Err(ScrubberError::PreviewPageOutOfRange);
        }
        let response = PreviewPage {
            text,
            warnings: state.scanner.warnings().to_vec(),
            has_next: state.pager.index > page_index,
            page_index,
            total_bytes: stamp.len,
            page_input_end,
        };
        if serde_json::to_vec(&response)
            .map_err(|_| ScrubberError::PreviewEncoding)?
            .len()
            > MAX_PREVIEW_IPC_BYTES
        {
            return Err(ScrubberError::PreviewEncoding);
        }
        *session.checkpoint.lock().unwrap() = next;
        return Ok(response);
    }
    Err(ScrubberError::InputFileModified)
}
