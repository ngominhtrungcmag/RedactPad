//! Rust-owned plain-text file sessions.

use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub enum ScrubberError {
    UnsupportedFormat,
    NotRegularFile,
    InvalidDestination,
    InputFileModified,
    PreviewPageOutOfRange,
    PreviewEncoding,
    SameFile,
    AlreadyExists,
    UnsafeStaging,
    OutputIo(Option<i32>),
    BlockingLimitation(crate::detector::stream::FileLimitation),
    InputIo(Option<i32>),
}

impl From<io::Error> for ScrubberError {
    fn from(error: io::Error) -> Self {
        Self::InputIo(error.raw_os_error())
    }
}

pub struct ScrubberSession {
    file: File,
    identity: (u64, u64),
    canonical_path: PathBuf,
    display_name: String,
    byte_size: u64,
    checkpoint: Mutex<Option<preview::Checkpoint>>,
}

impl ScrubberSession {
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn byte_size(&self) -> u64 {
        self.byte_size
    }

    pub fn input_identity(&self) -> (u64, u64) {
        self.identity
    }

    pub fn current_byte_size(&self) -> Result<u64, ScrubberError> {
        Ok(self.file.metadata()?.len())
    }
}

pub fn open_input_file(path: &Path) -> Result<ScrubberSession, ScrubberError> {
    open_input_file_with_hook(path, || Ok(()))
}

fn open_input_file_with_hook(
    path: &Path,
    before_open: impl FnOnce() -> io::Result<()>,
) -> Result<ScrubberSession, ScrubberError> {
    if !path.extension().is_some_and(|extension| {
        extension.eq_ignore_ascii_case("log") || extension.eq_ignore_ascii_case("txt")
    }) {
        return Err(ScrubberError::UnsupportedFormat);
    }
    let expected = path.metadata()?;
    if !expected.is_file() {
        return Err(ScrubberError::NotRegularFile);
    }
    // Avoid blocking if a FIFO replaces the validated path before open.
    let canonical_path = path.canonicalize()?;
    before_open()?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    let identity = (metadata.dev(), metadata.ino());
    if !metadata.is_file() || identity != (expected.dev(), expected.ino()) {
        return Err(ScrubberError::InputFileModified);
    }
    let display_name = path
        .file_name()
        .ok_or(ScrubberError::UnsupportedFormat)?
        .to_string_lossy()
        .into_owned();
    Ok(ScrubberSession {
        file,
        identity,
        canonical_path,
        display_name,
        byte_size: metadata.len(),
        checkpoint: Mutex::default(),
    })
}

#[cfg(target_os = "macos")]
mod publisher;
#[cfg(target_os = "macos")]
pub use publisher::{
    export_file, export_file_with_hooks, ExportHooks, ExportJob, ExportOutcome, ExportStep,
};

mod preview;
pub use preview::{
    get_preview_page, get_preview_page_with_hook, PreviewPage, MAX_PREVIEW_IPC_BYTES,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_regular_file_replaced_between_validation_and_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("input.log");
        let replacement = dir.path().join("replacement.log");
        std::fs::write(&path, b"original").unwrap();
        std::fs::write(&replacement, b"replacement").unwrap();

        let result = open_input_file_with_hook(&path, || std::fs::rename(&replacement, &path));
        assert!(matches!(result, Err(ScrubberError::InputFileModified)));
    }
}
