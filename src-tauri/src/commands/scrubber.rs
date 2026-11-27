//! File selections and handles stay in Rust. IPC only accepts opaque IDs and page indexes.

use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError},
};

use serde::Serialize;
use tauri::State;

use super::Argument;
use crate::{
    detector::stream::FileLimitation,
    scrubber::{
        export_file, export_file_with_hooks, get_preview_page, open_input_file, ExportHooks,
        ExportJob, ExportOutcome, PreviewPage, ScrubberError, ScrubberSession,
    },
};

pub trait FileDialogPort: Send + Sync {
    fn pick_input_file(&self) -> Option<PathBuf>;
    fn pick_output_file(&self, suggested_name: &str) -> Option<PathBuf>;
}

pub struct NativeFileDialogs;

impl FileDialogPort for NativeFileDialogs {
    fn pick_input_file(&self) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .add_filter("Plain text", &["log", "txt"])
            .pick_file()
    }

    fn pick_output_file(&self, suggested_name: &str) -> Option<PathBuf> {
        rfd::FileDialog::new()
            .set_file_name(suggested_name)
            .save_file()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScrubberCommandError {
    pub code: String,
    pub message: String,
}

impl ScrubberCommandError {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }

    pub(super) fn invalid_arguments() -> Self {
        Self::new("InvalidArguments", "The file scrubber request is invalid.")
    }

    fn unavailable() -> Self {
        Self::new("StateUnavailable", "The file scrubber is unavailable.")
    }
}

impl From<ScrubberError> for ScrubberCommandError {
    fn from(error: ScrubberError) -> Self {
        use ScrubberError::*;
        let (code, message) = match error {
            UnsupportedFormat => ("UnsupportedFormat", "Choose a .log or .txt file."),
            NotRegularFile => ("NotRegularFile", "Choose a regular file."),
            InvalidDestination => ("InvalidDestination", "Choose a valid output filename."),
            InputFileModified => (
                "InputFileModified",
                "The input changed while it was being read.",
            ),
            PreviewPageOutOfRange => ("PreviewPageOutOfRange", "That preview page is unavailable."),
            PreviewEncoding => ("PreviewEncoding", "The preview could not be encoded."),
            SameFile => ("SameFile", "Choose a destination separate from the input."),
            AlreadyExists => ("AlreadyExists", "Choose a destination that does not exist."),
            UnsafeStaging => (
                "UnsafeStaging",
                "A private staging file could not be secured.",
            ),
            OutputIo(_) => ("OutputIo", "The redacted file could not be written."),
            InputIo(_) => ("InputIo", "The input could not be read."),
            BlockingLimitation(limitation) => return limitation.into(),
        };
        Self::new(code, message)
    }
}

impl From<FileLimitation> for ScrubberCommandError {
    fn from(limitation: FileLimitation) -> Self {
        use FileLimitation::*;
        let (code, message) = match limitation {
            OversizedPemBlock => (
                "OversizedPemBlock",
                "Export blocked because a PEM private key block exceeds the supported size.",
            ),
            UnclosedPemBlock => (
                "UnclosedPemBlock",
                "Export blocked because a PEM private key block is unclosed.",
            ),
            UnsupportedMultilineCandidate => (
                "UnsupportedMultilineCandidate",
                "Export blocked because a quoted credential spans multiple lines.",
            ),
            OversizedRuleCandidate => (
                "OversizedRuleCandidate",
                "Export blocked because a candidate exceeds the supported size.",
            ),
            OversizedOverlapCluster => (
                "OversizedOverlapCluster",
                "Export blocked because overlapping candidates exceed the supported size.",
            ),
        };
        Self::new(code, message)
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScrubberSessionSummary {
    pub session_id: u64,
    pub display_name: String,
    pub byte_size: u64,
    pub has_active_export: bool,
    pub active_job_id: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportJobSnapshot {
    pub job_id: u64,
    pub session_id: u64,
    #[serde(flatten)]
    pub state: ExportState,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all_fields = "camelCase")]
pub enum ExportState {
    Running,
    Cancelled {
        cleanup_warning: bool,
    },
    Published,
    PublishedWithWarning {
        warning: &'static str,
    },
    Failed {
        #[serde(flatten)]
        error: ScrubberCommandError,
        cleanup_warning: bool,
    },
}

impl From<ExportOutcome> for ExportState {
    fn from(outcome: ExportOutcome) -> Self {
        match outcome {
            ExportOutcome::Cancelled { cleanup_warning } => Self::Cancelled { cleanup_warning },
            ExportOutcome::Published => Self::Published,
            ExportOutcome::PublishedWithWarning {
                cleanup_warning,
                sync_warning,
            } => {
                let warning = match (cleanup_warning, sync_warning) {
                    (true, true) => {
                        "Staging cleanup and destination directory sync did not complete."
                    }
                    (true, false) => "Staging cleanup did not complete.",
                    _ => "Destination directory sync did not complete.",
                };
                Self::PublishedWithWarning { warning }
            }
            ExportOutcome::Failed {
                error,
                cleanup_warning,
            } => Self::Failed {
                error: error.into(),
                cleanup_warning,
            },
        }
    }
}

struct ActiveExport {
    job_id: u64,
    session_id: u64,
    handle: ExportJob,
    terminal: OnceLock<ExportState>,
}

impl ActiveExport {
    fn snapshot(&self, state: ExportState) -> ExportJobSnapshot {
        ExportJobSnapshot {
            job_id: self.job_id,
            session_id: self.session_id,
            state,
        }
    }
}

#[derive(Default)]
struct ControllerState {
    session_id: u64,
    session: Option<Arc<ScrubberSession>>,
    job: Option<Arc<ActiveExport>>,
}

impl ControllerState {
    fn session(&self, id: u64) -> Result<&Arc<ScrubberSession>, ScrubberCommandError> {
        self.session
            .as_ref()
            .filter(|_| self.session_id == id)
            .ok_or_else(|| {
                ScrubberCommandError::new("StaleSession", "The selected input is no longer active.")
            })
    }

    fn active_job_id(&self) -> Option<u64> {
        self.job
            .as_ref()
            .filter(|job| job.terminal.get().is_none())
            .map(|job| job.job_id)
    }

    fn ensure_idle(&self) -> Result<(), ScrubberCommandError> {
        if self.active_job_id().is_some() {
            Err(ScrubberCommandError::new(
                "ExportInProgress",
                "Wait for the current export to finish.",
            ))
        } else {
            Ok(())
        }
    }

    fn summary(&self) -> Option<ScrubberSessionSummary> {
        let session = self.session.as_ref()?;
        let active_job_id = self.active_job_id();
        Some(ScrubberSessionSummary {
            session_id: self.session_id,
            display_name: session.display_name().to_owned(),
            byte_size: session.byte_size(),
            has_active_export: active_job_id.is_some(),
            active_job_id,
        })
    }
}

pub struct ScrubberController {
    dialogs: Box<dyn FileDialogPort>,
    hooks: Option<Arc<dyn ExportHooks + Send + Sync>>,
    selection: Mutex<()>,
    state: Mutex<ControllerState>,
}

impl ScrubberController {
    pub fn new(dialogs: impl FileDialogPort + 'static) -> Self {
        Self {
            dialogs: Box::new(dialogs),
            hooks: None,
            selection: Mutex::new(()),
            state: Mutex::default(),
        }
    }

    pub fn with_export_hooks(
        dialogs: impl FileDialogPort + 'static,
        hooks: impl ExportHooks + Send + Sync + 'static,
    ) -> Self {
        Self {
            hooks: Some(Arc::new(hooks)),
            ..Self::new(dialogs)
        }
    }

    fn state(&self) -> Result<MutexGuard<'_, ControllerState>, ScrubberCommandError> {
        self.state
            .lock()
            .map_err(|_| ScrubberCommandError::unavailable())
    }

    fn selection(&self) -> Result<MutexGuard<'_, ()>, ScrubberCommandError> {
        self.selection.try_lock().map_err(|error| match error {
            TryLockError::WouldBlock => ScrubberCommandError::new(
                "SelectionInProgress",
                "Finish the current file selection first.",
            ),
            TryLockError::Poisoned(_) => ScrubberCommandError::unavailable(),
        })
    }

    fn open(&self, path: &Path) -> Result<ScrubberSessionSummary, ScrubberCommandError> {
        let session = open_input_file(path)?;
        let mut state = self.state()?;
        state.session_id = state
            .session_id
            .checked_add(1)
            .ok_or_else(ScrubberCommandError::unavailable)?;
        state.session = Some(Arc::new(session));
        state
            .summary()
            .ok_or_else(ScrubberCommandError::unavailable)
    }

    pub fn pick_input(&self) -> Result<Option<ScrubberSessionSummary>, ScrubberCommandError> {
        let _selection = self.selection()?;
        self.state()?.ensure_idle()?;
        self.dialogs
            .pick_input_file()
            .map(|path| self.open(&path))
            .transpose()
    }

    pub fn ingest_drop(
        &self,
        paths: &[PathBuf],
    ) -> Result<ScrubberSessionSummary, ScrubberCommandError> {
        let _selection = self.selection()?;
        self.state()?.ensure_idle()?;
        let [path] = paths else {
            return Err(ScrubberCommandError::new(
                "InvalidDrop",
                "Drop one .log or .txt file at a time.",
            ));
        };
        self.open(path)
    }

    pub fn get_session(&self) -> Result<Option<ScrubberSessionSummary>, ScrubberCommandError> {
        Ok(self.state()?.summary())
    }

    pub fn get_preview_page(
        &self,
        session_id: u64,
        page_index: usize,
    ) -> Result<PreviewPage, ScrubberCommandError> {
        let session = Arc::clone(self.state()?.session(session_id)?);
        let page = get_preview_page(&session, page_index as u64)?;
        self.state()?.session(session_id)?;
        Ok(page)
    }

    pub fn export_to_picked_destination(
        &self,
        session_id: u64,
    ) -> Result<Option<ExportJobSnapshot>, ScrubberCommandError> {
        let _selection = self.selection()?;
        let (session, job_id) = {
            let state = self.state()?;
            let session = Arc::clone(state.session(session_id)?);
            state.ensure_idle()?;
            let previous_id = state.job.as_ref().map_or(0, |job| job.job_id);
            (
                session,
                previous_id
                    .checked_add(1)
                    .ok_or_else(ScrubberCommandError::unavailable)?,
            )
        };
        let (stem, extension) = session
            .display_name()
            .rsplit_once('.')
            .ok_or_else(ScrubberCommandError::unavailable)?;
        let Some(destination) = self
            .dialogs
            .pick_output_file(&format!("{stem}.redacted.{extension}"))
        else {
            return Ok(None);
        };
        let job = Arc::new(ActiveExport {
            job_id,
            session_id,
            handle: ExportJob::new(),
            terminal: OnceLock::new(),
        });
        let worker_job = Arc::clone(&job);
        let hooks = self.hooks.clone();
        let mut state = self.state()?;
        std::thread::Builder::new()
            .name("scrubber-export".into())
            .spawn(move || {
                let result = catch_unwind(AssertUnwindSafe(|| match hooks {
                    Some(hooks) => export_file_with_hooks(
                        &session,
                        &destination,
                        &worker_job.handle,
                        &SharedHooks(hooks),
                    ),
                    None => export_file(&session, &destination, &worker_job.handle),
                }));
                let outcome = match result {
                    Ok(outcome) => outcome.into(),
                    Err(_) => ExportState::Failed {
                        error: ScrubberCommandError::unavailable(),
                        cleanup_warning: true,
                    },
                };
                let _ = worker_job.terminal.set(outcome);
            })
            .map_err(|_| ScrubberCommandError::unavailable())?;
        let snapshot = job.snapshot(ExportState::Running);
        state.job = Some(job);
        Ok(Some(snapshot))
    }

    fn job(&self, job_id: u64) -> Result<Arc<ActiveExport>, ScrubberCommandError> {
        self.state()?
            .job
            .as_ref()
            .filter(|job| job.job_id == job_id)
            .cloned()
            .ok_or(ScrubberCommandError::new(
                "UnknownJob",
                "That export job is unavailable.",
            ))
    }

    pub fn get_export_status(
        &self,
        job_id: u64,
    ) -> Result<ExportJobSnapshot, ScrubberCommandError> {
        let job = self.job(job_id)?;
        Ok(Self::snapshot(&job))
    }

    fn snapshot(job: &ActiveExport) -> ExportJobSnapshot {
        job.snapshot(job.terminal.get().cloned().unwrap_or(ExportState::Running))
    }

    pub fn cancel_export(&self, job_id: u64) -> Result<ExportJobSnapshot, ScrubberCommandError> {
        let job = self.job(job_id)?;
        if job.terminal.get().is_none() {
            let outcome = job.handle.cancel();
            let _ = job.terminal.set(outcome.into());
        }
        Ok(Self::snapshot(&job))
    }

    pub fn clear_session(&self, session_id: Option<u64>) -> Result<(), ScrubberCommandError> {
        let _selection = self.selection()?;
        let mut state = self.state()?;
        if let Some(id) = session_id {
            state.session(id)?;
        }
        state.ensure_idle()?;
        state.session = None;
        Ok(())
    }
}

struct SharedHooks(Arc<dyn ExportHooks + Send + Sync>);

impl ExportHooks for SharedHooks {
    fn step(&self, step: crate::scrubber::ExportStep) -> std::io::Result<()> {
        self.0.step(step)
    }

    fn write(&self, file: &mut std::fs::File, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(file, bytes)
    }
}

pub(super) type SharedScrubber = Arc<ScrubberController>;

async fn background<T: Send + 'static>(
    state: State<'_, SharedScrubber>,
    operation: impl FnOnce(&ScrubberController) -> Result<T, ScrubberCommandError> + Send + 'static,
) -> Result<T, ScrubberCommandError> {
    let controller = Arc::clone(&state);
    tauri::async_runtime::spawn_blocking(move || operation(&controller))
        .await
        .map_err(|_| ScrubberCommandError::unavailable())?
}

#[tauri::command]
pub async fn scrubber_pick_input(
    state: State<'_, SharedScrubber>,
) -> Result<Option<ScrubberSessionSummary>, ScrubberCommandError> {
    background(state, ScrubberController::pick_input).await
}

#[tauri::command]
pub fn scrubber_get_session(
    state: State<'_, SharedScrubber>,
) -> Result<Option<ScrubberSessionSummary>, ScrubberCommandError> {
    state.get_session()
}

#[tauri::command]
pub async fn scrubber_get_preview_page(
    state: State<'_, SharedScrubber>,
    session_id: Argument<u64>,
    page_index: Argument<usize>,
) -> Result<PreviewPage, ScrubberCommandError> {
    background(state, move |controller| {
        controller.get_preview_page(session_id.0, page_index.0)
    })
    .await
}

#[tauri::command]
pub async fn scrubber_export_to_picked_destination(
    state: State<'_, SharedScrubber>,
    session_id: Argument<u64>,
) -> Result<Option<ExportJobSnapshot>, ScrubberCommandError> {
    background(state, move |controller| {
        controller.export_to_picked_destination(session_id.0)
    })
    .await
}

#[tauri::command]
pub fn scrubber_get_export_status(
    state: State<'_, SharedScrubber>,
    job_id: Argument<u64>,
) -> Result<ExportJobSnapshot, ScrubberCommandError> {
    state.get_export_status(job_id.0)
}

#[tauri::command]
pub async fn scrubber_cancel_export(
    state: State<'_, SharedScrubber>,
    job_id: Argument<u64>,
) -> Result<ExportJobSnapshot, ScrubberCommandError> {
    background(state, move |controller| controller.cancel_export(job_id.0)).await
}

#[tauri::command]
pub fn scrubber_clear_session(
    state: State<'_, SharedScrubber>,
    session_id: Argument<Option<u64>>,
) -> Result<(), ScrubberCommandError> {
    state.clear_session(session_id.0)
}

pub(crate) mod native_drop;
