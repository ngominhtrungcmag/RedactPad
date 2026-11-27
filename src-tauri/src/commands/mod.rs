//! Tauri IPC for draft analysis, review, and explicit clipboard writes.

use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize};
use tauri::{
    ipc::{CommandArg, CommandItem, InvokeError},
    Runtime, State,
};

use crate::{
    detector::DetectOptions,
    workbench::{
        ClipboardWriter, MatchAction, SystemClipboard, WorkbenchError, WorkbenchSnapshot,
        WorkbenchState,
    },
};

pub type CommandError = WorkbenchError;
type SharedWorkbench = Mutex<WorkbenchState>;

// Serde's default type errors can include the provided value.
pub struct Argument<T>(T);

impl<'de, R: Runtime, T: Deserialize<'de>> CommandArg<'de, R> for Argument<T> {
    fn from_command(command: CommandItem<'de, R>) -> Result<Self, InvokeError> {
        #[cfg(target_os = "macos")]
        let scrubber_command = command.name.starts_with("scrubber_");
        T::deserialize(command).map(Self).map_err(|_| {
            #[cfg(target_os = "macos")]
            if scrubber_command {
                return scrubber::ScrubberCommandError::invalid_arguments().into();
            }
            WorkbenchError::InvalidArguments.into()
        })
    }
}

#[derive(Serialize)]
pub struct CopyResult {
    pub draft_revision: u64,
    pub review_revision: u64,
}

fn lock(state: &SharedWorkbench) -> Result<MutexGuard<'_, WorkbenchState>, CommandError> {
    state.lock().map_err(|_| WorkbenchError::StateUnavailable)
}

pub fn analyze_draft_inner(
    state: &SharedWorkbench,
    text: String,
    options: Option<DetectOptions>,
) -> Result<WorkbenchSnapshot, CommandError> {
    lock(state)?.set_draft(text, options.unwrap_or_default())
}

/// Analyze and replace the active draft, resetting its review.
#[tauri::command]
pub fn analyze_draft(
    state: State<'_, SharedWorkbench>,
    text: Argument<String>,
    options: Argument<Option<DetectOptions>>,
) -> Result<WorkbenchSnapshot, CommandError> {
    analyze_draft_inner(&state, text.0, options.0)
}

/// Set the review action on one automatic match in the requested draft.
#[tauri::command]
pub fn set_match_action(
    state: State<'_, SharedWorkbench>,
    draft_revision: Argument<u64>,
    match_id: Argument<String>,
    action: Argument<MatchAction>,
) -> Result<WorkbenchSnapshot, CommandError> {
    lock(&state)?.set_match_action(draft_revision.0, &match_id.0, action.0)
}

/// Add a manual redaction using half-open UTF-8 byte offsets.
#[tauri::command]
pub fn add_manual_redaction(
    state: State<'_, SharedWorkbench>,
    draft_revision: Argument<u64>,
    start: Argument<usize>,
    end: Argument<usize>,
) -> Result<WorkbenchSnapshot, CommandError> {
    lock(&state)?.add_manual_redaction(draft_revision.0, start.0, end.0)
}

/// Remove a manual redaction from the requested draft.
#[tauri::command]
pub fn remove_manual_redaction(
    state: State<'_, SharedWorkbench>,
    draft_revision: Argument<u64>,
    manual_id: Argument<String>,
) -> Result<WorkbenchSnapshot, CommandError> {
    lock(&state)?.remove_manual_redaction(draft_revision.0, &manual_id.0)
}

/// Clear the active draft and advance its revision.
#[tauri::command]
pub fn clear_draft(state: State<'_, SharedWorkbench>) -> Result<WorkbenchSnapshot, CommandError> {
    Ok(lock(&state)?.clear())
}

pub fn copy_redacted_text_inner(
    state: &SharedWorkbench,
    draft_revision: u64,
    review_revision: u64,
    clipboard: &dyn ClipboardWriter,
) -> Result<CopyResult, CommandError> {
    // Hold the lock through the write so a review change cannot invalidate the preview midway.
    lock(state)?.copy_redacted(draft_revision, review_revision, clipboard)?;
    Ok(CopyResult {
        draft_revision,
        review_revision,
    })
}

/// Copy the preview for the exact draft and review revision.
#[tauri::command]
pub fn copy_redacted_text(
    state: State<'_, SharedWorkbench>,
    draft_revision: Argument<u64>,
    review_revision: Argument<u64>,
) -> Result<CopyResult, CommandError> {
    copy_redacted_text_inner(
        &state,
        draft_revision.0,
        review_revision.0,
        &SystemClipboard,
    )
}

#[cfg(target_os = "macos")]
pub mod scrubber;

#[tauri::command]
pub fn file_scrubber_supported() -> bool {
    cfg!(target_os = "macos")
}

#[cfg(test)]
mod tests {
    #[test]
    fn file_scrubber_support_matches_target_os() {
        assert_eq!(super::file_scrubber_supported(), cfg!(target_os = "macos"));
    }
}
