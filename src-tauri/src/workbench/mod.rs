//! Draft review and rendering with revision-bound clipboard writes.

use std::fmt::Write as _;

use serde::{ser::SerializeStruct, Deserialize, Serialize};

pub use crate::detector::WorkbenchWarning;
use crate::detector::{detect, DetectOptions, Span};

pub const MAX_INPUT_BYTES: usize = 1_048_576;
const MANUAL_REASON: &str = "manual.selection";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkbenchError {
    InputTooLarge,
    StaleRevision,
    InvalidRange,
    UnknownMatch,
    UnknownManualRedaction,
    EmptyDraft,
    ClipboardWriteFailed,
    StateUnavailable,
    InvalidArguments,
}

impl Serialize for WorkbenchError {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (code, message) = match self {
            Self::InputTooLarge => ("InputTooLarge", "Text exceeds the 1 MiB limit."),
            Self::StaleRevision => ("StaleRevision", "This draft or review has changed."),
            Self::InvalidRange => ("InvalidRange", "Select a valid range of text."),
            Self::UnknownMatch => ("UnknownMatch", "This match is no longer available."),
            Self::UnknownManualRedaction => (
                "UnknownManualRedaction",
                "This manual redaction is no longer available.",
            ),
            Self::EmptyDraft => ("EmptyDraft", "There is no text to copy."),
            Self::ClipboardWriteFailed => (
                "ClipboardWriteFailed",
                "Could not write to the clipboard. Try again.",
            ),
            Self::StateUnavailable => ("StateUnavailable", "The workbench is unavailable."),
            Self::InvalidArguments => ("InvalidArguments", "The workbench request is invalid."),
        };
        let mut error = serializer.serialize_struct("WorkbenchError", 2)?;
        error.serialize_field("code", code)?;
        error.serialize_field("message", message)?;
        error.end()
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchAction {
    Redact,
    Allow,
}

#[derive(Clone, Serialize)]
pub struct AutomaticMatch {
    pub id: String,
    #[serde(flatten)]
    pub span: Span,
    pub action: MatchAction,
    pub overridden_by_manual: bool,
}

#[derive(Clone, Serialize)]
pub struct ManualRedaction {
    pub id: String,
    #[serde(flatten)]
    pub span: Span,
}

#[derive(Serialize)]
pub struct EffectiveSpan {
    pub id: String,
    #[serde(flatten)]
    pub span: Span,
    pub action: MatchAction,
}

#[derive(Serialize)]
pub struct WorkbenchSnapshot {
    pub draft_revision: u64,
    pub review_revision: u64,
    pub byte_length: usize,
    pub max_bytes: usize,
    pub matches: Vec<AutomaticMatch>,
    pub manual_redactions: Vec<ManualRedaction>,
    pub effective_spans: Vec<EffectiveSpan>,
    pub redacted_preview: String,
    pub warnings: Vec<WorkbenchWarning>,
}

#[derive(Default)]
pub struct WorkbenchState {
    draft_revision: u64,
    review_revision: u64,
    source_text: String,
    options: DetectOptions,
    auto_matches: Vec<AutomaticMatch>,
    manual_redactions: Vec<ManualRedaction>,
    warnings: Vec<WorkbenchWarning>,
}

impl WorkbenchState {
    pub fn set_draft(
        &mut self,
        text: String,
        options: DetectOptions,
    ) -> Result<WorkbenchSnapshot, WorkbenchError> {
        if text.len() > MAX_INPUT_BYTES {
            return Err(WorkbenchError::InputTooLarge);
        }
        let detection = detect(&text, &options);
        self.reset(text, options);
        self.auto_matches = detection
            .spans
            .into_iter()
            .enumerate()
            .map(|(index, span)| AutomaticMatch {
                id: format!("auto-{}-{index}", self.draft_revision),
                span,
                action: MatchAction::Redact,
                overridden_by_manual: false,
            })
            .collect();
        self.warnings = detection.warnings;
        Ok(self.snapshot())
    }

    pub fn set_match_action(
        &mut self,
        draft_revision: u64,
        match_id: &str,
        action: MatchAction,
    ) -> Result<WorkbenchSnapshot, WorkbenchError> {
        self.check_draft(draft_revision)?;
        let matched = self
            .auto_matches
            .iter_mut()
            .find(|matched| matched.id == match_id)
            .ok_or(WorkbenchError::UnknownMatch)?;
        matched.action = action;
        self.review_revision += 1;
        Ok(self.snapshot())
    }

    pub fn add_manual_redaction(
        &mut self,
        draft_revision: u64,
        start: usize,
        end: usize,
    ) -> Result<WorkbenchSnapshot, WorkbenchError> {
        self.check_draft(draft_revision)?;
        if start >= end || self.source_text.get(start..end).is_none() {
            return Err(WorkbenchError::InvalidRange);
        }
        let first = self
            .manual_redactions
            .partition_point(|manual| manual.span.end <= start);
        let last = self
            .manual_redactions
            .partition_point(|manual| manual.span.start < end);
        self.review_revision += 1;
        let (id, start, end) = if first < last {
            let existing = &self.manual_redactions[first];
            (
                existing.id.clone(),
                start.min(existing.span.start),
                end.max(self.manual_redactions[last - 1].span.end),
            )
        } else {
            (
                format!("manual-{}-{}", self.draft_revision, self.review_revision),
                start,
                end,
            )
        };
        self.manual_redactions.splice(
            first..last,
            [ManualRedaction {
                id,
                span: Span {
                    start,
                    end,
                    reason_id: MANUAL_REASON,
                    reason_label: "Manual selection",
                },
            }],
        );
        Ok(self.snapshot())
    }

    pub fn remove_manual_redaction(
        &mut self,
        draft_revision: u64,
        manual_id: &str,
    ) -> Result<WorkbenchSnapshot, WorkbenchError> {
        self.check_draft(draft_revision)?;
        let index = self
            .manual_redactions
            .iter()
            .position(|manual| manual.id == manual_id)
            .ok_or(WorkbenchError::UnknownManualRedaction)?;
        self.manual_redactions.remove(index);
        self.review_revision += 1;
        Ok(self.snapshot())
    }

    pub fn clear(&mut self) -> WorkbenchSnapshot {
        self.reset(String::new(), DetectOptions::default());
        self.snapshot()
    }

    pub fn copy_redacted(
        &self,
        draft_revision: u64,
        review_revision: u64,
        clipboard: &dyn ClipboardWriter,
    ) -> Result<(), WorkbenchError> {
        self.check_draft(draft_revision)?;
        if review_revision != self.review_revision {
            return Err(WorkbenchError::StaleRevision);
        }
        if self.source_text.is_empty() {
            return Err(WorkbenchError::EmptyDraft);
        }
        let (_, spans) = self.review_spans();
        clipboard.write_text(&self.render(&spans))
    }

    fn check_draft(&self, draft_revision: u64) -> Result<(), WorkbenchError> {
        if draft_revision == self.draft_revision {
            Ok(())
        } else {
            Err(WorkbenchError::StaleRevision)
        }
    }

    fn reset(&mut self, text: String, options: DetectOptions) {
        self.draft_revision += 1;
        self.review_revision = 0;
        self.source_text = text;
        self.options = options;
        self.auto_matches.clear();
        self.manual_redactions.clear();
        self.warnings.clear();
    }

    fn review_spans(&self) -> (Vec<AutomaticMatch>, Vec<EffectiveSpan>) {
        let effective = |id: &String, span, action| EffectiveSpan {
            id: id.clone(),
            span,
            action,
        };
        let mut matches = self.auto_matches.clone();
        let mut spans = Vec::with_capacity(matches.len() + self.manual_redactions.len());
        let mut manual = self.manual_redactions.iter().peekable();
        for matched in &mut matches {
            while manual
                .peek()
                .is_some_and(|entry| entry.span.end <= matched.span.start)
            {
                let entry = manual.next().unwrap();
                spans.push(effective(&entry.id, entry.span, MatchAction::Redact));
            }
            let mut start = matched.span.start;
            let automatic = |start, end| EffectiveSpan {
                id: if (start, end) == (matched.span.start, matched.span.end) {
                    matched.id.clone()
                } else {
                    format!("{}-{start}-{end}", matched.id)
                },
                span: Span {
                    start,
                    end,
                    ..matched.span
                },
                action: matched.action,
            };
            let mut has_uncovered = false;
            while let Some(entry) = manual
                .peek()
                .filter(|entry| entry.span.start < matched.span.end)
            {
                if start < entry.span.start {
                    spans.push(automatic(start, entry.span.start));
                    has_uncovered = true;
                }
                start = entry.span.end;
                if start > matched.span.end {
                    break;
                }
                spans.push(effective(&entry.id, entry.span, MatchAction::Redact));
                manual.next();
            }
            if start < matched.span.end {
                spans.push(automatic(start, matched.span.end));
                has_uncovered = true;
            }
            matched.overridden_by_manual = !has_uncovered;
        }
        spans.extend(manual.map(|entry| effective(&entry.id, entry.span, MatchAction::Redact)));
        (matches, spans)
    }

    fn render(&self, spans: &[EffectiveSpan]) -> String {
        let mut preview = String::with_capacity(self.source_text.len());
        let mut offset = 0;
        for entry in spans
            .iter()
            .filter(|entry| entry.action == MatchAction::Redact)
        {
            preview.push_str(&self.source_text[offset..entry.span.start]);
            if entry.span.reason_id == MANUAL_REASON {
                preview.push_str("[REDACTED_MANUAL]");
            } else {
                write!(preview, "[REDACTED:{}]", entry.span.reason_id).expect("writing to String");
            }
            offset = entry.span.end;
        }
        preview.push_str(&self.source_text[offset..]);
        preview
    }

    fn snapshot(&self) -> WorkbenchSnapshot {
        let (matches, effective_spans) = self.review_spans();
        WorkbenchSnapshot {
            draft_revision: self.draft_revision,
            review_revision: self.review_revision,
            byte_length: self.source_text.len(),
            max_bytes: MAX_INPUT_BYTES,
            matches,
            manual_redactions: self.manual_redactions.clone(),
            redacted_preview: self.render(&effective_spans),
            effective_spans,
            warnings: self.warnings.clone(),
        }
    }
}

pub trait ClipboardWriter: Send + Sync {
    fn write_text(&self, text: &str) -> Result<(), WorkbenchError>;
}

pub struct SystemClipboard;

impl ClipboardWriter for SystemClipboard {
    fn write_text(&self, text: &str) -> Result<(), WorkbenchError> {
        arboard::Clipboard::new()
            .and_then(|mut clipboard| clipboard.set_text(text))
            .map_err(|_| WorkbenchError::ClipboardWriteFailed)
    }
}
