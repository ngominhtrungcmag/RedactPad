use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use proptest::prelude::*;
use redactpad_lib::{
    commands::{analyze_draft_inner, copy_redacted_text_inner},
    workbench::{ClipboardWriter, MatchAction, WorkbenchError, WorkbenchState, MAX_INPUT_BYTES},
};

#[derive(Default)]
struct Clipboard {
    fail: AtomicBool,
    writes: Mutex<Vec<String>>,
}

impl ClipboardWriter for Clipboard {
    fn write_text(&self, text: &str) -> Result<(), WorkbenchError> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(WorkbenchError::ClipboardWriteFailed);
        }
        self.writes.lock().unwrap().push(text.to_owned());
        Ok(())
    }
}

#[test]
fn rejects_stale_copy_at_command_boundary_and_retries_failed_write() {
    let state = Mutex::new(WorkbenchState::default());
    let clipboard = Clipboard::default();
    let initial = analyze_draft_inner(&state, "password=fictional".into(), None).unwrap();
    let reviewed = state
        .lock()
        .unwrap()
        .set_match_action(
            initial.draft_revision,
            &initial.matches[0].id,
            MatchAction::Allow,
        )
        .unwrap();
    let copy = |draft, review| copy_redacted_text_inner(&state, draft, review, &clipboard).err();
    assert_eq!(
        copy(initial.draft_revision, initial.review_revision),
        Some(WorkbenchError::StaleRevision)
    );
    assert_eq!(
        copy(0, reviewed.review_revision),
        Some(WorkbenchError::StaleRevision)
    );
    assert!(clipboard.writes.lock().unwrap().is_empty());
    clipboard.fail.store(true, Ordering::Relaxed);
    assert_eq!(
        copy(reviewed.draft_revision, reviewed.review_revision),
        Some(WorkbenchError::ClipboardWriteFailed)
    );
    clipboard.fail.store(false, Ordering::Relaxed);
    assert_eq!(
        copy(reviewed.draft_revision, reviewed.review_revision),
        None
    );
    assert_eq!(
        *clipboard.writes.lock().unwrap(),
        [reviewed.redacted_preview]
    );
}

#[test]
fn clipboard_write_holds_review_lock_and_oversize_keeps_accepted_draft() {
    struct LockedClipboard<'a>(&'a Mutex<WorkbenchState>);

    impl ClipboardWriter for LockedClipboard<'_> {
        fn write_text(&self, text: &str) -> Result<(), WorkbenchError> {
            assert!(matches!(
                self.0.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            assert_eq!(text, "password=[REDACTED:credential.field]");
            Ok(())
        }
    }

    let state = Mutex::new(WorkbenchState::default());
    let draft = analyze_draft_inner(&state, "password=fictional".into(), None).unwrap();
    assert_eq!(
        analyze_draft_inner(&state, "🔐".repeat(MAX_INPUT_BYTES / 4 + 1), None).err(),
        Some(WorkbenchError::InputTooLarge)
    );
    let copied = copy_redacted_text_inner(
        &state,
        draft.draft_revision,
        draft.review_revision,
        &LockedClipboard(&state),
    )
    .unwrap();
    assert_eq!(copied.draft_revision, draft.draft_revision);
    assert_eq!(copied.review_revision, draft.review_revision);
    let boundary = analyze_draft_inner(&state, "🔐".repeat(MAX_INPUT_BYTES / 4), None).unwrap();
    assert_eq!(boundary.byte_length, MAX_INPUT_BYTES);
    assert_eq!(boundary.draft_revision, draft.draft_revision + 1);
}

#[test]
fn rejected_edits_preserve_state_and_never_echo_input() {
    let mut state = WorkbenchState::default();
    let initial = state
        .set_draft("🔐 password=fictional".into(), Default::default())
        .unwrap();
    assert_eq!(initial.matches[0].action, MatchAction::Redact);
    for (start, end) in [(0, 0), (5, 4), (0, 100), (1, 4), (0, 3)] {
        assert_eq!(
            state
                .add_manual_redaction(initial.draft_revision, start, end)
                .err(),
            Some(WorkbenchError::InvalidRange)
        );
    }
    assert_eq!(
        state
            .set_match_action(initial.draft_revision, "fictional", MatchAction::Allow)
            .err(),
        Some(WorkbenchError::UnknownMatch)
    );
    assert_eq!(
        state
            .remove_manual_redaction(initial.draft_revision, "fictional")
            .err(),
        Some(WorkbenchError::UnknownManualRedaction)
    );
    let oversize = state
        .set_draft("🔐".repeat(MAX_INPUT_BYTES / 4 + 1), Default::default())
        .err()
        .unwrap();
    assert_eq!(oversize, WorkbenchError::InputTooLarge);
    let error = serde_json::to_value(oversize).unwrap();
    assert_eq!(error["code"], "InputTooLarge");
    assert!(!error.to_string().contains("🔐"));
    for error in [
        WorkbenchError::UnknownMatch,
        WorkbenchError::UnknownManualRedaction,
        WorkbenchError::InvalidRange,
    ] {
        assert!(!serde_json::to_string(&error).unwrap().contains("fictional"));
    }
    let clipboard = Clipboard::default();
    state
        .copy_redacted(initial.draft_revision, initial.review_revision, &clipboard)
        .unwrap();
    assert_eq!(
        *clipboard.writes.lock().unwrap(),
        [initial.redacted_preview]
    );
    let cleared = state.clear();
    assert_eq!(cleared.draft_revision, initial.draft_revision + 1);
    assert_eq!(cleared.review_revision, 0);
    assert_eq!(cleared.byte_length, 0);
    assert_eq!(
        state
            .add_manual_redaction(initial.draft_revision, 0, 4)
            .err(),
        Some(WorkbenchError::StaleRevision)
    );
}

#[test]
fn manual_spans_merge_and_override_automatic_matches_in_either_action() {
    let mut state = WorkbenchState::default();
    let original = state
        .set_draft("password=fictional end".into(), Default::default())
        .unwrap();
    let draft = original.draft_revision;
    let id = &original.matches[0].id;
    let manual = state.add_manual_redaction(draft, 9, 14).unwrap();
    assert!(!manual.matches[0].overridden_by_manual);
    let merged = state.add_manual_redaction(draft, 13, 18).unwrap();
    assert!(merged.matches[0].overridden_by_manual);
    assert_eq!(merged.manual_redactions.len(), 1);
    assert_eq!(
        merged.manual_redactions[0].id,
        manual.manual_redactions[0].id
    );
    let allowed = state
        .set_match_action(draft, id, MatchAction::Allow)
        .unwrap();
    assert!(allowed.matches[0].overridden_by_manual);
    assert_eq!(allowed.redacted_preview, "password=[REDACTED_MANUAL] end");
    let removed = state
        .remove_manual_redaction(draft, &allowed.manual_redactions[0].id)
        .unwrap();
    assert_eq!(removed.redacted_preview, "password=fictional end");
    assert_eq!(removed.review_revision, 4);
}

#[test]
fn partial_manual_redaction_preserves_the_automatic_action() {
    let source = "🔐 password=fictional end";
    let start = source.find("fictional").unwrap();
    for (from, to) in [(0, 3), (3, 6), (6, 9)] {
        let mut state = WorkbenchState::default();
        let original = state.set_draft(source.into(), Default::default()).unwrap();
        let draft = original.draft_revision;
        let matched = &original.matches[0];
        let automatic = format!("[REDACTED:{}]", matched.span.reason_id);
        let from = start + from;
        let to = start + to;
        let redacted = state.add_manual_redaction(draft, from, to).unwrap();
        assert!(!redacted.matches[0].overridden_by_manual);
        let left = if from > start { automatic.as_str() } else { "" };
        let right = if to < start + 9 {
            automatic.as_str()
        } else {
            ""
        };
        let expected = format!("🔐 password={left}[REDACTED_MANUAL]{right} end");
        assert_eq!(redacted.redacted_preview, expected);
        let clipboard = Clipboard::default();
        state
            .copy_redacted(draft, redacted.review_revision, &clipboard)
            .unwrap();
        assert_eq!(*clipboard.writes.lock().unwrap(), [expected]);

        let allowed = state
            .set_match_action(draft, &matched.id, MatchAction::Allow)
            .unwrap();
        assert!(!allowed.matches[0].overridden_by_manual);
        assert_eq!(
            allowed.redacted_preview,
            format!("{}[REDACTED_MANUAL]{}", &source[..from], &source[to..])
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig { failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn spans_are_disjoint_and_render_preserves_untouched_bytes(
        chars in prop::collection::vec(any::<char>(), 0..120),
        selections in prop::collection::vec((any::<usize>(), any::<usize>()), 0..24),
    ) {
        let source = format!("{} 🔐 password=fictional user@example.test", chars.into_iter().collect::<String>());
        let boundaries: Vec<_> = source.char_indices().map(|(index, _)| index).chain([source.len()]).collect();
        let mut state = WorkbenchState::default();
        let mut snapshot = state.set_draft(source.clone(), Default::default()).unwrap();
        for (left, right) in selections {
            let left = left % (boundaries.len() - 1);
            let right = right % (boundaries.len() - 1);
            snapshot = state.add_manual_redaction(snapshot.draft_revision, boundaries[left.min(right)], boundaries[left.max(right) + 1]).unwrap();
        }
        let mut offset = 0;
        let mut rest = snapshot.redacted_preview.as_bytes();
        for entry in snapshot.effective_spans {
            let span = entry.span;
            prop_assert!(offset <= span.start && span.start < span.end);
            prop_assert!(source.get(span.start..span.end).is_some());
            rest = rest.strip_prefix(&source.as_bytes()[offset..span.start]).ok_or(TestCaseError::fail("untouched prefix changed"))?;
            let marker = if span.reason_id == "manual.selection" {
                "[REDACTED_MANUAL]".to_owned()
            } else {
                format!("[REDACTED:{}]", span.reason_id)
            };
            rest = rest.strip_prefix(marker.as_bytes()).ok_or(TestCaseError::fail("replacement differs"))?;
            offset = span.end;
        }
        prop_assert_eq!(rest, &source.as_bytes()[offset..]);
    }
}
