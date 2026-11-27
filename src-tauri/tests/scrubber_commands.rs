#![cfg(target_os = "macos")]

use std::{
    fs, io,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use redactpad_lib::{
    commands::scrubber::{
        ExportJobSnapshot, ExportState, FileDialogPort, ScrubberCommandError, ScrubberController,
    },
    detector::stream::FileLimitation,
    scrubber::{ExportHooks, ExportStep, MAX_PREVIEW_IPC_BYTES},
};
use serde_json::json;

struct Dialogs {
    input: PathBuf,
    output: Option<PathBuf>,
}

impl FileDialogPort for Dialogs {
    fn pick_input_file(&self) -> Option<PathBuf> {
        Some(self.input.clone())
    }

    fn pick_output_file(&self, suggested_name: &str) -> Option<PathBuf> {
        assert_eq!(suggested_name, "sample.redacted.log");
        self.output.clone()
    }
}

fn finish(controller: &ScrubberController, job_id: u64) -> ExportJobSnapshot {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let snapshot = controller.get_export_status(job_id).unwrap();
        if snapshot.state != ExportState::Running {
            return snapshot;
        }
        assert!(Instant::now() < deadline, "export did not finish");
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn selection_rejects_unsupported_formats_and_sanitizes_drop_results() {
    let root = tempfile::tempdir().unwrap();
    for name in [
        "sample.json",
        "sample.jsonl",
        "sample.csv",
        "sample.sql",
        ".env",
    ] {
        let path = root.path().join(name);
        fs::write(&path, "SECRET_INPUT").unwrap();
        let controller = ScrubberController::new(Dialogs {
            input: path.clone(),
            output: None,
        });
        let pick_error = controller.pick_input().unwrap_err();
        assert_eq!(pick_error.code, "UnsupportedFormat");
        assert_eq!(controller.ingest_drop(&[path]).unwrap_err(), pick_error);
        assert_eq!(
            serde_json::to_value(&pick_error).unwrap(),
            json!({"code":"UnsupportedFormat", "message":"Choose a .log or .txt file."})
        );
        assert!(controller.get_session().unwrap().is_none());
    }

    let path = root.path().join("sample.log");
    fs::write(&path, "SECRET_INPUT").unwrap();
    let controller = ScrubberController::new(Dialogs {
        input: path.clone(),
        output: None,
    });
    assert_eq!(
        controller
            .ingest_drop(&[path.clone(), path.clone()])
            .unwrap_err()
            .code,
        "InvalidDrop"
    );
    assert_eq!(
        serde_json::to_value(controller.ingest_drop(&[path]).unwrap()).unwrap(),
        json!({"sessionId":1, "displayName":"sample.log", "byteSize":12, "hasActiveExport":false, "activeJobId":null})
    );
}

#[test]
fn stale_sessions_and_unknown_jobs_are_rejected() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("sample.log");
    fs::write(&input, "\0".repeat(MAX_PREVIEW_IPC_BYTES)).unwrap();
    let controller = ScrubberController::new(Dialogs {
        input,
        output: None,
    });
    let stale = controller.pick_input().unwrap().unwrap().session_id;
    let active = controller.pick_input().unwrap().unwrap().session_id;
    assert_eq!(
        controller.get_preview_page(stale, 0).unwrap_err().code,
        "StaleSession"
    );
    assert_eq!(
        controller
            .export_to_picked_destination(stale)
            .unwrap_err()
            .code,
        "StaleSession"
    );
    assert_eq!(
        controller.clear_session(Some(stale)).unwrap_err().code,
        "StaleSession"
    );
    assert_eq!(
        controller.get_export_status(1).unwrap_err().code,
        "UnknownJob"
    );
    assert_eq!(controller.cancel_export(1).unwrap_err().code, "UnknownJob");
    assert!(controller
        .export_to_picked_destination(active)
        .unwrap()
        .is_none());
    let page = controller.get_preview_page(active, 0).unwrap();
    assert!(serde_json::to_vec(&page).unwrap().len() <= MAX_PREVIEW_IPC_BYTES);
    controller.clear_session(Some(active)).unwrap();
    assert!(controller.get_session().unwrap().is_none());
}

#[test]
fn blocking_limits_are_reported_without_leaking_input_or_leaving_staging() {
    for (content, limitation, expected_code, expected_message) in [
        (
            "password=\"SECRET_INPUT\nmore\"".to_owned(),
            FileLimitation::UnsupportedMultilineCandidate,
            "UnsupportedMultilineCandidate",
            "Export blocked because a quoted credential spans multiple lines.",
        ),
        (
            format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                "SECRET_INPUT".repeat(1500)
            ),
            FileLimitation::OversizedPemBlock,
            "OversizedPemBlock",
            "Export blocked because a PEM private key block exceeds the supported size.",
        ),
    ] {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("sample.log");
        let output = root.path().join("sample.redacted.log");
        fs::write(&input, &content).unwrap();
        let controller = ScrubberController::new(Dialogs {
            input,
            output: Some(output),
        });
        let session = controller.pick_input().unwrap().unwrap();
        let job = controller
            .export_to_picked_destination(session.session_id)
            .unwrap()
            .unwrap();
        let snapshot = finish(&controller, job.job_id);
        assert_eq!(
            serde_json::to_value(snapshot).unwrap(),
            json!({"jobId":job.job_id, "sessionId":session.session_id, "state":"Failed", "code":expected_code, "message":expected_message, "cleanupWarning":false})
        );
        assert_eq!(ScrubberCommandError::from(limitation).code, expected_code);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}

#[test]
fn save_selection_rejects_the_input_and_existing_output() {
    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("sample.log");
    let existing = root.path().join("existing.log");
    fs::write(&input, "original").unwrap();
    fs::write(&existing, "existing").unwrap();
    for (output, expected) in [
        (input.clone(), "SameFile"),
        (existing.clone(), "AlreadyExists"),
    ] {
        let controller = ScrubberController::new(Dialogs {
            input: input.clone(),
            output: Some(output),
        });
        let session = controller.pick_input().unwrap().unwrap();
        let job = controller
            .export_to_picked_destination(session.session_id)
            .unwrap()
            .unwrap();
        let ExportState::Failed {
            error,
            cleanup_warning: false,
        } = finish(&controller, job.job_id).state
        else {
            panic!("output was accepted");
        };
        assert_eq!(error.code, expected);
    }
    assert_eq!(fs::read_to_string(input).unwrap(), "original");
    assert_eq!(fs::read_to_string(existing).unwrap(), "existing");
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 2);
}

struct Pause {
    step: ExportStep,
    reached: mpsc::Sender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
    fail: bool,
}

impl ExportHooks for Pause {
    fn step(&self, step: ExportStep) -> io::Result<()> {
        if step == self.step {
            self.reached.send(()).unwrap();
            self.resume
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(10))
                .unwrap();
            if self.fail {
                return Err(io::Error::other("injected failure"));
            }
        }
        Ok(())
    }
}

#[test]
fn reloaded_session_recovers_job_for_polling_and_cancellation() {
    for (step, fail) in [
        (ExportStep::BeforePublish, false),
        (ExportStep::Publishing, true),
        (ExportStep::DirectorySync, false),
        (ExportStep::DirectorySync, true),
    ] {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("sample.log");
        let output = root.path().join("sample.redacted.log");
        fs::write(&input, "ordinary text").unwrap();
        let (reached, paused) = mpsc::channel();
        let (resume, release) = mpsc::channel();
        let controller = Arc::new(ScrubberController::with_export_hooks(
            Dialogs {
                input,
                output: Some(output.clone()),
            },
            Pause {
                step,
                reached,
                resume: Mutex::new(release),
                fail,
            },
        ));
        let session = controller.pick_input().unwrap().unwrap();
        let job = controller
            .export_to_picked_destination(session.session_id)
            .unwrap()
            .unwrap();
        paused.recv_timeout(Duration::from_secs(10)).unwrap();
        let recovered = controller.get_session().unwrap().unwrap();
        assert!(recovered.has_active_export);
        assert_eq!(recovered.active_job_id, Some(job.job_id));
        let summary = serde_json::to_value(recovered).unwrap();
        assert_eq!(summary["activeJobId"], json!(job.job_id));
        let active_job_id = summary["activeJobId"].as_u64().unwrap();
        assert_eq!(
            controller.get_export_status(active_job_id).unwrap().state,
            ExportState::Running
        );
        assert_eq!(
            controller.pick_input().unwrap_err().code,
            "ExportInProgress"
        );
        assert_eq!(
            controller
                .clear_session(Some(session.session_id))
                .unwrap_err()
                .code,
            "ExportInProgress"
        );

        let (send, cancelled) = mpsc::channel();
        let other = Arc::clone(&controller);
        let cancellation =
            thread::spawn(move || send.send(other.cancel_export(active_job_id)).unwrap());
        assert!(matches!(
            cancelled.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        resume.send(()).unwrap();
        let outcome = cancelled
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .unwrap();
        cancellation.join().unwrap();
        assert_eq!(outcome, finish(&controller, active_job_id));
        let terminal = controller.get_session().unwrap().unwrap();
        assert!(!terminal.has_active_export);
        assert_eq!(terminal.active_job_id, None);
        let summary = serde_json::to_value(terminal).unwrap();
        assert_eq!(summary.get("activeJobId"), Some(&serde_json::Value::Null));
        match (step, fail, &outcome.state) {
            (
                ExportStep::BeforePublish,
                false,
                ExportState::Cancelled {
                    cleanup_warning: false,
                },
            )
            | (
                ExportStep::Publishing,
                true,
                ExportState::Failed {
                    cleanup_warning: false,
                    ..
                },
            )
            | (ExportStep::DirectorySync, false, ExportState::Published)
            | (ExportStep::DirectorySync, true, ExportState::PublishedWithWarning { .. }) => {}
            _ => panic!("unexpected outcome: {outcome:?}"),
        }
        let published = step == ExportStep::DirectorySync;
        assert_eq!(output.exists(), published);
        assert_eq!(
            fs::read_dir(root.path()).unwrap().count(),
            if published { 2 } else { 1 }
        );
    }
}

#[test]
fn ipc_uses_camel_case_and_hides_invalid_values() {
    use redactpad_lib::commands::scrubber;
    use tauri::test::{get_ipc_response, mock_builder, mock_context, noop_assets, INVOKE_KEY};

    let root = tempfile::tempdir().unwrap();
    let input = root.path().join("sample.log");
    fs::write(&input, "ordinary text").unwrap();
    let app = mock_builder()
        .manage(Arc::new(ScrubberController::new(Dialogs {
            input,
            output: None,
        })))
        .invoke_handler(tauri::generate_handler![
            scrubber::scrubber_pick_input,
            scrubber::scrubber_get_preview_page,
            scrubber::scrubber_get_export_status,
        ])
        .build(mock_context(noop_assets()))
        .unwrap();
    let window = tauri::WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .unwrap();
    let invoke = |cmd: &str, body: serde_json::Value| {
        get_ipc_response(
            &window,
            tauri::webview::InvokeRequest {
                cmd: cmd.into(),
                callback: tauri::ipc::CallbackFn(0),
                error: tauri::ipc::CallbackFn(1),
                url: "tauri://localhost".parse().unwrap(),
                body: tauri::ipc::InvokeBody::Json(body),
                headers: Default::default(),
                invoke_key: INVOKE_KEY.to_owned(),
            },
        )
    };

    let selection = invoke("scrubber_pick_input", json!({})).unwrap();
    assert_eq!(
        selection.deserialize::<serde_json::Value>().unwrap(),
        json!({"sessionId":1, "displayName":"sample.log", "byteSize":13, "hasActiveExport":false, "activeJobId":null})
    );
    let page = invoke(
        "scrubber_get_preview_page",
        json!({"sessionId":1, "pageIndex":0}),
    )
    .unwrap()
    .deserialize::<serde_json::Value>()
    .unwrap();
    assert_eq!(page["text"], "ordinary text");
    assert_eq!(page["pageIndex"], 0);
    let error = match invoke(
        "scrubber_get_export_status",
        json!({"jobId":"/private/SECRET"}),
    ) {
        Err(error) => error,
        Ok(_) => panic!("non-numeric job ID accepted"),
    };
    assert_eq!(
        error,
        json!({"code":"InvalidArguments", "message":"The file scrubber request is invalid."})
    );
}
