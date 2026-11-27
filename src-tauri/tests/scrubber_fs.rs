#![cfg(target_os = "macos")]

use std::{fs, os::unix::fs::symlink};

use redactpad_lib::scrubber::{open_input_file, ScrubberError};

#[test]
fn accepts_only_regular_plain_text_files() {
    let dir = tempfile::tempdir().unwrap();
    for extension in ["json", "jsonl", "csv", "sql", "env", "dotenv", "pdf"] {
        let path = dir.path().join(format!("sample.{extension}"));
        fs::write(&path, b"sample").unwrap();
        assert!(matches!(
            open_input_file(&path),
            Err(ScrubberError::UnsupportedFormat)
        ));
    }

    let folder = dir.path().join("folder.log");
    fs::create_dir(&folder).unwrap();
    assert!(matches!(
        open_input_file(&folder),
        Err(ScrubberError::NotRegularFile)
    ));

    let broken = dir.path().join("broken.txt");
    symlink(dir.path().join("missing"), &broken).unwrap();
    assert!(open_input_file(&broken).is_err());

    let input = dir.path().join("sample.LoG");
    fs::write(&input, b"sample").unwrap();
    let session = open_input_file(&input).unwrap();
    assert_eq!(session.display_name(), "sample.LoG");
    assert_eq!(session.byte_size(), 6);
}

#[test]
fn export_is_private_and_rejects_existing_aliases() {
    use redactpad_lib::scrubber::{export_file, ExportJob, ExportOutcome};
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input.log");
    let destination = dir.path().join("redacted.log");
    fs::write(&input, b"password=synthetic\n").unwrap();
    let session = open_input_file(&input).unwrap();
    let alias = dir.path().join("alias");
    fs::hard_link(&input, &alias).unwrap();
    for path in [&input, &alias] {
        assert_eq!(
            export_file(&session, path, &ExportJob::new()),
            ExportOutcome::Failed {
                error: ScrubberError::SameFile,
                cleanup_warning: false,
            }
        );
    }
    fs::remove_file(&alias).unwrap();
    symlink(&input, &alias).unwrap();
    assert_eq!(
        export_file(&session, &alias, &ExportJob::new()),
        ExportOutcome::Failed {
            error: ScrubberError::SameFile,
            cleanup_warning: false,
        }
    );

    assert_eq!(
        export_file(&session, &destination, &ExportJob::new()),
        ExportOutcome::Published
    );
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"password=[REDACTED:credential.field]\n"
    );
    assert_eq!(
        fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read(&input).unwrap(), b"password=synthetic\n");
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3);
}

#[test]
fn preview_is_bounded_even_for_maximum_json_escaping_and_reflects_edits() {
    use redactpad_lib::scrubber::{get_preview_page, MAX_PREVIEW_IPC_BYTES};

    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("binary.log");
    let mut content = vec![0; 2 * 256 * 1024];
    fs::write(&input, &content).unwrap();
    let session = open_input_file(&input).unwrap();
    let first = get_preview_page(&session, 0).unwrap();
    assert!(first.has_next);
    assert_eq!(first.total_bytes, content.len() as u64);
    assert!(serde_json::to_vec(&first).unwrap().len() <= MAX_PREVIEW_IPC_BYTES);
    assert!(first.text.bytes().all(|byte| byte == 0));

    content[..6].copy_from_slice(b"edited");
    fs::write(&input, &content).unwrap();
    assert!(get_preview_page(&session, 0)
        .unwrap()
        .text
        .starts_with("edited"));
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::{
        fs::File,
        io::{self, Write},
        os::unix::fs::{FileExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::{mpsc, Arc, Barrier},
        thread,
        time::Duration,
    };

    use redactpad_lib::{
        detector::stream::{FileLimitation, CHUNK_SIZE},
        scrubber::{
            export_file, export_file_with_hooks, get_preview_page, get_preview_page_with_hook,
            ExportHooks, ExportJob, ExportOutcome, ExportStep, ScrubberSession,
        },
    };

    type StepHook<'a> = dyn Fn(ExportStep) -> io::Result<()> + Sync + 'a;

    #[derive(Default)]
    struct Hooks<'a> {
        step: Option<&'a StepHook<'a>>,
        write_limit: Option<usize>,
    }

    impl ExportHooks for Hooks<'_> {
        fn step(&self, step: ExportStep) -> io::Result<()> {
            self.step.map_or(Ok(()), |hook| hook(step))
        }

        fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
            match self.write_limit {
                Some(0) => Err(io::Error::from_raw_os_error(libc::ENOSPC)),
                Some(limit) => file.write(&bytes[..bytes.len().min(limit)]),
                None => file.write(bytes),
            }
        }
    }

    const INPUT: &[u8] = b"password=synthetic\r\n";
    const OUTPUT: &[u8] = b"password=[REDACTED:credential.field]\r\n";

    fn setup(bytes: &[u8]) -> (tempfile::TempDir, ScrubberSession, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("input.log");
        fs::write(&input, bytes).unwrap();
        let session = open_input_file(&input).unwrap();
        let output = dir.path().join("output.log");
        (dir, session, output)
    }

    fn stage(parent: &Path) -> PathBuf {
        fs::read_dir(parent)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .as_encoded_bytes()
                    .starts_with(b".redactpad-")
            })
            .unwrap()
    }

    #[test]
    fn retries_short_writes_and_cleans_up_on_disk_full_after_writing() {
        let (dir, session, output) = setup(INPUT);
        let hooks = Hooks {
            step: None,
            write_limit: Some(3),
        };
        assert_eq!(
            export_file_with_hooks(&session, &output, &ExportJob::new(), &hooks),
            ExportOutcome::Published
        );
        assert_eq!(fs::read(&output).unwrap(), OUTPUT);
        fs::remove_file(&output).unwrap();

        struct DiskFull(std::sync::atomic::AtomicBool);
        impl ExportHooks for DiskFull {
            fn write(&self, file: &mut File, bytes: &[u8]) -> io::Result<usize> {
                use std::sync::atomic::Ordering::Relaxed;
                if self.0.swap(true, Relaxed) {
                    Err(io::Error::from_raw_os_error(libc::ENOSPC))
                } else {
                    file.write(&bytes[..1])
                }
            }
        }
        let outcome = export_file_with_hooks(
            &session,
            &output,
            &ExportJob::new(),
            &DiskFull(false.into()),
        );
        assert_eq!(
            outcome,
            ExportOutcome::Failed {
                error: ScrubberError::OutputIo(Some(libc::ENOSPC)),
                cleanup_warning: false
            }
        );
        assert_eq!(fs::read(dir.path().join("input.log")).unwrap(), INPUT);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn blocks_multiline_and_long_pem_even_without_a_cached_preview() {
        let mut pem = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
        pem.resize(CHUNK_SIZE + 16, b'A');
        pem.extend(b" password=synthetic");
        for (bytes, limitation) in [
            (
                b"password=\"line1\nline2\"".as_slice(),
                FileLimitation::UnsupportedMultilineCandidate,
            ),
            (&pem, FileLimitation::OversizedPemBlock),
        ] {
            let (dir, session, output) = setup(bytes);
            assert_eq!(
                export_file(&session, &output, &ExportJob::new()),
                ExportOutcome::Failed {
                    error: ScrubberError::BlockingLimitation(limitation),
                    cleanup_warning: false,
                }
            );
            assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
            assert_eq!(fs::read(dir.path().join("input.log")).unwrap(), bytes);
            if limitation == FileLimitation::OversizedPemBlock {
                let first = get_preview_page(&session, 0).unwrap();
                let second = get_preview_page(&session, 1).unwrap();
                assert!(first.has_next);
                assert_eq!(first.warnings, vec![limitation]);
                assert!(second
                    .text
                    .ends_with("password=[REDACTED:credential.field]"));
                assert!(!second.has_next);
            }
        }
    }

    fn assert_preview_and_export_block(bytes: &[u8], limitation: FileLimitation) {
        let (dir, session, output) = setup(bytes);
        assert_eq!(
            get_preview_page(&session, 0).unwrap().warnings,
            vec![limitation]
        );
        assert_eq!(
            export_file(&session, &output, &ExportJob::new()),
            ExportOutcome::Failed {
                error: ScrubberError::BlockingLimitation(limitation),
                cleanup_warning: false,
            }
        );
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn blocks_an_oversized_bracketed_database_host_across_windows() {
        // Keep the prefix on the first preview page while putting the end past the scan window.
        let mut input = vec![b'x'; CHUNK_SIZE - 8_192];
        input.extend(b"\npostgres://user:synthetic@[");
        input.extend(std::iter::repeat_n(b'a', 8_300));
        input.extend(b"]\n");
        assert_preview_and_export_block(&input, FileLimitation::OversizedRuleCandidate);
    }

    #[test]
    fn exports_labeled_phones_with_internal_or_trailing_padding() {
        let padding = " ".repeat(4_400);
        for (input, expected) in [
            (
                format!("phone=1234567{padding}\n"),
                format!("phone=[REDACTED:pii.phone]{padding}\n"),
            ),
            (
                "phone=123   4567".into(),
                "phone=[REDACTED:pii.phone]".into(),
            ),
        ] {
            let (_dir, session, output) = setup(input.as_bytes());
            let preview = get_preview_page(&session, 0).unwrap();
            assert!(preview.warnings.is_empty());
            assert_eq!(preview.text, expected);
            assert_eq!(
                export_file(&session, &output, &ExportJob::new()),
                ExportOutcome::Published
            );
            assert_eq!(fs::read(output).unwrap(), expected.as_bytes());
        }
    }

    #[test]
    fn blocks_oversized_phone_padding_without_leaving_an_export() {
        let padding = " ".repeat(4_400);
        for input in [
            format!("phone=1{padding}234567"),
            format!("phone{padding}=1234567"),
            format!("phone=1234567{}\n", " ".repeat(70_000)),
        ] {
            assert_preview_and_export_block(
                input.as_bytes(),
                FileLimitation::OversizedRuleCandidate,
            );
        }
    }

    #[test]
    fn blocks_an_oversized_labeled_phone_across_windows() {
        let mut input = vec![b'x'; CHUNK_SIZE - 4_301];
        input.extend(b"\nphone=");
        input.extend(std::iter::repeat_n(b'1', 4_300));
        input.push(b'\n');
        assert_preview_and_export_block(&input, FileLimitation::OversizedRuleCandidate);
    }

    #[test]
    fn blocks_a_duplicate_pem_begin_even_when_the_second_opening_closes() {
        let input = b"-----BEGIN RSA PRIVATE KEY-----\nfirst\n-----BEGIN RSA PRIVATE KEY-----\nsecond\n-----END RSA PRIVATE KEY-----\n";
        assert_preview_and_export_block(input, FileLimitation::UnclosedPemBlock);
    }

    #[test]
    fn publishes_to_the_pinned_parent_after_its_path_is_replaced() {
        let (root, session, _) = setup(INPUT);
        let parent = root.path().join("original");
        let moved = root.path().join("moved");
        fs::create_dir(&parent).unwrap();
        let hook = |step| {
            if step == ExportStep::BeforePublish {
                fs::rename(&parent, &moved)?;
                fs::create_dir(&parent)?;
                fs::write(parent.join("output.log"), b"other file")?;
            }
            Ok(())
        };
        let hooks = Hooks {
            step: Some(&hook),
            ..Hooks::default()
        };
        assert_eq!(
            export_file_with_hooks(
                &session,
                &parent.join("output.log"),
                &ExportJob::new(),
                &hooks
            ),
            ExportOutcome::Published
        );
        assert_eq!(fs::read(moved.join("output.log")).unwrap(), OUTPUT);
        assert_eq!(fs::read(parent.join("output.log")).unwrap(), b"other file");
        assert_eq!(fs::read_dir(&moved).unwrap().count(), 1);
    }

    #[test]
    fn replaced_stage_name_is_never_removed() {
        let (root, session, output) = setup(INPUT);
        let hook = |step| {
            if step == ExportStep::BeforePublish {
                let name = stage(root.path());
                fs::rename(&name, root.path().join("moved-stage"))?;
                fs::create_dir(&name)?;
            }
            Ok(())
        };
        let hooks = Hooks {
            step: Some(&hook),
            ..Hooks::default()
        };
        assert_eq!(
            export_file_with_hooks(&session, &output, &ExportJob::new(), &hooks),
            ExportOutcome::PublishedWithWarning {
                cleanup_warning: true,
                sync_warning: false
            },
        );
        assert!(stage(root.path()).exists());
        assert_eq!(
            fs::read_dir(root.path().join("moved-stage"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(fs::read(&output).unwrap(), OUTPUT);
    }

    fn add_inheritable_acl(path: &Path) {
        let status = std::process::Command::new("/bin/chmod")
            .args(["+a", "everyone allow list,add_file,search,add_subdirectory,delete_child,file_inherit,directory_inherit"])
            .arg(path)
            .status().unwrap();
        assert!(status.success());
    }

    #[test]
    fn clears_inherited_staging_acl_and_skips_cleanup_under_extended_parent_acl() {
        for sticky in [false, true] {
            let (root, session, _) = setup(INPUT);
            let parent = root.path().join("parent");
            let output = parent.join("output.log");
            fs::create_dir(&parent).unwrap();
            fs::set_permissions(
                &parent,
                fs::Permissions::from_mode(if sticky { 0o1777 } else { 0o700 }),
            )
            .unwrap();
            add_inheritable_acl(&parent);
            let hook = |step| {
                if step == ExportStep::Staged {
                    let result = std::process::Command::new("/bin/ls")
                        .arg("-led")
                        .arg(stage(&parent))
                        .output()?;
                    assert!(result.status.success());
                    let listing = String::from_utf8(result.stdout).unwrap();
                    assert!(!listing.contains("everyone"), "{listing}");
                }
                Ok(())
            };
            let hooks = Hooks {
                step: Some(&hook),
                ..Hooks::default()
            };
            assert_eq!(
                export_file_with_hooks(&session, &output, &ExportJob::new(), &hooks),
                ExportOutcome::PublishedWithWarning {
                    cleanup_warning: true,
                    sync_warning: false
                }
            );
            assert_eq!(fs::read(&output).unwrap(), OUTPUT);
            assert_eq!(fs::read_dir(stage(&parent)).unwrap().count(), 0);
        }
    }

    #[test]
    fn cancellation_and_export_share_the_terminal_publication_outcome() {
        for (paused_step, failure, expected) in [
            (ExportStep::Publishing, None, ExportOutcome::Published),
            (
                ExportStep::Publishing,
                Some(libc::EEXIST),
                ExportOutcome::Failed {
                    error: ScrubberError::AlreadyExists,
                    cleanup_warning: false,
                },
            ),
            (
                ExportStep::DirectorySync,
                Some(libc::EIO),
                ExportOutcome::PublishedWithWarning {
                    cleanup_warning: false,
                    sync_warning: true,
                },
            ),
            (
                ExportStep::Cleanup,
                Some(libc::EIO),
                ExportOutcome::PublishedWithWarning {
                    cleanup_warning: true,
                    sync_warning: false,
                },
            ),
        ] {
            let (dir, session, output) = setup(INPUT);
            let job = ExportJob::new();
            let reached = Barrier::new(2);
            let resume = Barrier::new(2);
            let hook = |step| {
                if step == paused_step {
                    reached.wait();
                    resume.wait();
                    if failure == Some(libc::EEXIST) {
                        fs::write(&output, b"winner")?;
                        return Ok(());
                    }
                    if let Some(errno) = failure {
                        return Err(io::Error::from_raw_os_error(errno));
                    }
                }
                Ok(())
            };
            let hooks = Hooks {
                step: Some(&hook),
                ..Hooks::default()
            };
            thread::scope(|scope| {
                let export =
                    scope.spawn(|| export_file_with_hooks(&session, &output, &job, &hooks));
                reached.wait();
                let (sent, received) = mpsc::channel();
                let job = &job;
                scope.spawn(move || sent.send(job.cancel()).unwrap());
                assert!(matches!(
                    received.recv_timeout(Duration::from_millis(25)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ));
                resume.wait();
                assert_eq!(export.join().unwrap(), expected);
                assert_eq!(received.recv().unwrap(), expected);
            });
            let expected_bytes = if failure == Some(libc::EEXIST) {
                b"winner".as_slice()
            } else {
                OUTPUT
            };
            assert_eq!(fs::read(&output).unwrap(), expected_bytes);
            if paused_step == ExportStep::Cleanup {
                assert_eq!(fs::read_dir(stage(dir.path())).unwrap().count(), 0);
            } else {
                assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
            }
        }
    }

    #[test]
    fn publishing_panic_wakes_cancel_waiter() {
        let (dir, session, output) = setup(INPUT);
        let job = Arc::new(ExportJob::new());
        let reached = Barrier::new(2);
        let resume = Barrier::new(2);
        let hook = |step| {
            if step == ExportStep::Publishing {
                reached.wait();
                resume.wait();
                panic!("injected publishing panic");
            }
            Ok(())
        };
        let hooks = Hooks {
            step: Some(&hook),
            ..Hooks::default()
        };
        let (sent, received) = mpsc::channel();
        let (pending, cancel) = thread::scope(|scope| {
            let export = scope.spawn(|| export_file_with_hooks(&session, &output, &job, &hooks));
            reached.wait();
            // Keep cancellation outside the scope so a regression fails by timeout.
            let cancel_job = Arc::clone(&job);
            let cancel = thread::spawn(move || sent.send(cancel_job.cancel()));
            let pending = received.recv_timeout(Duration::from_millis(25));
            resume.wait();
            assert!(export.join().is_err());
            (pending, cancel)
        });
        assert!(matches!(pending, Err(mpsc::RecvTimeoutError::Timeout)));
        let outcome = received.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            outcome,
            ExportOutcome::Failed {
                error: ScrubberError::OutputIo(None),
                ..
            }
        ));
        cancel.join().unwrap().unwrap();
        assert_eq!(job.cancel(), outcome);
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn cancels_before_publish_and_removes_staging() {
        let (dir, session, output) = setup(INPUT);
        let job = ExportJob::new();
        let reached = Barrier::new(2);
        let resume = Barrier::new(2);
        let hook = |step| {
            if step == ExportStep::BeforePublish {
                reached.wait();
                resume.wait();
            }
            Ok(())
        };
        let hooks = Hooks {
            step: Some(&hook),
            ..Hooks::default()
        };
        thread::scope(|scope| {
            let export = scope.spawn(|| export_file_with_hooks(&session, &output, &job, &hooks));
            reached.wait();
            let cancel = scope.spawn(|| job.cancel());
            while !job.cancellation_requested() {
                thread::yield_now();
            }
            resume.wait();
            assert_eq!(
                export.join().unwrap(),
                ExportOutcome::Cancelled {
                    cleanup_warning: false
                }
            );
            assert_eq!(
                cancel.join().unwrap(),
                ExportOutcome::Cancelled {
                    cleanup_warning: false
                }
            );
        });
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(fs::read(dir.path().join("input.log")).unwrap(), INPUT);
    }

    #[test]
    fn a_rewrite_of_payment_context_outside_the_page_recomputes_its_card_span() {
        use redactpad_lib::scrubber::MAX_PREVIEW_IPC_BYTES;

        let marker = "[REDACTED:pii.payment_card]";
        let mut content = vec![b'x'; MAX_PREVIEW_IPC_BYTES - 1024 - marker.len() - 1];
        content.extend(b" 4111111111111111");
        content.extend([b' '; 44]);
        let context = content.len();
        content.extend(b"card\n");
        content.resize(2 * CHUNK_SIZE, b'x');
        let (dir, session, _) = setup(&content);
        let first = get_preview_page(&session, 0).unwrap();
        assert!(first.text.ends_with(marker));
        assert!(!first.text.contains("card\n"));
        let input = fs::OpenOptions::new()
            .write(true)
            .open(dir.path().join("input.log"))
            .unwrap();
        let changed = std::cell::Cell::new(false);
        let rewritten = get_preview_page_with_hook(&session, 0, |page_input_end| {
            assert!(context < page_input_end as usize);
            if !changed.replace(true) {
                input.write_all_at(b"xxxx", context as u64).unwrap();
            }
        })
        .unwrap();
        assert!(rewritten.text.contains("4111111111111111"));
        assert!(!rewritten.text.contains(marker));
    }

    #[test]
    fn rejects_same_size_rewrites_before_inside_and_beyond_the_visible_page() {
        let mut content = vec![b'x'; 3 * CHUNK_SIZE];
        content[CHUNK_SIZE - 10..CHUNK_SIZE + 9].copy_from_slice(b" start boundary end");
        for (page, offset) in [(1, 10), (1, CHUNK_SIZE + 25), (0, CHUNK_SIZE - 10)] {
            let (dir, session, _) = setup(&content);
            get_preview_page(&session, 0).unwrap();
            let input = fs::OpenOptions::new()
                .write(true)
                .open(dir.path().join("input.log"))
                .unwrap();
            let calls = std::cell::Cell::new(0);
            let response = get_preview_page_with_hook(&session, page, |page_input_end| {
                assert!(offset < page_input_end as usize);
                if calls.replace(calls.get() + 1) == 0 {
                    input.write_all_at(b"Z", offset as u64).unwrap();
                }
            })
            .unwrap();
            assert_eq!(calls.get(), 2);
            assert_eq!(
                response.text,
                get_preview_page(&session, page).unwrap().text
            );
            assert_eq!(response.text.contains('Z'), offset == CHUNK_SIZE + 25);
        }
    }
}
