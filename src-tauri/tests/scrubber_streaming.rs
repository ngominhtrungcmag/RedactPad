use redactpad_lib::detector::{
    detect,
    stream::{full_buffer, FileLimitation, Scanner},
    DetectOptions, Span,
};

fn streamed(
    input: &[u8],
    cuts: &[usize],
    options: &DetectOptions,
) -> (Vec<Span>, Vec<FileLimitation>, Vec<u8>) {
    let mut scanner = Scanner::new(options);
    let mut spans = Vec::new();
    let mut output = Vec::new();
    let mut start = 0;
    for end in cuts.iter().copied().chain([input.len()]) {
        scanner
            .push(&input[start..end], |bytes, matches| {
                output.extend(bytes);
                spans.extend_from_slice(matches);
                Ok(())
            })
            .unwrap();
        start = end;
    }
    scanner
        .finish(|bytes, matches| {
            output.extend(bytes);
            spans.extend_from_slice(matches);
            Ok(())
        })
        .unwrap();
    (spans, scanner.warnings().to_vec(), output)
}

#[test]
fn preserves_binary_and_only_replaces_credential_values_at_every_split() {
    let input = b"\xff\xc3\xa9\x80\r\npassword=synthetic\r\n";
    for split in 0..=input.len() {
        let actual = streamed(input, &[split], &DetectOptions::default());
        assert_eq!(
            actual,
            full_buffer(input, &DetectOptions::default()),
            "split {split}"
        );
        assert_eq!(
            actual.2,
            b"\xff\xc3\xa9\x80\r\npassword=[REDACTED:credential.field]\r\n"
        );
    }
}

#[test]
fn independently_labeled_week_one_corpus() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        id: String,
        text: String,
        #[serde(default)]
        options: DetectOptions,
        expected: Vec<Expected>,
    }

    #[derive(serde::Deserialize)]
    struct Expected {
        start: usize,
        end: usize,
        reason_id: String,
    }

    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("../../fixtures/corpus/corpus.json")).unwrap();
    assert_eq!(fixtures.len(), 77);
    for fixture in fixtures {
        let bytes = fixture.text.as_bytes();
        let actual = streamed(bytes, &[], &fixture.options);
        assert_eq!(
            actual,
            full_buffer(bytes, &fixture.options),
            "{}",
            fixture.id
        );
        // The text-mode PEM warning fixture needs an export-blocking warning in file mode.
        assert_eq!(
            actual
                .0
                .iter()
                .map(|s| (s.start, s.end, s.reason_id))
                .collect::<Vec<_>>(),
            fixture
                .expected
                .iter()
                .map(|s| (s.start, s.end, s.reason_id.as_str()))
                .collect::<Vec<_>>(),
            "{}",
            fixture.id
        );
    }
}

#[test]
fn supported_pem_with_horizontal_padding_at_the_inclusive_cap() {
    use redactpad_lib::detector::stream::PEM_LIMIT;

    let mut input = b"-----BEGIN PRIVATE KEY-----   \r\n".to_vec();
    let closing = b"\r\n-----END PRIVATE KEY-----   ";
    input.resize(PEM_LIMIT - closing.len(), b'A');
    input.extend(closing);
    input.extend(b"\r\npassword=synthetic");
    let options = DetectOptions::default();
    let expected = full_buffer(&input, &options);
    assert_eq!(expected.0.len(), 2);
    assert!(expected.1.is_empty());
    for split in [
        0,
        26,
        27,
        28,
        29,
        30,
        31,
        PEM_LIMIT - 1,
        PEM_LIMIT,
        PEM_LIMIT + 1,
        input.len(),
    ] {
        assert_eq!(
            streamed(&input, &[split], &options),
            expected,
            "split {split}"
        );
    }

    input.insert(PEM_LIMIT, b' ');
    let actual = streamed(&input, &[PEM_LIMIT], &options);
    assert_eq!(actual, full_buffer(&input, &options));
    assert_eq!(actual.1, vec![FileLimitation::OversizedPemBlock]);
    assert_eq!(actual.0.len(), 1);
}

#[test]
fn overflowing_pem_unpins_before_a_long_newline_free_tail() {
    use redactpad_lib::detector::stream::CHUNK_SIZE;

    let mut input = b"-----BEGIN PRIVATE KEY-----\n".to_vec();
    input.resize(CHUNK_SIZE + 200, b'A');
    input.extend(b" password=synthetic");
    let options = DetectOptions::default();
    let mut scanner = Scanner::new(&options);
    let mut emitted = 0;
    scanner
        .push(&input[..CHUNK_SIZE], |bytes, _| {
            emitted += bytes.len();
            Ok(())
        })
        .unwrap();
    assert!(emitted > CHUNK_SIZE / 2);
    assert_eq!(scanner.warnings(), &[FileLimitation::OversizedPemBlock]);
    let actual = streamed(&input, &[9, CHUNK_SIZE - 1, CHUNK_SIZE], &options);
    assert_eq!(actual, full_buffer(&input, &options));
    assert_eq!(actual.0.len(), 1);
}

#[test]
fn recognises_overflowing_rules_and_unsupported_quoted_multiline_candidates() {
    let options = DetectOptions::default();
    for input in [
        format!("password{}=synthetic", " ".repeat(4200)),
        format!("password={}", "A".repeat(4200)),
    ] {
        let actual = streamed(input.as_bytes(), &[4096], &options);
        assert_eq!(actual.1, vec![FileLimitation::OversizedRuleCandidate]);
        assert!(actual.0.is_empty());
    }
    for input in [
        b"password=\"first\r\nsecond\"".as_slice(),
        b"password='first\\\nsecond'",
    ] {
        assert_eq!(
            streamed(input, &[8, 13], &options).1,
            vec![FileLimitation::UnsupportedMultilineCandidate]
        );
    }
    let input = b"-----BEGIN PRIVATE KEY-----   \nbody";
    assert_eq!(
        streamed(input, &[28], &options).1,
        vec![FileLimitation::UnclosedPemBlock]
    );
}

proptest::proptest! {
    #[test]
    fn random_partitions_match_the_unwindowed_reference(
        prefix in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
        suffix in proptest::collection::vec(proptest::num::u8::ANY, 0..256),
        chunks in proptest::collection::vec(1usize..50, 0..40),
        across_window in proptest::bool::ANY,
    ) {
        use redactpad_lib::detector::stream::CHUNK_SIZE;

        let mut input = vec![b' '; if across_window { CHUNK_SIZE - 7 } else { 0 }];
        let offset = input.len();
        input.extend(prefix);
        input.extend(b"\r\nAuthorization: Bearer synthetic.token\r\nphone: +1 (555) 555-0100\r\n");
        input.extend(suffix);
        let cuts = chunks.into_iter().scan(offset, |state, size| {
            *state += size;
            (*state < input.len()).then_some(*state)
        }).collect::<Vec<_>>();
        let options = DetectOptions::default();
        proptest::prop_assert_eq!(streamed(&input, &cuts, &options), full_buffer(&input, &options));
    }
}

#[test]
fn transitive_overlap_through_a_uri_stays_uncommitted_past_the_safe_frontier() {
    use redactpad_lib::detector::stream::{
        CHUNK_SIZE, MAX_LEFT_CONTEXT, MAX_NON_PEM_MATCH, MAX_RIGHT_CONTEXT,
    };
    let fixture = b"password=postgres://u:p@host/x,two@example.com\r\n";
    let mut input =
        vec![b' '; CHUNK_SIZE - MAX_NON_PEM_MATCH - MAX_LEFT_CONTEXT - MAX_RIGHT_CONTEXT - 20];
    let start = input.len();
    input.extend(fixture);
    input.resize(CHUNK_SIZE + 5, b' ');
    let options = DetectOptions::default();
    let expected = full_buffer(&input, &options);
    assert_eq!(expected.0.len(), 1);
    assert_eq!(expected.0[0].reason_id, "connection.database_uri");
    for offset in 0..=fixture.len() {
        assert_eq!(
            streamed(&input, &[start + offset, CHUNK_SIZE], &options),
            expected
        );
    }
}

#[test]
fn contextual_patterns_and_eof_agree_at_every_byte_split() {
    let options = DetectOptions::default();
    for input in [
        format!("card{}4111111111111111\r\n", " ".repeat(44)),
        format!("4111111111111111{}card\r\n", " ".repeat(44)),
        "Authorization: Basic c3ludGhldGlj\r\nphone: +1 (555) 555-0100\r\npassword=synthetic token=other".into(),
        "-----BEGIN PRIVATE KEY-----\nfirst\n-----BEGIN PRIVATE KEY-----\nsecond\n-----END PRIVATE KEY-----\n".into(),
        "-----BEGIN PRIVATE KEY-----   \r\nsynthetic\r\n-----END PRIVATE KEY-----\r\n".into(),
        "password=\"line1\nline2\"".into(),
    ] {
        let expected = full_buffer(input.as_bytes(), &options);
        assert!(!expected.0.is_empty() || !expected.1.is_empty());
        for split in 0..=input.len() {
            assert_eq!(streamed(input.as_bytes(), &[split], &options), expected, "split {split}");
        }
    }
}

#[test]
fn long_fixtures_match_when_every_byte_is_a_chunk_boundary() {
    use redactpad_lib::detector::stream::{CHUNK_SIZE, MAX_PEM_MARKER_LINE, PEM_LIMIT};

    let mut long_line = vec![b'x'; CHUNK_SIZE + 1];
    long_line.extend(b" password=synthetic");
    let mut long_email = vec![b'a'; CHUNK_SIZE + 1];
    long_email.extend(b"@example.com password=synthetic");
    let mut oversized_delimiter = vec![b' '; MAX_PEM_MARKER_LINE + 1];
    oversized_delimiter.extend(b"-----BEGIN PRIVATE KEY-----\npassword=synthetic");
    for (input, warning) in [
        (long_line, None),
        (long_email, Some(FileLimitation::OversizedRuleCandidate)),
        (oversized_delimiter, Some(FileLimitation::OversizedPemBlock)),
    ] {
        let options = DetectOptions::default();
        let expected = full_buffer(&input, &options);
        assert_eq!(expected.1, warning.into_iter().collect::<Vec<_>>());
        assert_eq!(expected.0.len(), 1);
        assert_eq!(
            streamed(&input, &(1..input.len()).collect::<Vec<_>>(), &options),
            expected
        );
    }

    for length in [PEM_LIMIT, PEM_LIMIT + 1] {
        let mut input = b"-----BEGIN PRIVATE KEY-----   \n".to_vec();
        let end = b"\n-----END PRIVATE KEY-----\t";
        input.resize(length - end.len(), b'a');
        input.extend(end);
        let options = DetectOptions::default();
        let expected = full_buffer(&input, &options);
        assert_eq!(expected.0.len(), usize::from(length == PEM_LIMIT));
        assert_eq!(expected.1.len(), usize::from(length > PEM_LIMIT));
        assert_eq!(
            streamed(&input, &(1..input.len()).collect::<Vec<_>>(), &options),
            expected
        );
    }
}

#[test]
fn separately_bounded_pem_blocks_can_form_an_oversized_connected_cluster() {
    use redactpad_lib::detector::stream::CHUNK_SIZE;

    let mut input = vec![b'x'; CHUNK_SIZE - 30_000];
    input.push(b'\n');
    let base = input.len();
    for index in 0..8 {
        let start = base + (index + 1) * 9_000;
        input.resize(start - 1, b'A');
        input.push(b'\n');
        input.extend(format!("-----BEGIN LABEL{index} PRIVATE KEY-----\n").bytes());
        if index > 0 {
            input.resize(start + 5_999, b'A');
            input.push(b'\n');
            input.extend(format!("-----END LABEL{} PRIVATE KEY-----\n", index - 1).bytes());
        }
    }
    input.extend(b"-----END LABEL7 PRIVATE KEY-----\npassword=synthetic");
    let options = DetectOptions::default();
    let expected = full_buffer(&input, &options);
    assert_eq!(expected.1, vec![FileLimitation::OversizedOverlapCluster]);
    assert_eq!(expected.0.len(), 1);
    assert_eq!(
        streamed(
            &input,
            &[CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1],
            &options
        ),
        expected
    );
}

#[test]
fn oversized_jwt_prefix_can_span_a_window_before_any_delimiter_is_visible() {
    use redactpad_lib::detector::stream::CHUNK_SIZE;

    let mut input = vec![b'a'; CHUNK_SIZE + 1];
    input.extend(b".eyJ9.synthetic password=synthetic");
    let options = DetectOptions::default();
    let expected = full_buffer(&input, &options);
    assert_eq!(expected.1, vec![FileLimitation::OversizedRuleCandidate]);
    assert_eq!(expected.0.len(), 1);
    assert_eq!(streamed(&input, &[CHUNK_SIZE], &options), expected);
}

#[test]
fn a_long_card_digit_run_cannot_turn_into_a_match_at_the_window_edge() {
    use redactpad_lib::detector::stream::CHUNK_SIZE;

    let mut input = vec![b'0'; CHUNK_SIZE - 1];
    input.extend(b" 4111111111111111 card");
    let options = DetectOptions::default();
    let expected = full_buffer(&input, &options);
    assert!(expected.0.is_empty());
    assert_eq!(streamed(&input, &[CHUNK_SIZE], &options), expected);
}

#[test]
fn pem_indentation_without_a_marker_is_ordinary_text() {
    let options = DetectOptions::default();
    for (indent, suffix) in [(257, b"x\n".as_slice()), (257, b"\n"), (256, b"-x\n")] {
        let mut input = vec![b' '; indent];
        input.extend(suffix);
        let expected = (Vec::new(), Vec::new(), input.clone());
        assert_eq!(full_buffer(&input, &options), expected);
        for split in 0..=input.len() {
            assert_eq!(streamed(&input, &[split], &options), expected);
        }
    }
}

#[test]
fn labeled_phone_padding_agrees_at_every_byte_split() {
    let options = DetectOptions::default();
    let padding = " ".repeat(4_400);
    let text = detect("phone=123   4567", &options);
    assert_eq!(text.spans.len(), 1);
    assert_eq!((text.spans[0].start, text.spans[0].end), (6, 16));

    for (input, output, spans, warnings) in [
        (
            "phone=123   4567".into(),
            "phone=[REDACTED:pii.phone]".into(),
            &[(6, 16, "pii.phone")][..],
            &[][..],
        ),
        (
            format!("phone=1234567{padding}\n"),
            format!("phone=[REDACTED:pii.phone]{padding}\n"),
            &[(6, 13, "pii.phone")][..],
            &[],
        ),
        (
            format!("phone=1{padding}234567\n"),
            format!("phone=1{padding}234567\n"),
            &[],
            &[FileLimitation::OversizedRuleCandidate],
        ),
    ] {
        let expected = full_buffer(input.as_bytes(), &options);
        assert_eq!(expected.1, warnings);
        assert_eq!(expected.2, output.as_bytes());
        assert_eq!(
            expected
                .0
                .iter()
                .map(|span| (span.start, span.end, span.reason_id))
                .collect::<Vec<_>>(),
            spans
        );
        for split in 0..=input.len() {
            assert_eq!(
                streamed(input.as_bytes(), &[split], &options),
                expected,
                "split {split}"
            );
        }
    }
}

#[test]
fn oversized_uri_and_phone_agree_across_scan_windows() {
    use redactpad_lib::detector::stream::CHUNK_SIZE;

    for (prefix, padding, suffix) in [
        (
            b"postgres://user:synthetic@[".as_slice(),
            b'a',
            b"]\n".as_slice(),
        ),
        (b"phone=".as_slice(), b'1', b"\n".as_slice()),
        (b"phone".as_slice(), b' ', b"=1234567\n".as_slice()),
    ] {
        let mut input = vec![b'\n'; CHUNK_SIZE - 4_300];
        input.extend(prefix);
        input.extend(std::iter::repeat_n(padding, 4_400));
        input.extend(suffix);
        let options = DetectOptions::default();
        let expected = full_buffer(&input, &options);
        assert_eq!(expected.1, vec![FileLimitation::OversizedRuleCandidate]);
        assert_eq!(streamed(&input, &[CHUNK_SIZE], &options), expected);
    }
}

#[test]
fn unresolved_phone_tails_cross_a_scan_window() {
    use redactpad_lib::detector::stream::{CHUNK_SIZE, MAX_OVERLAP_CLUSTER};

    let options = DetectOptions::default();
    for (length, suffix, oversized) in [
        (4_400, b"\n".as_slice(), false),
        (4_400, b"".as_slice(), false),
        (4_400, b"x".as_slice(), false),
        (4_400, b"8\n".as_slice(), true),
        (4_400, b"(89)\n".as_slice(), true),
        (4_400, b"(\n".as_slice(), true),
        (MAX_OVERLAP_CLUSTER, b"\n".as_slice(), false),
        (MAX_OVERLAP_CLUSTER + 1, b"\n".as_slice(), true),
    ] {
        let mut input = vec![b'\n'; CHUNK_SIZE - 4_300];
        input.extend(b"phone=1234567");
        input.extend(std::iter::repeat_n(b' ', length));
        input.extend(suffix);
        let expected = full_buffer(&input, &options);
        if oversized {
            assert_eq!(expected.1, [FileLimitation::OversizedRuleCandidate]);
            assert!(expected.0.is_empty());
        } else {
            assert!(expected.1.is_empty());
            assert_eq!(expected.0.len(), 1);
            assert_eq!(expected.0[0].reason_id, "pii.phone");
        }
        for split in CHUNK_SIZE - 2..=CHUNK_SIZE + 2 {
            assert_eq!(streamed(&input, &[split], &options), expected);
        }
    }
}
