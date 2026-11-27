use std::time::Instant;

use redactpad_lib::detector::{detect, DetectOptions};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    id: String,
    suite: String,
    text: String,
    #[serde(default)]
    options: DetectOptions,
    expected: Vec<Expected>,
}

#[derive(Deserialize)]
struct Expected {
    start: usize,
    end: usize,
    reason_id: String,
}

#[test]
fn scores_independently_labeled_corpus() {
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("../../fixtures/corpus/corpus.json")).unwrap();
    let (mut tp, mut emitted, mut provider_tp, mut provider_expected, mut negatives) =
        (0, 0, 0, 0, 0);
    for fixture in fixtures {
        let result = detect(&fixture.text, &fixture.options);
        let hits = result
            .spans
            .iter()
            .filter(|span| {
                fixture.expected.iter().any(|expected| {
                    (span.start, span.end, span.reason_id)
                        == (expected.start, expected.end, expected.reason_id.as_str())
                })
            })
            .count();
        if hits != fixture.expected.len() || hits != result.spans.len() {
            eprintln!(
                "{}: {hits}/{} exact, {} emitted",
                fixture.id,
                fixture.expected.len(),
                result.spans.len()
            );
        }
        tp += hits;
        emitted += result.spans.len();
        if fixture.suite == "supported_provider" {
            provider_tp += hits;
            provider_expected += fixture.expected.len();
        }
        if fixture.suite == "canonical_negative" {
            negatives += result.spans.len();
        }
    }
    let precision = 100.0 * tp as f64 / emitted as f64;
    println!("Exact {tp}/{emitted} ({precision:.2}%), provider {provider_tp}/{provider_expected}, canonical negative hits {negatives}");
    assert!(precision >= 99.0);
    assert!(provider_expected > 0);
    assert_eq!(provider_tp, provider_expected);
    assert_eq!(negatives, 0);
}

#[test]
fn benchmark_fixture_has_ordered_utf8_spans() {
    let text = include_str!("../../fixtures/corpus/bench_100kib.txt");
    assert_eq!(text.len(), 102_400);
    detect("", &DetectOptions::default());
    let started = Instant::now();
    let result = detect(text, &DetectOptions::default());
    println!(
        "100 KiB scan: {:?}, {} spans",
        started.elapsed(),
        result.spans.len()
    );
    assert!(!result.spans.is_empty());
    let mut previous_end = 0;
    for span in result.spans {
        assert!(previous_end <= span.start && span.start < span.end);
        assert!(text.get(span.start..span.end).is_some());
        previous_end = span.end;
    }
}
