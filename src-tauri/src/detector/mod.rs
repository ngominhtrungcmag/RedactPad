//! Deterministic detection over half-open UTF-8 byte ranges.

pub mod stream;

use std::cmp::Reverse;
use std::collections::{BTreeMap, HashMap};
use std::sync::OnceLock;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use regex::{Match, Regex};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const PEM_LIMIT: usize = 16_384;

#[derive(Clone, Default, Deserialize)]
pub struct DetectOptions {
    #[serde(default)]
    pub phone_locales: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Span {
    pub start: usize,
    pub end: usize,
    pub reason_id: &'static str,
    pub reason_label: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum WorkbenchWarning {
    OversizedPemBlock,
}

pub struct Detection {
    pub spans: Vec<Span>,
    pub warnings: Vec<WorkbenchWarning>,
}

type Reason = (u8, &'static str, &'static str);

const PEM: Reason = (1, "key.pem_private_key", "PEM private key");
const DATABASE: Reason = (2, "connection.database_uri", "Database connection URI");
const JWT: Reason = (4, "auth.jwt", "JSON Web Token");
const BEARER: Reason = (5, "auth.bearer_token", "Bearer token");
const BASIC: Reason = (
    5,
    "auth.basic_credentials",
    "Basic authorization credentials",
);
const FIELD: Reason = (6, "credential.field", "Credential field");
const CARD: Reason = (7, "pii.payment_card", "Payment card number");
const EMAIL: Reason = (8, "pii.email", "Email address");
const PHONE: Reason = (9, "pii.phone", "Phone number");

const PROVIDERS: [(Reason, &str); 6] = [
    (
        (3, "provider.aws_access_key_id", "AWS access key ID"),
        r"(?:AKIA|ASIA)[A-Z0-9]{16}",
    ),
    (
        (3, "provider.github_token", "GitHub token"),
        r"(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})",
    ),
    (
        (3, "provider.openai_api_key", "OpenAI API key"),
        r"sk-(?:(?:proj|svcacct)-[A-Za-z0-9_-]{32,}|[A-Za-z0-9]{48})",
    ),
    (
        (3, "provider.anthropic_api_key", "Anthropic API key"),
        r"sk-ant-api[0-9]{2}-[A-Za-z0-9_-]{32,}",
    ),
    (
        (3, "provider.slack_token", "Slack token"),
        r"xox[baprs]-[0-9]{9,}(?:-[0-9]{9,}){0,2}-[A-Za-z0-9]{16,}",
    ),
    (
        (3, "provider.stripe_key", "Stripe key"),
        r"(?:(?:sk|rk)_(?:live|test)_|whsec_)[A-Za-z0-9]{16,}",
    ),
];

const US_NUMBER: &str =
    r"(?:\+?1[ .-]?)?(?:\([2-9][0-9]{2}\)[ .-]?|[2-9][0-9]{2}[ .-]?)[2-9][0-9]{2}[ .-]?[0-9]{4}";

struct Rules {
    pem: Regex,
    database: Regex,
    providers: Vec<(Reason, Regex)>,
    jwt: Regex,
    authorization: Regex,
    field: Regex,
    card: Regex,
    payment_context: Regex,
    email: Regex,
    phone: Regex,
    us_phone: Regex,
}

fn rules() -> &'static Rules {
    static RULES: OnceLock<Rules> = OnceLock::new();
    RULES.get_or_init(|| {
        let compile = |pattern| Regex::new(pattern).expect("valid detector rule");
        Rules {
            pem: compile(r"(?m)^[ \t]*(-----(BEGIN|END) ((?:[A-Z0-9]+ )*PRIVATE KEY)-----)[ \t]*\r?$"),
            database: compile(r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|mssql|sqlserver|oracle|cockroachdb)://[^\s/:@<>"'(),;]*:[^\s/@<>"'(),;]+@(?:\[[0-9a-f:.]+\]|[a-z0-9][a-z0-9._-]*)(?::[0-9]+)?(?:[/?#][^\s<>"'\x60]*)?"#),
            providers: PROVIDERS.iter().map(|&(reason, pattern)| (reason, compile(pattern))).collect(),
            jwt: compile(r"\b([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)"),
            authorization: compile(r#"(?i)\bauthorization["']?[ \t]*[:=][ \t]*["']?(bearer|basic) ([A-Za-z0-9._~+/-]+=*)"#),
            field: compile(r#"(?i)\b(?:pass(?:word|wd|phrase)?|pwd|api[_-]?key|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|secret[_-]?key|token|secret)["']?[ \t]*[:=][ \t]*(?:"((?:[^"\\\r\n]|\\[^\r\n])+)"|'((?:[^'\\\r\n]|\\[^\r\n])+)'|([^\s"',;}\]<>]+))"#),
            card: compile(r"[0-9](?:[ -]?[0-9])+"),
            payment_context: compile(r"(?i)\b(?:payment(?:[ _-]+card)?|(?:credit|debit)[ _-]+card|card(?:[ _-]+(?:number|no))?|pan)\b"),
            email: compile(r"[A-Za-z0-9_%+-]+(?:\.[A-Za-z0-9_%+-]+)*@(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}"),
            phone: compile(r"(?i)\b(?:phone(?:[ _-]+number)?|tel(?:ephone)?|mobile|fax|cell)(?:[ \t]*[:=][ \t]*|[ \t]+)(\+?(?:\([0-9]{1,4}\)|[0-9])(?:[ .-]*(?:[0-9]|\([0-9]{1,4}\)))*)"),
            us_phone: Regex::new(US_NUMBER).expect("valid US phone rule"),
        }
    })
}

fn add(
    candidates: &mut Vec<(u8, Span)>,
    start: usize,
    end: usize,
    (priority, reason_id, reason_label): Reason,
) {
    candidates.push((
        priority,
        Span {
            start,
            end,
            reason_id,
            reason_label,
        },
    ));
}

fn token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-')
}

fn token_boundary(text: &str, m: Match<'_>) -> bool {
    !m.start()
        .checked_sub(1)
        .and_then(|i| text.as_bytes().get(i))
        .copied()
        .is_some_and(token_byte)
        && !text
            .as_bytes()
            .get(m.end())
            .copied()
            .is_some_and(token_byte)
}

fn jwt_json(segment: &str) -> Option<Value> {
    let decoded = URL_SAFE_NO_PAD.decode(segment).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn luhn(digits: &[u8]) -> bool {
    (13..=19).contains(&digits.len())
        && digits.iter().any(|&digit| digit != 0)
        && digits
            .iter()
            .rev()
            .enumerate()
            .map(|(index, &digit)| {
                let doubled = digit * 2;
                if index % 2 == 0 {
                    digit
                } else if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            })
            .sum::<u8>()
            % 10
            == 0
}

fn phone_digits(value: &str) -> usize {
    value.bytes().filter(u8::is_ascii_digit).count()
}

fn resolve(mut candidates: Vec<(u8, Span)>) -> Vec<Span> {
    candidates.sort_unstable_by_key(|&(priority, span)| {
        (
            priority,
            span.start,
            Reverse(span.end - span.start),
            span.reason_id,
        )
    });
    let mut kept: BTreeMap<usize, Span> = BTreeMap::new();
    for (_, span) in candidates {
        if !kept
            .range(..span.end)
            .next_back()
            .is_some_and(|(_, other)| other.end > span.start)
        {
            kept.insert(span.start, span);
        }
    }
    kept.into_values().collect()
}

fn pem_blocks(text: &str, regex: &Regex, candidates: &mut Vec<(u8, Span)>) -> bool {
    let mut opens = HashMap::new();
    let mut oversized = false;
    for captures in regex.captures_iter(text) {
        let marker = captures.get(1).unwrap();
        let label = captures.get(3).unwrap().as_str();
        if &captures[2] == "BEGIN" {
            opens.insert(label, marker.start());
        } else if let Some(start) = opens.remove(label) {
            if marker.end() - start <= PEM_LIMIT {
                add(candidates, start, marker.end(), PEM);
            } else {
                oversized = true;
            }
        }
    }
    oversized
}

fn uri_end(uri: &str) -> usize {
    let mut end = uri.trim_end_matches([',', '.', ';', '!', '?']).len();
    for (left, right) in [('(', ')'), ('[', ']'), ('{', '}')] {
        let extra = uri[..end]
            .matches(right)
            .count()
            .saturating_sub(uri[..end].matches(left).count());
        for _ in 0..extra {
            if !uri[..end].ends_with(right) {
                break;
            }
            end -= 1;
        }
    }
    end
}

fn payment_context(text: &str, card: Match<'_>, regex: &Regex) -> bool {
    let start = text.ceil_char_boundary(card.start().saturating_sub(48));
    let end = text.floor_char_boundary((card.end() + 48).min(text.len()));
    let before = text[start..card.start()]
        .rsplit(['\n', '\r'])
        .next()
        .unwrap_or("");
    let after = text[card.end()..end]
        .split(['\n', '\r'])
        .next()
        .unwrap_or("");
    regex.is_match(before) || regex.is_match(after)
}

/// Find supported secrets and contextual PII without retaining input or matched values.
pub fn detect(text: &str, options: &DetectOptions) -> Detection {
    let rules = rules();
    let mut candidates = Vec::new();
    let oversized_pem = pem_blocks(text, &rules.pem, &mut candidates);
    for m in rules.database.find_iter(text) {
        add(
            &mut candidates,
            m.start(),
            m.start() + uri_end(m.as_str()),
            DATABASE,
        );
    }
    for &(reason, ref regex) in &rules.providers {
        for m in regex.find_iter(text).filter(|&m| token_boundary(text, m)) {
            add(&mut candidates, m.start(), m.end(), reason);
        }
    }
    for captures in rules.jwt.captures_iter(text) {
        let m = captures.get(0).unwrap();
        if token_boundary(text, m)
            && jwt_json(&captures[1])
                .and_then(|header| header.get("alg")?.as_str().map(|alg| !alg.is_empty()))
                .unwrap_or(false)
            && jwt_json(&captures[2]).is_some_and(|payload| payload.is_object())
            && URL_SAFE_NO_PAD.decode(&captures[3]).is_ok()
        {
            add(&mut candidates, m.start(), m.end(), JWT);
        }
    }
    for captures in rules.authorization.captures_iter(text) {
        let m = captures.get(2).unwrap();
        let (value, reason) = if captures[1].eq_ignore_ascii_case("bearer") {
            (m.as_str().trim_end_matches('.'), BEARER)
        } else {
            let value = m.as_str().trim_end_matches('.');
            if !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                continue;
            }
            (value, BASIC)
        };
        if !value.is_empty() {
            add(&mut candidates, m.start(), m.start() + value.len(), reason);
        }
    }
    for captures in rules.field.captures_iter(text) {
        let m = captures.iter().skip(1).flatten().next().unwrap();
        let trimmed = m.as_str().trim_start();
        let start = m.end() - trimmed.len();
        let value = trimmed.trim_end();
        if !value.is_empty() {
            add(&mut candidates, start, start + value.len(), FIELD);
        }
    }
    for m in rules.card.find_iter(text) {
        if m.len() <= 37
            && token_boundary(text, m)
            && payment_context(text, m, &rules.payment_context)
        {
            let digits: Vec<_> = m
                .as_str()
                .bytes()
                .filter(u8::is_ascii_digit)
                .map(|b| b - b'0')
                .collect();
            if luhn(&digits) {
                add(&mut candidates, m.start(), m.end(), CARD);
            }
        }
    }
    for m in rules
        .email
        .find_iter(text)
        .filter(|&m| token_boundary(text, m))
    {
        add(&mut candidates, m.start(), m.end(), EMAIL);
    }
    for captures in rules.phone.captures_iter(text) {
        let m = captures.get(1).unwrap();
        if (7..=15).contains(&phone_digits(m.as_str())) {
            add(&mut candidates, m.start(), m.end(), PHONE);
        }
    }
    if options
        .phone_locales
        .iter()
        .any(|locale| locale.eq_ignore_ascii_case("US"))
    {
        for m in rules
            .us_phone
            .find_iter(text)
            .filter(|&m| token_boundary(text, m))
        {
            add(&mut candidates, m.start(), m.end(), PHONE);
        }
    }
    Detection {
        spans: resolve(candidates),
        warnings: if oversized_pem {
            vec![WorkbenchWarning::OversizedPemBlock]
        } else {
            vec![]
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rules_match_the_exact_entity() {
        for (reason, prefix, value) in [
            (
                "key.pem_private_key",
                "",
                "-----BEGIN RSA PRIVATE KEY-----\r\nabcd\r\n-----END RSA PRIVATE KEY-----",
            ),
            (
                "connection.database_uri",
                "🔐 ",
                "mongodb+srv://fixture:p%40ss@example.test/db?retryWrites=true#state",
            ),
            ("provider.aws_access_key_id", "id: ", "ASIA0000000000000000"),
            (
                "provider.github_token",
                "token: ",
                "gho_000000000000000000000000000000000000",
            ),
            (
                "provider.openai_api_key",
                "key: ",
                "sk-svcacct-00000000000000000000000000000000",
            ),
            (
                "provider.anthropic_api_key",
                "key: ",
                "sk-ant-api03-00000000000000000000000000000000-AA",
            ),
            (
                "provider.slack_token",
                "token: ",
                "xoxb-0000000000-0000000000000000",
            ),
            ("provider.stripe_key", "key: ", "rk_test_0000000000000000"),
            (
                "auth.jwt",
                "Authorization: Bearer ",
                "eyJhbGciOiJIUzI1NiJ9.e30.ZmFrZQ",
            ),
            (
                "auth.bearer_token",
                "Authorization: Bearer ",
                "fictional/token-1=",
            ),
            ("auth.basic_credentials", "Authorization: Basic ", "dTpw"),
            (
                "credential.field",
                "password = \"  ",
                "fictional \"quoted\" value",
            ),
            (
                "pii.payment_card",
                "Debit card number: ",
                "4242-4242-4242-4242",
            ),
            ("pii.email", "📧 ", "test+alias@sub.example.test"),
            ("pii.phone", "Mobile: ", "+44 (20) 7946 0958"),
        ] {
            let (value, suffix) = if reason == "credential.field" {
                (value.replace('"', "\\\""), "  \"\n")
            } else {
                (value.to_owned(), "\n")
            };
            let text = format!("{prefix}{value}{suffix}");
            let detection = detect(&text, &DetectOptions::default());
            assert_eq!(detection.spans.len(), 1, "{reason}");
            let span = detection.spans[0];
            assert_eq!(
                (span.start, span.end, span.reason_id),
                (prefix.len(), prefix.len() + value.len(), reason)
            );
        }
    }

    #[test]
    fn requires_context_or_valid_structure() {
        let text = "Bearer a-fake-token\nBasic dTpw\n4242424242424242\n202-555-0100\ninvalid.e30.ZmFrZQ\n00000000-0000-4000-8000-000000000001\n06cd5e5c4ccab49aa353052ab20e2ce9c69007b0\n2026-11-27T08:15:30.000Z\n1.2.3\n0123456789abcdef0123456789abcdef";
        assert!(detect(text, &DetectOptions::default()).spans.is_empty());
        let opted_in = detect(
            text,
            &DetectOptions {
                phone_locales: vec!["US".into()],
            },
        );
        assert_eq!(opted_in.spans.len(), 1);
        assert_eq!(opted_in.spans[0].reason_id, PHONE.1);
        assert_eq!(
            &text[opted_in.spans[0].start..opted_in.spans[0].end],
            "202-555-0100"
        );
        for text in [
            "Authorization: Basic !!!",
            "Payment card: 4242424242424243",
            "postgres://example.test/db",
            "a@localhost",
            "password = \"\"",
        ] {
            assert!(detect(text, &DetectOptions::default()).spans.is_empty());
        }
    }

    #[test]
    fn pem_cap_includes_delimiters_and_oversized_blocks_preserve_credentials() {
        let head = "-----BEGIN PRIVATE KEY-----\n";
        let tail = "\nAKIA0000000000000000\n-----END PRIVATE KEY-----";
        let block = format!(
            "{head}{}{tail}\n",
            "A".repeat(PEM_LIMIT - head.len() - tail.len())
        );
        let exact = detect(&block, &DetectOptions::default());
        assert_eq!(exact.spans.len(), 1);
        assert_eq!(exact.spans[0].reason_id, PEM.1);
        assert_eq!(exact.spans[0].end, PEM_LIMIT);
        assert!(exact.warnings.is_empty());
        let oversized = format!("\n{}", block.replacen("\nA", "\nAA", 1));
        let rejected = detect(&oversized, &DetectOptions::default());
        let start = oversized.find("AKIA").unwrap();
        assert_eq!(rejected.spans.len(), 1);
        let span = rejected.spans[0];
        assert_eq!(
            (span.start, span.end, span.reason_id),
            (start, start + 20, "provider.aws_access_key_id")
        );
        assert_eq!(rejected.warnings, [WorkbenchWarning::OversizedPemBlock]);
        let mismatched = detect(
            "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----",
            &DetectOptions::default(),
        );
        assert!(mismatched.spans.is_empty());
    }

    #[test]
    fn overlap_resolution_uses_all_tie_breakers() {
        let mut entries = Vec::new();
        add(&mut entries, 0, 9, (2, "later.priority", ""));
        add(&mut entries, 2, 7, (1, "first.shorter", ""));
        add(&mut entries, 3, 10, (1, "later.start", ""));
        add(&mut entries, 2, 8, (1, "z", ""));
        add(&mut entries, 2, 8, (1, "a", ""));
        add(&mut entries, 8, 9, (1, "adjacent", ""));
        let resolved = resolve(entries);
        assert_eq!(
            resolved
                .iter()
                .map(|span| span.reason_id)
                .collect::<Vec<_>>(),
            ["a", "adjacent"]
        );
    }
}
