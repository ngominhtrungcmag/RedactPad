//! Raw byte detection. Rule match lengths include prefixes and separators;
//! every non-PEM rule is limited to 4096 bytes and a single line.
//! Provider, JWT, email and US phone boundaries inspect one adjacent byte.
//! Field, authorization, URI and labeled phone rules use one left boundary byte.
//! Card recognition uses one-byte token boundaries and 48 bytes of line-local
//! context on each side. PEM uses line boundaries and bounded delimiter lines.

use std::io::{self, Write};

use regex::bytes::{Captures, Match, Regex};

use super::*;

pub const MAX_LEFT_CONTEXT: usize = 128;
pub const MAX_RIGHT_CONTEXT: usize = 64;
pub const MAX_NON_PEM_MATCH: usize = 4096;
pub const MAX_PEM_MARKER_LINE: usize = 256;
pub const PEM_LIMIT: usize = super::PEM_LIMIT;
pub const MAX_OVERLAP_CLUSTER: usize = 65536;
pub const CHUNK_SIZE: usize = 256 * 1024;
const LOOKAHEAD: usize = MAX_NON_PEM_MATCH + MAX_RIGHT_CONTEXT + MAX_LEFT_CONTEXT;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum FileLimitation {
    OversizedPemBlock,
    UnclosedPemBlock,
    UnsupportedMultilineCandidate,
    OversizedRuleCandidate,
    OversizedOverlapCluster,
}

fn warn(warnings: &mut Vec<FileLimitation>, warning: FileLimitation) {
    if !warnings.contains(&warning) {
        warnings.push(warning);
        warnings.sort_unstable();
    }
}

type Candidate = (u8, Span);

const FIELD_START: &str = r#"(?i)\b(?:pass(?:word|wd|phrase)?|pwd|api[_-]?key|client[_-]?secret|aws[_-]?secret[_-]?access[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|secret[_-]?key|token|secret)["']?[ \t]*"#;

#[derive(Clone, Copy)]
enum Rule {
    Database,
    Provider(Reason),
    Jwt,
    Authorization,
    Field,
    OverflowPrefix,
    DoubleQuoted,
    SingleQuoted,
    Card,
    Email,
    Phone,
    UsPhone,
}

fn compile(pattern: &str) -> Regex {
    Regex::new(&format!("(?-u:{pattern})")).expect("valid byte detector rule")
}

fn byte_rules() -> &'static [(Rule, Regex)] {
    static RULES: OnceLock<Vec<(Rule, Regex)>> = OnceLock::new();
    RULES.get_or_init(|| {
        let text = super::rules();
        let mut rules: Vec<_> = text
            .providers
            .iter()
            .map(|(reason, pattern)| (Rule::Provider(*reason), compile(pattern.as_str())))
            .collect();
        rules.extend([
            (Rule::Database, compile(text.database.as_str())),
            (Rule::Jwt, compile(text.jwt.as_str())),
            (Rule::Authorization, compile(text.authorization.as_str())),
            (Rule::Field, compile(text.field.as_str())),
            (
                Rule::OverflowPrefix,
                compile(&format!(r"{FIELD_START}(?:[:=][ \t]*)?")),
            ),
            (
                Rule::DoubleQuoted,
                compile(&format!(
                    r#"{FIELD_START}[:=][ \t]*"(?:[^"\\\r\n]|\\[^\r\n])*(?:\\?[\r\n])?"#
                )),
            ),
            (
                Rule::SingleQuoted,
                compile(&format!(
                    r"{FIELD_START}[:=][ \t]*'(?:[^'\\\r\n]|\\[^\r\n])*(?:\\?[\r\n])?"
                )),
            ),
            (Rule::OverflowPrefix, compile(r#"(?i)\bauthorization["']?[ \t]*(?:[:=][ \t]*["']?(?:bearer|basic)?)?"#)),
            (Rule::OverflowPrefix, compile(r"(?i)\b(?:phone(?:[ _-]+number)?|tel(?:ephone)?|mobile|fax|cell)[ \t]*(?:[:=][ \t]*)?")),
            (Rule::OverflowPrefix, compile(r#"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|mssql|sqlserver|oracle|cockroachdb)://[^\s/:@<>"'(),;]*(?::(?:[^\s/@<>"'(),;]+(?:@\[[0-9a-f:.]*)?)?)?"#)),
            (Rule::OverflowPrefix, compile(r"\b(?:eyJ[A-Za-z0-9_-]*|[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.)[A-Za-z0-9_-]*")),
            (Rule::OverflowPrefix, compile(r"[A-Za-z0-9_%+-]+(?:\.[A-Za-z0-9_%+-]+)*@[A-Za-z0-9.-]+")),
            (Rule::OverflowPrefix, compile(r"xox[baprs]-[0-9]+(?:-[0-9]+){0,2}")),
            (
                Rule::OverflowPrefix,
                compile(r"(?:AKIA|ASIA)[A-Z0-9]{16,}|(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{36,}|sk-[A-Za-z0-9_-]{48,}"),
            ),
            (Rule::Card, compile(text.card.as_str())),
            (Rule::Email, compile(text.email.as_str())),
            (Rule::Phone, compile(text.phone.as_str())),
            (Rule::UsPhone, compile(text.us_phone.as_str())),
        ]);
        rules
    })
}

fn boundary(bytes: &[u8], matched: Match<'_>) -> bool {
    !matched
        .start()
        .checked_sub(1)
        .is_some_and(|index| token_byte(bytes[index]))
        && !bytes.get(matched.end()).copied().is_some_and(token_byte)
}

fn has_payment_context(bytes: &[u8], matched: Match<'_>) -> bool {
    static PAYMENT: OnceLock<Regex> = OnceLock::new();
    let pattern = PAYMENT.get_or_init(|| compile(super::rules().payment_context.as_str()));
    let before = &bytes[matched.start().saturating_sub(48)..matched.start()];
    let after = &bytes[matched.end()..(matched.end() + 48).min(bytes.len())];
    pattern.is_match(
        before
            .rsplit(|b| matches!(b, b'\r' | b'\n'))
            .next()
            .unwrap(),
    ) || pattern.is_match(after.split(|b| matches!(b, b'\r' | b'\n')).next().unwrap())
}

fn trimmed_match(bytes: &[u8], matched: Match<'_>, trim: fn(&[u8]) -> &[u8]) -> (usize, usize) {
    let value = trim(matched.as_bytes());
    let start = value.as_ptr() as usize - bytes.as_ptr() as usize;
    (start, start + value.len())
}

fn uri_length(bytes: &[u8]) -> usize {
    let mut end = bytes.len();
    while end > 0 && matches!(bytes[end - 1], b',' | b'.' | b';' | b'!' | b'?') {
        end -= 1;
    }
    for (left, right) in [(b'(', b')'), (b'[', b']'), (b'{', b'}')] {
        let balance: i32 = bytes[..end]
            .iter()
            .map(|&byte| i32::from(byte == right) - i32::from(byte == left))
            .sum();
        for _ in 0..balance {
            if bytes[..end].last() != Some(&right) {
                break;
            }
            end -= 1;
        }
    }
    end
}

enum PhoneTail {
    Complete,
    Pending,
    Oversized,
}

fn phone_tail(bytes: &[u8], matched: Match<'_>, eof: bool) -> PhoneTail {
    if matched.len() > MAX_NON_PEM_MATCH {
        return PhoneTail::Oversized;
    }

    let tail = &bytes[matched.end()..];
    let separators = tail
        .iter()
        .take(MAX_OVERLAP_CLUSTER + 1)
        .take_while(|&&byte| matches!(byte, b' ' | b'.' | b'-'))
        .count();
    if separators > MAX_OVERLAP_CLUSTER {
        return PhoneTail::Oversized;
    }
    match tail.get(separators) {
        // The regex already consumed digits and complete parenthesized groups.
        Some(b'(') if matched.len() + separators + 1 > MAX_NON_PEM_MATCH => PhoneTail::Oversized,
        None if !eof => PhoneTail::Pending,
        _ => PhoneTail::Complete,
    }
}

fn candidate(
    rule: Rule,
    bytes: &[u8],
    captures: Captures<'_>,
    base: usize,
    candidates: &mut Vec<Candidate>,
    warnings: &mut Vec<FileLimitation>,
) {
    let matched = captures.get(0).unwrap();
    if matched.len() > MAX_NON_PEM_MATCH {
        if !matches!(rule, Rule::Card) {
            warn(warnings, FileLimitation::OversizedRuleCandidate);
        }
        return;
    }
    let mut start = matched.start();
    let mut end = matched.end();
    let reason = match rule {
        Rule::Database => {
            end = start + uri_length(matched.as_bytes());
            DATABASE
        }
        Rule::Provider(reason) if boundary(bytes, matched) => reason,
        Rule::Jwt if boundary(bytes, matched) => {
            let json = |index| jwt_json(std::str::from_utf8(captures.get(index)?.as_bytes()).ok()?);
            let valid_header = json(1).is_some_and(|value| {
                value
                    .get("alg")
                    .and_then(Value::as_str)
                    .is_some_and(|alg| !alg.is_empty())
            });
            if !valid_header
                || !json(2).is_some_and(|value| value.is_object())
                || URL_SAFE_NO_PAD.decode(&captures[3]).is_err()
            {
                return;
            }
            JWT
        }
        Rule::Authorization => {
            let value = captures.get(2).unwrap();
            start = value.start();
            end = value.end();
            while end > start && bytes[end - 1] == b'.' {
                end -= 1;
            }
            if captures[1].eq_ignore_ascii_case(b"bearer") {
                BEARER
            } else if bytes[start..end]
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                BASIC
            } else {
                return;
            }
        }
        Rule::Field => {
            let value = captures.iter().skip(1).flatten().next().unwrap();
            (start, end) = trimmed_match(bytes, value, <[u8]>::trim_ascii);
            FIELD
        }
        Rule::DoubleQuoted | Rule::SingleQuoted => {
            if matches!(matched.as_bytes().last(), Some(b'\r' | b'\n')) {
                warn(warnings, FileLimitation::UnsupportedMultilineCandidate);
            }
            return;
        }
        Rule::Card
            if matched.len() <= 37
                && boundary(bytes, matched)
                && has_payment_context(bytes, matched) =>
        {
            let mut digits = [0; 37];
            let mut count = 0;
            for &digit in matched.as_bytes().iter().filter(|d| d.is_ascii_digit()) {
                digits[count] = digit - b'0';
                count += 1;
            }
            if !luhn(&digits[..count]) {
                return;
            }
            CARD
        }
        Rule::Email if boundary(bytes, matched) => EMAIL,
        Rule::Phone => {
            let value = captures.get(1).unwrap();
            if !(7..=15).contains(
                &value
                    .as_bytes()
                    .iter()
                    .filter(|b| b.is_ascii_digit())
                    .count(),
            ) {
                return;
            }
            (start, end) = (value.start(), value.end());
            PHONE
        }
        Rule::UsPhone if boundary(bytes, matched) => PHONE,
        _ => return,
    };
    if start < end {
        add(candidates, base + start, base + end, reason);
    }
}

fn enabled(rule: Rule, bytes: &[u8], us_phone: bool) -> bool {
    match rule {
        Rule::Jwt => bytes.contains(&b'.'),
        Rule::Email => bytes.contains(&b'@'),
        Rule::UsPhone => us_phone,
        _ => true,
    }
}

fn us_phone(options: &DetectOptions) -> bool {
    options
        .phone_locales
        .iter()
        .any(|locale| locale.eq_ignore_ascii_case("US"))
}

#[derive(Clone, Default)]
struct LongTokenState {
    email_len: usize,
    jwt_len: usize,
    jwt_parts: u8,
    jwt_after_dot: bool,
}

impl LongTokenState {
    fn push(&mut self, bytes: &[u8], warnings: &mut Vec<FileLimitation>) {
        for &byte in bytes {
            if token_byte(byte) || matches!(byte, b'%' | b'+' | b'.') {
                self.email_len = (self.email_len + 1).min(MAX_NON_PEM_MATCH + 1);
            } else {
                if byte == b'@' && self.email_len >= MAX_NON_PEM_MATCH {
                    warn(warnings, FileLimitation::OversizedRuleCandidate);
                }
                self.email_len = 0;
            }

            if token_byte(byte) {
                if self.jwt_parts == 0 {
                    // A leading hyphen cannot satisfy the initial ASCII word boundary.
                    if byte == b'-' {
                        continue;
                    }
                    self.jwt_parts = 1;
                } else if self.jwt_after_dot {
                    self.jwt_parts += 1;
                    self.jwt_after_dot = false;
                }
                self.jwt_len = (self.jwt_len + 1).min(MAX_NON_PEM_MATCH + 1);
                if self.jwt_parts == 3 && self.jwt_len > MAX_NON_PEM_MATCH {
                    warn(warnings, FileLimitation::OversizedRuleCandidate);
                }
            } else if byte == b'.' && (1..3).contains(&self.jwt_parts) && !self.jwt_after_dot {
                self.jwt_after_dot = true;
                self.jwt_len = (self.jwt_len + 1).min(MAX_NON_PEM_MATCH + 1);
            } else {
                self.jwt_parts = 0;
                self.jwt_len = 0;
                self.jwt_after_dot = false;
            }
        }
    }
}

fn pem_pattern() -> &'static Regex {
    static PEM_PATTERN: OnceLock<Regex> = OnceLock::new();
    PEM_PATTERN.get_or_init(|| compile(super::rules().pem.as_str()))
}

const PEM_MARKERS: [&[u8]; 2] = [b"-----BEGIN", b"-----END"];

fn starts_marker(line: &[u8]) -> bool {
    PEM_MARKERS.iter().any(|marker| line.starts_with(marker))
}

fn possible_marker(line: &[u8]) -> bool {
    let line = line.trim_ascii_start();
    PEM_MARKERS
        .iter()
        .any(|prefix| prefix.starts_with(line) || line.starts_with(prefix))
}

#[derive(Clone, Default)]
struct PemState {
    line: Vec<u8>,
    line_start: usize,
    opens: Vec<(usize, Vec<u8>)>,
    ignoring_line: bool,
    excess_indent: bool,
}

impl PemState {
    fn line_end(
        &mut self,
        end: usize,
        candidates: &mut Vec<Candidate>,
        warnings: &mut Vec<FileLimitation>,
    ) {
        if let Some(captures) = (!self.line.is_empty())
            .then(|| pem_pattern().captures(&self.line))
            .flatten()
        {
            let marker = captures.get(1).unwrap();
            let label = captures.get(3).unwrap().as_bytes();
            if let Some(index) = self.opens.iter().position(|(_, value)| value == label) {
                let (start, _) = self.opens.remove(index);
                if &captures[2] == b"BEGIN" {
                    warn(warnings, FileLimitation::UnclosedPemBlock);
                } else if end - start <= PEM_LIMIT {
                    add(candidates, start, self.line_start + marker.end(), PEM);
                } else {
                    warn(warnings, FileLimitation::OversizedPemBlock);
                }
            }
            if &captures[2] == b"BEGIN" {
                self.opens
                    .push((self.line_start + marker.start(), label.to_vec()));
            }
        }
        self.line.clear();
        self.ignoring_line = false;
        self.excess_indent = false;
        self.line_start = end + 1;
    }

    fn push(
        &mut self,
        bytes: &[u8],
        start: usize,
        candidates: &mut Vec<Candidate>,
        warnings: &mut Vec<FileLimitation>,
    ) {
        for (index, &byte) in (start..).zip(bytes) {
            if matches!(byte, b'\r' | b'\n') {
                self.line_end(index, candidates, warnings);
            } else if !self.ignoring_line
                && !(self.excess_indent && self.line.is_empty() && byte.is_ascii_whitespace())
            {
                self.line.push(byte);
                if !possible_marker(&self.line) {
                    self.line.clear();
                    self.ignoring_line = true;
                } else {
                    if self.line.len() > MAX_PEM_MARKER_LINE {
                        let indent = self.line.len() - self.line.trim_ascii_start().len();
                        self.line.drain(..indent);
                        self.excess_indent = true;
                    }
                    if self.excess_indent && starts_marker(self.line.trim_ascii_start()) {
                        warn(warnings, FileLimitation::OversizedPemBlock);
                        self.opens.clear();
                        self.line.clear();
                        self.ignoring_line = true;
                    }
                }
            }

            // An END at the cap is valid only if this byte terminates the
            // complete delimiter line, including any horizontal padding.
            while self
                .opens
                .first()
                .is_some_and(|(open, _)| index - open >= PEM_LIMIT)
            {
                self.opens.remove(0);
                warn(warnings, FileLimitation::OversizedPemBlock);
            }
        }
    }

    fn frontier(&self, default: usize) -> usize {
        let frontier = self
            .opens
            .first()
            .map_or(default, |(start, _)| default.min(*start));
        if self.line.is_empty() || self.excess_indent {
            frontier
        } else {
            frontier.min(self.line_start)
        }
    }

    fn finish(
        &mut self,
        end: usize,
        candidates: &mut Vec<Candidate>,
        warnings: &mut Vec<FileLimitation>,
    ) {
        self.line_end(end, candidates, warnings);
        if !self.opens.is_empty() {
            warn(warnings, FileLimitation::UnclosedPemBlock);
            self.opens.clear();
        }
    }
}

fn cluster_end(candidates: &[Candidate]) -> (usize, usize) {
    let mut end = candidates[0].1.end;
    let mut count = 1;
    for (_, span) in &candidates[1..] {
        if span.start >= end {
            break;
        }
        end = end.max(span.end);
        count += 1;
    }
    (count, end)
}

fn order(candidates: &mut Vec<Candidate>) {
    candidates.sort_unstable_by_key(|(_, span)| (span.start, span.end, span.reason_id));
    candidates.dedup_by_key(|(_, span)| (span.start, span.end, span.reason_id));
}

fn redact(bytes: &[u8], base: usize, spans: &[Span], mut writer: impl Write) -> io::Result<()> {
    let mut start = 0;
    for span in spans {
        writer.write_all(&bytes[start..span.start - base])?;
        write!(writer, "[REDACTED:{}]", span.reason_id)?;
        start = span.end - base;
    }
    writer.write_all(&bytes[start..])
}

fn card_at_window_end(bytes: &[u8], end: usize) -> bool {
    matches!(&bytes[end..], [] | [b' ' | b'-'])
}

fn skip_card_continuation(bytes: &[u8], mut end: usize) -> usize {
    while end < bytes.len() {
        if bytes[end].is_ascii_digit() {
            end += 1;
        } else if matches!(bytes[end], b' ' | b'-')
            && bytes.get(end + 1).is_some_and(u8::is_ascii_digit)
        {
            end += 2;
        } else {
            break;
        }
    }
    end
}

#[derive(Clone)]
pub struct Scanner {
    bytes: Vec<u8>,
    base: usize,
    committed: usize,
    cursors: Vec<usize>,
    pending: Vec<Candidate>,
    pem: PemState,
    long_tokens: LongTokenState,
    warnings: Vec<FileLimitation>,
    us_phone: bool,
    next_scan: usize,
    card_continuation: bool,
}

impl Scanner {
    pub fn new(options: &DetectOptions) -> Self {
        Self {
            bytes: Vec::new(),
            base: 0,
            committed: 0,
            cursors: vec![0; byte_rules().len()],
            pending: Vec::new(),
            pem: PemState::default(),
            long_tokens: LongTokenState::default(),
            warnings: Vec::new(),
            us_phone: us_phone(options),
            next_scan: CHUNK_SIZE,
            card_continuation: false,
        }
    }

    pub(crate) fn checkpoint_bytes(&self) -> usize {
        self.bytes.capacity()
            + self.cursors.capacity() * std::mem::size_of::<usize>()
            + self.pending.capacity() * std::mem::size_of::<Candidate>()
            + self.pem.line.capacity()
            + self.pem.opens.capacity() * std::mem::size_of::<(usize, Vec<u8>)>()
            + self
                .pem
                .opens
                .iter()
                .map(|(_, label)| label.capacity())
                .sum::<usize>()
            + self.warnings.capacity() * std::mem::size_of::<FileLimitation>()
    }

    pub fn warnings(&self) -> &[FileLimitation] {
        &self.warnings
    }

    pub fn push(
        &mut self,
        mut bytes: &[u8],
        mut emit: impl FnMut(&[u8], &[Span]) -> io::Result<()>,
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            let input_end = self.base + self.bytes.len();
            let count = bytes.len().min(self.next_scan - input_end);
            self.pem.push(
                &bytes[..count],
                input_end,
                &mut self.pending,
                &mut self.warnings,
            );
            self.long_tokens.push(&bytes[..count], &mut self.warnings);
            self.bytes.extend_from_slice(&bytes[..count]);
            bytes = &bytes[count..];
            if input_end + count == self.next_scan {
                self.scan(false, &mut emit)?;
                self.next_scan += CHUNK_SIZE;
            }
        }
        Ok(())
    }

    pub fn finish(
        &mut self,
        mut emit: impl FnMut(&[u8], &[Span]) -> io::Result<()>,
    ) -> io::Result<()> {
        self.scan(true, &mut emit)
    }

    fn scan(
        &mut self,
        eof: bool,
        emit: &mut impl FnMut(&[u8], &[Span]) -> io::Result<()>,
    ) -> io::Result<()> {
        let end = self.base + self.bytes.len();
        let rule_frontier = if eof {
            end
        } else {
            end.saturating_sub(LOOKAHEAD)
        };
        let mut frontier = if eof {
            self.pem.finish(end, &mut self.pending, &mut self.warnings);
            end
        } else {
            self.pem.frontier(rule_frontier)
        };

        'rules: for (index, (rule, pattern)) in byte_rules().iter().enumerate() {
            let cursor = &mut self.cursors[index];
            let mut local = cursor.saturating_sub(self.base);
            if matches!(rule, Rule::Card) && self.card_continuation {
                local = skip_card_continuation(&self.bytes, local);
                *cursor = self.base + local;
                if !eof && card_at_window_end(&self.bytes, local) {
                    continue;
                }
                self.card_continuation = false;
            }
            if local < self.bytes.len() && enabled(*rule, &self.bytes[local..], self.us_phone) {
                while let Some(captures) = pattern.captures_at(&self.bytes, local) {
                    let matched = captures.get(0).unwrap();
                    if self.base + matched.start() >= rule_frontier {
                        break;
                    }
                    local = matched.end();
                    *cursor = self.base + local;
                    if matches!(rule, Rule::Phone) {
                        match phone_tail(&self.bytes, matched, eof) {
                            PhoneTail::Complete => {}
                            PhoneTail::Pending => {
                                // The next scan adds a full chunk, more than the phone-tail cap.
                                *cursor = self.base + matched.start();
                                frontier = frontier.min(*cursor);
                                continue 'rules;
                            }
                            PhoneTail::Oversized => {
                                warn(&mut self.warnings, FileLimitation::OversizedRuleCandidate);
                                continue;
                            }
                        }
                    }
                    if matches!(rule, Rule::Card) && !eof && card_at_window_end(&self.bytes, local)
                    {
                        self.card_continuation = true;
                    }
                    candidate(
                        *rule,
                        &self.bytes,
                        captures,
                        self.base,
                        &mut self.pending,
                        &mut self.warnings,
                    );
                }
            }
            *cursor = (*cursor).max(rule_frontier);
        }

        order(&mut self.pending);
        let mut spans = Vec::new();
        let mut consumed = 0;
        let mut oversized = Vec::new();
        while consumed < self.pending.len() {
            let remaining = &self.pending[consumed..];
            let start = remaining[0].1.start;
            let (count, end) = cluster_end(remaining);
            if end - start > MAX_OVERLAP_CLUSTER {
                warn(&mut self.warnings, FileLimitation::OversizedOverlapCluster);
                // Keep the union only. A later span can still extend the discarded cluster.
                if end > frontier {
                    add(&mut oversized, start, end, (0, "", ""));
                }
            } else if end > frontier {
                frontier = frontier.min(start);
                break;
            } else {
                spans.extend(resolve(remaining[..count].to_vec()));
            }
            consumed += count;
        }
        self.pending.drain(..consumed);
        self.pending.extend(oversized);

        if frontier > self.committed {
            let mut output = Vec::new();
            redact(
                &self.bytes[self.committed - self.base..frontier - self.base],
                self.committed,
                &spans,
                &mut output,
            )?;
            emit(&output, &spans)?;
            self.committed = frontier;
        }
        let retain = self
            .committed
            .min(rule_frontier)
            .saturating_sub(MAX_LEFT_CONTEXT);
        if retain > self.base {
            self.bytes.drain(..retain - self.base);
            self.base = retain;
        }
        Ok(())
    }
}

fn reference_pem(
    bytes: &[u8],
    candidates: &mut Vec<Candidate>,
    warnings: &mut Vec<FileLimitation>,
) {
    let mut opens = HashMap::<&[u8], usize>::new();
    let mut offset = 0;
    for line in bytes.split(|&byte| matches!(byte, b'\r' | b'\n')) {
        let end = offset + line.len();
        opens.retain(|_, start| {
            if end - *start > PEM_LIMIT {
                warn(warnings, FileLimitation::OversizedPemBlock);
                false
            } else {
                true
            }
        });
        if line.len() <= MAX_PEM_MARKER_LINE {
            if let Some(captures) = pem_pattern().captures(line) {
                let marker = captures.get(1).unwrap();
                let label = captures.get(3).unwrap().as_bytes();
                if &captures[2] == b"BEGIN" {
                    if opens.insert(label, offset + marker.start()).is_some() {
                        warn(warnings, FileLimitation::UnclosedPemBlock);
                    }
                } else if let Some(start) = opens.remove(label) {
                    add(candidates, start, offset + marker.end(), PEM);
                }
            }
        } else if starts_marker(line.trim_ascii_start()) {
            opens.clear();
            warn(warnings, FileLimitation::OversizedPemBlock);
        }
        offset = end + 1;
    }
    if !opens.is_empty() {
        warn(warnings, FileLimitation::UnclosedPemBlock);
    }
}

/// Unwindowed reference for tests and small inputs.
pub fn full_buffer(
    bytes: &[u8],
    options: &DetectOptions,
) -> (Vec<Span>, Vec<FileLimitation>, Vec<u8>) {
    let mut candidates = Vec::new();
    let mut warnings = Vec::new();
    LongTokenState::default().push(bytes, &mut warnings);
    reference_pem(bytes, &mut candidates, &mut warnings);
    for (rule, pattern) in byte_rules() {
        if enabled(*rule, bytes, us_phone(options)) {
            for captures in pattern.captures_iter(bytes) {
                if matches!(rule, Rule::Phone)
                    && matches!(
                        phone_tail(bytes, captures.get(0).unwrap(), true),
                        PhoneTail::Oversized
                    )
                {
                    warn(&mut warnings, FileLimitation::OversizedRuleCandidate);
                    continue;
                }
                candidate(*rule, bytes, captures, 0, &mut candidates, &mut warnings);
            }
        }
    }
    order(&mut candidates);
    let mut accepted = Vec::new();
    let mut remaining = candidates.as_slice();
    while !remaining.is_empty() {
        let (count, end) = cluster_end(remaining);
        if end - remaining[0].1.start <= MAX_OVERLAP_CLUSTER {
            accepted.extend_from_slice(&remaining[..count]);
        } else {
            warn(&mut warnings, FileLimitation::OversizedOverlapCluster);
        }
        remaining = &remaining[count..];
    }
    let spans = resolve(accepted);
    let mut output = Vec::new();
    redact(bytes, 0, &spans, &mut output).expect("writing to Vec cannot fail");
    (spans, warnings, output)
}
