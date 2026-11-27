# Week 1 synthetic detector corpus

The labels were assigned from the written detection contract before running
any detector. All credentials and personal data are fabricated. Domains use
reserved examples, phone numbers use reserved fictional 555-01xx ranges,
the payment number is a sandbox test card, and private key material and JWT
signatures are fake. The benchmark is exactly 102,400 UTF-8 bytes and repeats
fictional support tickets, logs, and configuration with a final archive footer.

## Fixture format

`corpus.json` is an array of fixtures with a unique `id`, a `suite`, a
`kind`, literal input `text`, and an ordered `expected` array. Each expected
match has integer `start` and `end` byte offsets, a `reason_id`, and the
literal string `slice` for checking those offsets.

- `suite` is `supported_provider`, `rules`, `mixed`, `canonical_negative`,
  or `edge_cases`.
- `kind` is `positive`, `near_miss`, or `boundary`. Canonical negatives
  always use `negative`. Near misses and canonical negatives have empty
  expectations. Boundary fixtures can match or be empty.
- `category` is required in `supported_provider` and `rules`. It names the
  rule exercised even when that fixture expects zero matches.
- The optional `options.phone_locales` array passes locale opt-ins to the
  detector. The corpus uses `["US"]` for the unlabeled US phone positive.
  Fixtures without options use default detection.

## Spans and stable reason IDs

All ranges are half-open UTF-8 byte offsets `[start, end)` on character
boundaries, with `0 <= start < end <= utf8_byte_len`. Matches are sorted by
start and disjoint. Adjacent spans are valid. Whitespace or punctuation
outside the matched entity stays outside the range.

This table is in descending overlap priority. IDs on the same row share
priority. For equal-priority candidates, sort by earlier start, then longer
span, then lexicographically smaller reason ID. Keep an entire winning span
and discard any lower-ranked candidate that overlaps it.

| Stable reason IDs | Span |
| --- | --- |
| `key.pem_private_key` | Full block from the opening delimiter through the closing delimiter, with matching PRIVATE KEY labels. Trailing line endings after the closing delimiter are outside the span. |
| `connection.database_uri` | Entire credential-bearing URI, including scheme, userinfo, host, and any remaining URI components. |
| `provider.aws_access_key_id`, `provider.github_token`, `provider.openai_api_key`, `provider.anthropic_api_key`, `provider.slack_token`, `provider.stripe_key` | Provider credential only. |
| `auth.jwt` | Complete JWT including its dot separators. |
| `auth.bearer_token`, `auth.basic_credentials` | Credential token immediately after the scheme and space in an authorization context. The authorization and scheme prefixes remain visible. |
| `credential.field` | Value only, excluding the key, delimiter, adjacent whitespace, and surrounding quotes. |
| `pii.payment_card` | Number including internal separators, when it passes Luhn and has payment context. |
| `pii.email` | Email address only. |
| `pii.phone` | Number including its formatting, excluding phone labels and surrounding whitespace. |

A provider credential or JWT inside an authorization header or credential
field takes priority over the generic token or value. A provider credential
inside a credential-bearing database URI belongs to the full URI match.
For Week 1, a complete PEM block is eligible through **16,384 UTF-8 bytes**
(16 KiB), inclusive. The 16,385-byte fixture expects zero emitted spans.
Any separate oversized-block diagnostic is outside corpus scoring.

## Validation and scoring

Run the independent label validator from the repository root.

```sh
node fixtures/corpus/validate_corpus.mjs
```

Once the Rust corpus scorer is wired into the test suite, run it with:

```sh
cargo test --manifest-path src-tauri/Cargo.toml --locked
```

Compare final detector matches after overlap resolution to the expected
`(start, end, reason_id)` tuples for each fixture. Each expectation can be
credited once. Precision is exact true positives divided by all emitted
matches across the corpus and must be at least **99%**. Supported-provider
detection is exact matches for expected spans in the `supported_provider`
suite divided by its expected span count and must be **100%**. The total
number of emitted matches in `canonical_negative` must be **zero**.
