import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { TextDecoder } from 'node:util';

const reasons = [
  'provider.aws_access_key_id',
  'provider.github_token',
  'provider.openai_api_key',
  'provider.anthropic_api_key',
  'provider.slack_token',
  'provider.stripe_key',
  'auth.jwt',
  'auth.bearer_token',
  'auth.basic_credentials',
  'connection.database_uri',
  'key.pem_private_key',
  'credential.field',
  'pii.email',
  'pii.payment_card',
  'pii.phone',
];
const suites = ['supported_provider', 'rules', 'mixed', 'canonical_negative', 'edge_cases'];
const coverageKinds = ['positive', 'near_miss', 'boundary'];
const read = (name) => readFileSync(new URL(name, import.meta.url));
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function validate() {
  const fixtures = JSON.parse(decoder.decode(read('corpus.json')));
  assert(Array.isArray(fixtures), 'corpus.json must contain an array');
  const ids = new Set();
  const coverage = new Set();
  const bySuite = new Map(suites.map((suite) => [suite, { fixtures: 0, spans: 0 }]));
  const byReason = new Map(reasons.map((reason) => [reason, { fixtures: 0, spans: 0 }]));
  let unicodeSpan = false;
  let boundedPem = false;
  let oversizedPem = false;

  for (const fixture of fixtures) {
    assert(fixture && typeof fixture === 'object', 'fixture must be an object');
    const { id, suite, kind, text, expected, category, options } = fixture;
    assert(typeof id === 'string' && /^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(id),
      'fixture ID must be a nonempty lowercase slug');
    assert(!ids.has(id), `${id}: duplicate ID`);
    ids.add(id);
    assert(bySuite.has(suite), `${id}: unknown suite`);
    assert(suite === 'canonical_negative' ? kind === 'negative' : coverageKinds.includes(kind),
      `${id}: invalid kind for suite`);
    assert(typeof text === 'string' && text.length > 0, `${id}: missing text`);
    assert(Array.isArray(expected), `${id}: expected must be an array`);
    if (options !== undefined) {
      assert(options && Array.isArray(options.phone_locales) &&
        options.phone_locales.length === 1 && options.phone_locales[0] === 'US',
      `${id}: expected phone locale US`);
    }
    if (kind === 'negative' || kind === 'near_miss') {
      assert.equal(expected.length, 0, `${id}: negative and near-miss fixtures must have no spans`);
    }
    if (kind === 'positive') assert(expected.length > 0, `${id}: positive fixture has no spans`);

    const suiteCounts = bySuite.get(suite);
    suiteCounts.fixtures++;
    suiteCounts.spans += expected.length;
    const bytes = Buffer.from(text, 'utf8');
    assert(decoder.decode(bytes) === text, `${id}: text contains an unpaired surrogate`);
    const isBoundary = (offset) => offset === bytes.length || (bytes[offset] & 0xc0) !== 0x80;
    let previousEnd = 0;
    const fixtureReasons = new Set();
    for (const span of expected) {
      assert(span && typeof span === 'object', `${id}: span must be an object`);
      const { start, end, reason_id, slice } = span;
      assert(byReason.has(reason_id), `${id}: unknown span reason`);
      assert(Number.isInteger(start) && Number.isInteger(end) &&
        start >= 0 && start < end && end <= bytes.length, `${id}: invalid span bounds`);
      assert(isBoundary(start) && isBoundary(end), `${id}: span splits a UTF-8 character`);
      assert(previousEnd <= start, `${id}: spans overlap or are out of order`);
      assert(bytes.subarray(start, end).toString('utf8') === slice, `${id}: span slice mismatch`);
      previousEnd = end;
      if (suite === 'edge_cases' && bytes.length > text.length && start > bytes.subarray(0, start).toString('utf8').length) {
        unicodeSpan = true;
      }
      if (reason_id === 'key.pem_private_key') {
        assert(end - start <= 16384, `${id}: expected PEM exceeds byte cap`);
        boundedPem ||= end - start === 16384;
      }
      byReason.get(reason_id).spans++;
      fixtureReasons.add(reason_id);
    }

    if (suite === 'supported_provider' || suite === 'rules') {
      assert(byReason.has(category), `${id}: missing or unknown category`);
      assert(category.startsWith('provider.') === (suite === 'supported_provider'),
        `${id}: category does not belong to suite`);
      assert(expected.every((span) => span.reason_id === category),
        `${id}: span does not match the fixture category`);
      if (kind === 'boundary' && category === 'key.pem_private_key' &&
          bytes.length > 16384 && expected.length === 0) {
        assert(text.startsWith('-----BEGIN PRIVATE KEY-----\n') &&
          text.endsWith('\n-----END PRIVATE KEY-----'), `${id}: oversized PEM must be a complete block`);
        oversizedPem = true;
      }
      coverage.add(`${category}/${kind}`);
      fixtureReasons.add(category);
    } else {
      assert(category === undefined, `${id}: unexpected category`);
    }
    for (const reason of fixtureReasons) byReason.get(reason).fixtures++;
  }

  for (const [suite, counts] of bySuite) assert(counts.fixtures > 0, `${suite}: no fixtures`);
  for (const reason of reasons) {
    for (const kind of coverageKinds) {
      assert(coverage.has(`${reason}/${kind}`), `${reason}: missing ${kind} fixture`);
    }
  }
  assert(unicodeSpan, 'edge_cases must include a span whose UTF-8 offset differs from its UTF-16 index');
  assert(boundedPem && oversizedPem, 'corpus must exercise both the exact PEM cap and an oversized block');

  const bench = read('bench_100kib.txt');
  assert.equal(bench.length, 102400, 'benchmark must be exactly 100 KiB');
  assert(bench.length > decoder.decode(bench).length, 'benchmark must contain multibyte text');

  console.log(`Validated ${fixtures.length} fixtures and ${[...bySuite.values()].reduce((total, row) => total + row.spans, 0)} spans. Benchmark: ${bench.length} UTF-8 bytes.`);
  console.table(Object.fromEntries(bySuite));
  console.table(Object.fromEntries(byReason));
}

try {
  validate();
} catch (error) {
  console.error(`Corpus validation failed: ${error.message}`);
  process.exitCode = 1;
}
