// Exit-code contract for bench/compare.mjs.
//
// compare.mjs is a hard CI gate, and every behaviour it promises was
// asserted only by the comment next to it. The fail-open bug it exists
// to avoid -- reporting success having compared nothing -- is exactly
// the kind a later edit reintroduces silently, so the contract is
// pinned here rather than in prose.
//
//   node --test bench/compare.test.mjs

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const COMPARE = join(HERE, 'compare.mjs');

const dir = mkdtempSync(join(tmpdir(), 'zopa-compare-test-'));
process.on('exit', () => rmSync(dir, { recursive: true, force: true }));

let seq = 0;
function tmpJson(value) {
  const path = join(dir, `f${seq++}.json`);
  writeFileSync(path, JSON.stringify(value));
  return path;
}

/** Run compare.mjs, returning { code, stdout, stderr } rather than throwing. */
function compare(...args) {
  try {
    const stdout = execFileSync('node', [COMPARE, ...args], { encoding: 'utf8', stdio: 'pipe' });
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    return { code: err.status, stdout: err.stdout ?? '', stderr: err.stderr ?? '' };
  }
}

const run = (results, engines) => tmpJson({
  generated: '2026-01-01T00:00:00Z',
  engines: engines ?? [...new Set(results.map((r) => r.engine))],
  results,
});

const rows = (compiled, other, fixture = 'f1') => [
  { fixture, engine: 'zopa-compiled', amortizedMicros: compiled },
  { fixture, engine: 'opa-wasm', amortizedMicros: other },
];

test('emits a baseline when given no baseline to compare against', () => {
  const r = compare(run(rows(1, 4)));
  assert.equal(r.code, 0);
  const emitted = JSON.parse(r.stdout);
  assert.equal(emitted.reference, 'zopa-compiled');
  assert.equal(emitted.ratios['f1/opa-wasm'], 4);
});

test('passes when the ratio is unchanged', () => {
  const baseline = compare(run(rows(1, 4))).stdout;
  const r = compare(run(rows(2, 8)), tmpJson(JSON.parse(baseline)));
  assert.equal(r.code, 0, r.stderr);
  assert.match(r.stdout, /no regression/);
});

test('fails when zopa loses ground past the threshold', () => {
  const baseline = JSON.parse(compare(run(rows(1, 4))).stdout);
  // Same rival cost, zopa four times slower: the ratio collapses 4x.
  const r = compare(run(rows(4, 4)), tmpJson(baseline));
  assert.equal(r.code, 1);
  assert.match(r.stdout, /REGRESSED/);
});

test('does not fire when zopa gets faster', () => {
  const baseline = JSON.parse(compare(run(rows(1, 4))).stdout);
  const r = compare(run(rows(0.5, 4)), tmpJson(baseline));
  assert.equal(r.code, 0, r.stderr);
});

test('fails closed when the reference engine did not run', () => {
  const baseline = JSON.parse(compare(run(rows(1, 4))).stdout);
  const without = run(
    [{ fixture: 'f1', engine: 'opa-wasm', amortizedMicros: 4 }],
    ['zopa', 'opa-wasm'],
  );
  const r = compare(without, tmpJson(baseline));
  assert.equal(r.code, 1, 'a run without the reference engine must not report success');
  assert.match(r.stderr, /did not run/);
});

test('fails closed when nothing in the baseline overlaps the run', () => {
  const baseline = JSON.parse(compare(run(rows(1, 4))).stdout);
  const r = compare(run(rows(1, 4, 'a-different-fixture')), tmpJson(baseline));
  assert.equal(r.code, 1, 'comparing zero pairs must not report success');
  assert.match(r.stderr, /nothing was compared/);
});

test('honours the threshold stored in the baseline', () => {
  const baseline = JSON.parse(compare(run(rows(1, 4))).stdout);
  // A 1.2x loss passes the default 1.5x gate and fails a stored 1.1x.
  const slightlyWorse = run(rows(1.2, 4));
  assert.equal(compare(slightlyWorse, tmpJson(baseline)).code, 0);

  const tight = compare(slightlyWorse, tmpJson({ ...baseline, threshold: 1.1 }));
  assert.equal(tight.code, 1);
  assert.match(tight.stdout, /gate: 1\.1x/);
});

test('ignores a fixture whose reference cost is not finite', () => {
  // An engine that counted zero iterations reports Infinity. That is a
  // result row, not a skipped engine, and `Infinity > 0` would pass a
  // bare positivity check while making every other ratio 0.
  const r = compare(run([
    ...rows(Infinity, 4, 'stalled'),
    ...rows(1, 4, 'healthy'),
  ]));
  const emitted = JSON.parse(r.stdout);
  assert.deepEqual(Object.keys(emitted.ratios), ['healthy/opa-wasm']);
});
