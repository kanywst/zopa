// Compare a benchmark run against the committed baseline.
//
// The numbers a shared CI runner produces are not publishable -- that
// is said plainly in bench/README.md and it is still true. What they
// are good for is catching a change that makes evaluation dramatically
// slower, which is invisible in a test suite and easy to ship.
//
// So the baseline is stored and compared as *ratios between engines on
// the same run*, never as absolute microseconds. A runner that happens
// to be twice as slow today scales every engine equally and the ratios
// hold; a change that doubles zopa's cost moves them. That is the only
// comparison across machines this data can honestly support.
//
//   node bench/compare.mjs <run.json> [baseline.json]
//
// Exits non-zero if any tracked ratio has regressed past the threshold.

import { readFileSync } from 'node:fs';
import { argv, exit } from 'node:process';

// A wide gate on purpose. Runner variance on a 0.1 us measurement is
// large, and a regression check that cries wolf gets ignored, which is
// worse than not having one. This is sized to catch "someone
// reintroduced a per-request policy parse", not a 5% drift.
const THRESHOLD = 1.5;

// zopa-compiled is the reference: it is the path a real deployment
// uses, and expressing everything against it means the baseline says
// "how does the rest of the world compare to us" rather than storing
// machine-specific microseconds.
const REFERENCE = 'zopa-compiled';

function ratios(run) {
  const out = {};
  const byFixture = new Map();
  for (const r of run.results) {
    if (!byFixture.has(r.fixture)) byFixture.set(r.fixture, new Map());
    byFixture.get(r.fixture).set(r.engine, r.amortizedMicros);
  }
  for (const [fixture, engines] of byFixture) {
    const ref = engines.get(REFERENCE);
    // Finite and positive. `Infinity` is a real result row rather than a
    // skipped engine -- it is what a `throughput()` window that counted
    // zero iterations produces -- and `Infinity > 0` would sail through
    // a bare positivity check, leaving every other engine's ratio 0.
    if (!Number.isFinite(ref) || ref <= 0) continue;
    for (const [engine, cost] of engines) {
      if (engine === REFERENCE) continue;
      if (!Number.isFinite(cost)) continue;
      out[`${fixture}/${engine}`] = cost / ref;
    }
  }
  return out;
}

const run = JSON.parse(readFileSync(argv[2], 'utf8'));
const current = ratios(run);

// Both branches need this, not just the compare one. Seeding from a run
// where `zopa-compiled` did not build would emit a valid-looking
// baseline with an empty `ratios` object and exit 0 -- a document with
// its teeth removed, which the next CI run would report as "nothing was
// compared" long after the cause. Same fail-open shape, other branch.
if (!run.engines.includes(REFERENCE)) {
  console.error(
    `${REFERENCE} did not run, so there is nothing to compare against.\n`
    + `engines in this run: ${run.engines.join(', ') || '(none)'}`,
  );
  exit(1);
}

if (argv[3] === undefined) {
  // No baseline: emit one. Used to seed bench/results/baseline.json.
  if (Object.keys(current).length === 0) {
    console.error(
      `${REFERENCE} ran but produced no comparable cost on any fixture; refusing to seed an empty baseline.`,
    );
    exit(1);
  }
  console.log(JSON.stringify({
    note: `Ratio of each engine's amortised cost to ${REFERENCE} on the same run. `
        + 'Absolute microseconds are deliberately not stored: they are machine-specific '
        + 'and a CI runner cannot measure them meaningfully. Ratios survive a slow runner.',
    reference: REFERENCE,
    threshold: THRESHOLD,
    generated: run.generated,
    ratios: current,
  }, null, 2));
  exit(0);
}

const baseline = JSON.parse(readFileSync(argv[3], 'utf8'));

// The stored threshold wins, so re-seeding with a different one takes
// effect rather than sitting in the file looking authoritative while
// the constant below decides.
const threshold = typeof baseline.threshold === 'number' ? baseline.threshold : THRESHOLD;

let failures = 0;
let compared = 0;

console.log(`ratio of each engine to ${REFERENCE}, current vs baseline (gate: ${threshold}x)\n`);
console.log(`${'fixture/engine'.padEnd(30)}| baseline |  current | change`);
console.log(`${'-'.repeat(30)}+----------+----------+-------`);

for (const [key, was] of Object.entries(baseline.ratios)) {
  const now = current[key];
  if (now === undefined) {
    // An engine that was skipped this run is not a regression; a
    // silently missing row would be, so say it.
    console.log(`${key.padEnd(30)}| ${was.toFixed(2).padStart(8)} |  (absent) | skipped`);
    continue;
  }
  compared++;
  // The ratio is other/zopa. It getting *smaller* means zopa lost
  // ground relative to that engine, which is the regression this
  // watches for.
  const change = was / now;
  const bad = change > threshold;
  if (bad) failures++;
  console.log(
    `${key.padEnd(30)}| ${was.toFixed(2).padStart(8)} | ${now.toFixed(2).padStart(8)} | ${
      bad ? `REGRESSED ${change.toFixed(2)}x` : `${change.toFixed(2)}x`}`,
  );
}

console.log(`\n${compared} ratio(s) compared`);

// Every ratio going missing while the reference engine did run means
// the fixture set or the engine list moved out from under the baseline.
// Re-seed deliberately; do not let it pass silently.
if (compared === 0) {
  console.error(
    '\nnothing was compared: the baseline and this run share no fixture/engine pair.\n'
    + 'Re-seed the baseline if that is intended:\n'
    + '  zig build bench -- --json=run.json && node bench/compare.mjs run.json > bench/results/baseline.json',
  );
  exit(1);
}

if (failures > 0) {
  console.error(
    `\n${failures} regression(s): zopa lost more than ${threshold}x of ground against another engine.\n`
    + 'If this is intended, re-seed the baseline:\n'
    + '  zig build bench -- --json=run.json && node bench/compare.mjs run.json > bench/results/baseline.json',
  );
  exit(1);
}
console.log('no regression');
