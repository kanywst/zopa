// Cross-engine benchmark: zopa against the two shapes it is meant to
// replace -- OPA compiled to wasm and loaded in-process, and OPA run as
// an out-of-process sidecar over HTTP.
//
// The rule this harness is built around: no engine is timed until every
// engine has been shown to return the same decision for the fixture. A
// latency number for an engine that answers differently is not a
// comparison, it is two unrelated measurements printed next to each
// other. Disagreement is a hard failure, not a footnote.
//
// Engines whose dependencies are missing are skipped and named, so
// `zig build bench` still does something useful with no `opa` on PATH.

import { readFileSync, readdirSync, mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import * as zopa from './engines/zopa.mjs';
import * as zopaCompiled from './engines/zopa-compiled.mjs';
import * as opaWasm from './engines/opa-wasm.mjs';
import * as opaHttp from './engines/opa-http.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const ALL_ENGINES = [zopa, zopaCompiled, opaWasm, opaHttp];

// ---------------------------------------------------------------- args

function parseArgs(argv) {
  const opts = {
    wasmPath: join(HERE, '..', 'zig-out', 'bin', 'zopa.wasm'),
    engines: null,
    quick: false,
    json: null,
  };
  for (const arg of argv) {
    if (arg === '--quick') opts.quick = true;
    else if (arg.startsWith('--engines=')) opts.engines = arg.slice(10).split(',').filter(Boolean);
    else if (arg.startsWith('--json=')) opts.json = arg.slice(7);
    else if (arg.startsWith('--')) throw new Error(`unknown flag: ${arg}`);
    // A bare path keeps the pre-existing `node bench/run.mjs <wasm>` form working.
    else opts.wasmPath = arg;
  }
  return opts;
}

const opts = parseArgs(process.argv.slice(2));

// Quick mode exists for the CI smoke job: it proves every engine still
// agrees and still runs, without spending minutes to sharpen a p99 that
// a shared runner cannot measure meaningfully anyway.
const BUDGET = opts.quick
  ? { warmup: 50, iters: 300, throughputMs: 100 }
  : { warmup: 1000, iters: 10_000, throughputMs: 1000 };

// -------------------------------------------------------------- stats

function percentile(sorted, p) {
  const idx = Math.min(sorted.length - 1, Math.floor(sorted.length * p));
  return sorted[idx];
}

function summarise(samples) {
  const sorted = Float64Array.from(samples).sort();
  return {
    p50: percentile(sorted, 0.50),
    p95: percentile(sorted, 0.95),
    p99: percentile(sorted, 0.99),
    mean: sorted.reduce((s, x) => s + x, 0) / sorted.length,
  };
}

const micros = (t0, t1) => Number(t1 - t0) / 1000;

// A zopa decision on a trivial policy takes about as long as reading
// the clock twice, so an uncorrected per-iteration sample is mostly
// timer. Measure that floor once and subtract it, or the fast engines
// get charged for the instrument. The throughput figure, which times a
// whole loop rather than each pass, is the cross-check: before this
// correction the two disagreed by 3x on 01_static.
function timerFloorMicros() {
  const probes = new Float64Array(2000);
  for (let k = 0; k < probes.length; k++) {
    const t0 = process.hrtime.bigint();
    probes[k] = micros(t0, process.hrtime.bigint());
  }
  probes.sort();
  return probes[Math.floor(probes.length / 2)];
}

const TIMER_FLOOR = timerFloorMicros();
const corrected = (x) => Math.max(0, x - TIMER_FLOOR);

// ------------------------------------------------------- measurements

async function latency(engine, mod) {
  const samples = new Float64Array(BUDGET.iters);
  if (mod.isAsync) {
    for (let k = 0; k < BUDGET.iters; k++) {
      const t0 = process.hrtime.bigint();
      await engine.decide();
      samples[k] = corrected(micros(t0, process.hrtime.bigint()));
    }
  } else {
    for (let k = 0; k < BUDGET.iters; k++) {
      const t0 = process.hrtime.bigint();
      engine.decide();
      samples[k] = corrected(micros(t0, process.hrtime.bigint()));
    }
  }
  return summarise(samples);
}

// Saturation for a single caller: how many sequential decisions fit in
// the window. For the in-process engines that is a CPU-bound loop; for
// the sidecar it is bounded by the round trip, which is the point.
async function throughput(engine, mod) {
  const deadline = process.hrtime.bigint() + BigInt(BUDGET.throughputMs) * 1_000_000n;
  let n = 0;
  if (mod.isAsync) {
    while (process.hrtime.bigint() < deadline) { await engine.decide(); n++; }
  } else {
    while (process.hrtime.bigint() < deadline) { engine.decide(); n++; }
  }
  return (n * 1000) / BUDGET.throughputMs;
}

// Cold start is a fresh setup plus the first decision: for wasm that is
// instantiate + first eval, for the sidecar it is process spawn +
// becoming ready + first request. Reported in milliseconds because the
// three differ by orders of magnitude.
async function coldStart(mod, fixture) {
  const t0 = process.hrtime.bigint();
  const engine = await mod.setup(fixture, opts);
  await engine.decide();
  const ms = micros(t0, process.hrtime.bigint()) / 1000;
  engine.close();
  return ms;
}

// ------------------------------------------------------------- driver

const fixtures = readdirSync(join(HERE, 'fixtures'))
  .filter((f) => f.endsWith('.json'))
  .sort()
  .map((f) => JSON.parse(readFileSync(join(HERE, 'fixtures', f), 'utf8')));

const selected = opts.engines
  ? ALL_ENGINES.filter((m) => opts.engines.includes(m.id))
  : ALL_ENGINES;
if (opts.engines) {
  const unknown = opts.engines.filter((e) => !ALL_ENGINES.some((m) => m.id === e));
  if (unknown.length) throw new Error(`unknown engine(s): ${unknown.join(', ')}`);
}

const live = [];
for (const mod of selected) {
  const check = await mod.available(opts);
  if (check.ok) {
    live.push(mod);
    console.log(`engine ${mod.id}: ready${check.note ? ` (${check.note})` : ''}`);
  } else {
    console.log(`engine ${mod.id}: SKIPPED -- ${check.reason}`);
  }
}
if (!live.some((m) => m.id === zopa.id)) {
  console.error('zopa itself is unavailable; nothing to benchmark');
  process.exit(1);
}

const results = [];
let disagreements = 0;

for (const fixture of fixtures) {
  const runnable = live.filter((m) => m.supports(fixture));
  const engines = [];
  for (const mod of runnable) {
    try {
      engines.push({ mod, inst: await mod.setup(fixture, opts) });
    } catch (err) {
      console.error(`  ${fixture.name} / ${mod.id}: setup failed -- ${err.message}`);
      process.exitCode = 1;
    }
  }

  // Agreement gate. zopa is the reference only because it is the
  // subject; a mismatch means the fixture's AST and its Rego have
  // drifted apart, and neither number below would mean anything.
  const decisions = new Map();
  for (const { mod, inst } of engines) decisions.set(mod.id, await inst.decide());
  const reference = decisions.get(zopa.id);
  for (const [engineId, decision] of decisions) {
    if (decision !== reference) {
      console.error(
        `  ${fixture.name}: DISAGREEMENT -- zopa says ${reference}, ${engineId} says ${decision}`,
      );
      disagreements++;
    }
  }
  if (reference === -1) {
    console.error(`  ${fixture.name}: zopa returned -1 (error); refusing to time an error path`);
    disagreements++;
  }

  if (disagreements === 0) {
    for (const { mod, inst } of engines) {
      for (let k = 0; k < BUDGET.warmup; k++) await inst.decide();
      const opsPerSec = await throughput(inst, mod);
      results.push({
        fixture: fixture.name,
        engine: mod.id,
        label: mod.label,
        decision: decisions.get(mod.id),
        ...(await latency(inst, mod)),
        opsPerSec,
        // Per-decision cost with no instrumentation in the loop at all.
        // On engines answering in well under a microsecond this is the
        // number to trust; the percentiles beside it still carry the
        // tail shape, which a loop total cannot show.
        amortizedMicros: 1e6 / opsPerSec,
        memoryBytes: (await inst.memoryBytes?.()) ?? null,
        artifactBytes: inst.artifactBytes?.() ?? null,
        coldStartMs: await coldStart(mod, fixture),
      });
    }
  }

  for (const { inst } of engines) inst.close();
}

// ------------------------------------------------------------- report

if (disagreements > 0) {
  console.error(`\n${disagreements} disagreement(s); no timings reported`);
  process.exit(1);
}

const engineIds = [...new Set(results.map((r) => r.engine))];
const pad = (s, n) => String(s).padEnd(n);
const num = (x, n, d = 2) => (x === null ? '-'.padStart(n) : x.toFixed(d).padStart(n));
const kib = (b, n) => (b === null ? '-'.padStart(n) : (b / 1024).toFixed(0).padStart(n));

console.log(`\nlatency per decision, microseconds (${BUDGET.iters} iterations after ${BUDGET.warmup} warm-up,`);
console.log(`minus a ${TIMER_FLOOR.toFixed(2)} us clock-read floor; every engine agreed on every decision shown)\n`);
console.log(`${pad('fixture', 16)}| ${pad('engine', 14)}| dec |    p50 |    p95 |    p99 |  amort`);
console.log(`${'-'.repeat(16)}+${'-'.repeat(15)}+-----+--------+--------+--------+-------`);
for (const r of results) {
  console.log(
    `${pad(r.fixture, 16)}| ${pad(r.engine, 14)}|${String(r.decision).padStart(4)} |${num(r.p50, 7)} |${num(r.p95, 7)} |${num(r.p99, 7)} |${num(r.amortizedMicros, 7)}`,
  );
}
console.log('\n`amort` is the uninstrumented per-decision cost (1s loop / count). Where it sits');
console.log('well below p50, the clock reads around each iteration are most of what p50 measured;');
console.log('trust amort for the level and the percentiles for the shape of the tail.');

console.log('\nper engine: throughput (single sequential caller), memory after warm-up, cold start\n');
console.log(`${pad('fixture', 16)}| ${pad('engine', 14)}|      ops/s | mem KiB | artifact KiB | cold ms`);
console.log(`${'-'.repeat(16)}+${'-'.repeat(15)}+------------+---------+--------------+--------`);
for (const r of results) {
  console.log(
    `${pad(r.fixture, 16)}| ${pad(r.engine, 14)}|${num(r.opsPerSec, 11, 0)} |${kib(r.memoryBytes, 8)} |${kib(r.artifactBytes, 13)} |${num(r.coldStartMs, 8, 2)}`,
  );
}

if (engineIds.length === 1) {
  console.log(`\nOnly ${engineIds[0]} ran. Install the \`opa\` CLI to get the comparison this harness exists for.`);
}

if (opts.json) {
  mkdirSync(dirname(opts.json), { recursive: true });
  writeFileSync(opts.json, `${JSON.stringify({
    generated: new Date().toISOString(),
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    budget: BUDGET,
    engines: engineIds,
    results,
  }, null, 2)}\n`);
  console.log(`\nwrote ${opts.json}`);
}
