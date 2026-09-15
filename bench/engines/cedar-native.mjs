// Cedar as a linked-in Rust library, via `bench/native/cedar`.
//
// `cedar.mjs` measures Cedar through `@cedar-policy/cedar-wasm`. That row is
// honest about what it is -- a Node host's cost -- but `bench/README.md` and
// `docs/proposals/benchmark-harness.md` both carried the same caveat: the
// wasm-bindgen boundary dominates it, so it is not a measurement of Cedar's
// evaluator. This engine is the caveat turned into a number.
//
// The timing does not happen here. `bench/run.mjs` times `decide()` inside the
// Node process, and driving a Rust child process from there would put a pipe
// round trip -- tens of microseconds -- inside the timed path, swamping
// everything being compared. So the Rust program measures itself, with the
// same budget, the same clock-read floor subtraction and the same best-of-N
// throughput windows, and this module reports what it found. That is what the
// `measure()` export is: an engine that cannot be timed from this process
// supplying its own row.
//
// Opt-in, and deliberately so. Building the harness pulls ~100 crates and
// takes a minute or two cold, which is not something every `zig build bench`
// should do. Name it explicitly:
//
//     zig build bench -- --engines=zopa,zopa-compiled,cedar,cedar-native
//     ZOPA_BENCH_CEDAR_NATIVE=1 zig build bench
//
// Nothing about the wasm module depends on this. It is a benchmark harness in
// a second language for one row, which is exactly the cost the proposal said
// it would be.

import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const id = 'cedar-native';
export const label = 'Cedar (native Rust)';

const HERE = dirname(fileURLToPath(import.meta.url));
const CRATE = join(HERE, '..', 'native', 'cedar');
const BINARY = join(CRATE, 'target', 'release', 'zopa-bench-cedar');
const FIXTURES = join(HERE, '..', 'fixtures');

function cargoVersion() {
  try {
    return execFileSync('cargo', ['--version'], { encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

// The pinned cedar-policy version comes from Cargo.lock rather than from the
// program, because Cargo.lock is what actually pins the build. A constant
// compiled into the binary would be a claim nothing checks.
function cedarVersion() {
  try {
    const lock = readFileSync(join(CRATE, 'Cargo.lock'), 'utf8');
    const m = lock.match(/name = "cedar-policy"\nversion = "([^"]+)"/);
    return m ? m[1] : 'unknown';
  } catch {
    return 'unknown';
  }
}

function requested(opts) {
  return Boolean(opts?.engines?.includes(id)) || process.env.ZOPA_BENCH_CEDAR_NATIVE === '1';
}

export async function available(opts) {
  if (!requested(opts)) {
    return {
      ok: false,
      reason: `opt-in only (--engines=...,${id} or ZOPA_BENCH_CEDAR_NATIVE=1); building it pulls ~100 crates`,
    };
  }
  const cargo = cargoVersion();
  if (!cargo && !existsSync(BINARY)) {
    return { ok: false, reason: 'cargo not on PATH and no prebuilt harness in bench/native/cedar/target' };
  }
  return { ok: true, note: `cedar-policy ${cedarVersion()}${cargo ? `, ${cargo}` : ', prebuilt'}` };
}

export function supports(fixture) {
  return typeof fixture.cedar === 'string' && fixture.cedar.length > 0;
}

// One run of the Rust program covers every fixture, so it is run once and the
// rows are held here. Running it per fixture would pay the process spawn and
// the warm-up N times over for the same numbers.
let pending = null;

function build() {
  if (existsSync(BINARY)) return;
  process.stderr.write('  cedar-native: building bench/native/cedar (first run, ~1-2 min)...\n');
  execFileSync('cargo', ['build', '--release'], { cwd: CRATE, stdio: ['ignore', 'ignore', 'inherit'] });
}

function runHarness(budget) {
  build();
  const out = execFileSync(
    BINARY,
    [
      '--fixtures', FIXTURES,
      '--warmup', String(budget.warmup),
      '--iters', String(budget.iters),
      '--throughput-ms', String(budget.throughputMs),
      '--throughput-runs', String(budget.throughputRuns),
    ],
    { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 },
  );
  const parsed = JSON.parse(out);
  const byName = new Map();
  for (const row of parsed.fixtures) byName.set(row.name, row);
  return byName;
}

function rows(budget) {
  // The budget is fixed for a whole `run.mjs` invocation, so caching the first
  // result cannot serve numbers measured under a different one.
  if (pending === null) pending = runHarness(budget);
  return pending;
}

function rowFor(fixture, budget) {
  const row = rows(budget).get(fixture.name);
  if (!row) throw new Error(`the native harness reported nothing for ${fixture.name}`);
  return row;
}

export async function setup(fixture, opts) {
  // `opts.budget` is set by run.mjs once it has resolved --quick. Falling back
  // would measure under a budget nothing asked for, so this refuses instead.
  const budget = opts?.budget;
  if (!budget) throw new Error('cedar-native needs opts.budget from run.mjs');
  const row = rowFor(fixture, budget);
  return {
    // The decision the Rust program computed for this fixture, for the
    // agreement gate. It is a real Cedar decision over the fixture's own
    // policy and input -- the gate is checking Cedar against zopa, and that
    // is what this is.
    decide() {
      return row.decision;
    },
    memoryBytes() {
      return null;
    },
    close() {},
  };
}

// An engine that cannot be timed from this process reports its own row.
// run.mjs uses this in place of its latency/throughput/cold-start loops.
export async function measure(fixture, budget) {
  const row = rowFor(fixture, budget);
  return {
    p50: row.p50,
    p95: row.p95,
    p99: row.p99,
    mean: row.mean,
    opsPerSec: row.opsPerSec,
    amortizedMicros: row.amortizedMicros,
    coldStartMs: row.coldStartMs,
    // No linear memory to read, and process RSS would measure the harness.
    memoryBytes: null,
    // A statically linked Rust binary is not comparable to a wasm module you
    // ship to a proxy, and reporting its size next to one would invite exactly
    // that comparison.
    artifactBytes: null,
    // The evaluator with the request already built: no JSON parse, no context
    // conversion. The difference between this and `amortizedMicros` is what
    // Cedar spends turning a request into its own value types, which is the
    // part the wasm binding's number cannot separate out.
    evalOnlyMicros: row.evalOnly?.amortizedMicros ?? null,
  };
}
