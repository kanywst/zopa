//! Cedar measured natively, as `docs/proposals/benchmark-harness.md` asked for.
//!
//! `bench/engines/cedar.mjs` measures Cedar through `@cedar-policy/cedar-wasm`,
//! where the wasm-bindgen boundary dominates: every decision serialises
//! principal, action, resource, context and entities into the module and
//! deserialises an answer back out. That number is real -- it is what a Node
//! host pays -- but it is not Cedar's evaluator, and the benchmark said so in
//! a caveat rather than measuring the alternative. This is the alternative.
//!
//! Why a separate binary rather than an engine module like the others: the
//! harness in `bench/run.mjs` times `decide()` inside the Node process. Driving
//! a Rust process from there would put a pipe round trip -- tens of
//! microseconds -- inside the timed path, which is larger than everything being
//! compared. So this program does its own timing and reports the distribution;
//! `bench/engines/cedar-native.mjs` runs it once and hands the numbers back.
//! The agreement gate still calls `decide()` across the pipe, because
//! correctness has no deadline.
//!
//! Timing mirrors `run.mjs` exactly so the rows are comparable: the same
//! warm-up, the same iteration count, a measured clock-read floor subtracted
//! from every sample, and throughput as the best of several short windows
//! rather than one long one.
//!
//!     zopa-bench-cedar --fixtures <dir> --warmup N --iters N \
//!                      --throughput-ms N --throughput-runs N
//!
//! Writes one JSON object to stdout. Everything else goes to stderr.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use serde_json::{json, Value};

/// The same placeholder triple `bench/engines/cedar.mjs` uses. The fixtures'
/// Cedar policies read `context.*` where their Rego reads `input.*`, so
/// nothing depends on entity data and no schema or entity store is needed.
const PRINCIPAL: &str = r#"User::"alice""#;
const ACTION: &str = r#"Action::"access""#;
const RESOURCE: &str = r#"Resource::"r""#;

struct Budget {
    warmup: usize,
    iters: usize,
    throughput_ms: u64,
    throughput_runs: u32,
}

fn main() -> ExitCode {
    match run() {
        Ok(out) => {
            println!("{out}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("zopa-bench-cedar: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<String, String> {
    let (dir, budget) = parse_args()?;

    // A measured floor, not an assumed one: `Instant::now()` is not free, and
    // on a decision costing a microsecond the reads around it are a
    // meaningful share of the sample. run.mjs subtracts the same way.
    let floor = timer_floor_micros();

    let mut fixtures: Vec<PathBuf> = fs::read_dir(&dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    fixtures.sort();

    let mut rows = Vec::new();
    for path in &fixtures {
        if let Some(row) = measure_fixture(path, &budget, floor)? {
            rows.push(row);
        }
    }

    // The cedar-policy version is not reported from here: the crate exposes no
    // version constant, and hardcoding one would be a claim this program
    // cannot check. `cedar-native.mjs` reads it out of Cargo.lock, which is
    // what actually pins the build.
    Ok(json!({
        "timerFloorMicros": floor,
        "fixtures": rows,
    })
    .to_string())
}

fn parse_args() -> Result<(PathBuf, Budget), String> {
    let mut dir = None;
    let mut budget = Budget {
        warmup: 1000,
        iters: 10_000,
        throughput_ms: 1500,
        throughput_runs: 5,
    };

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        let need = |i: usize| -> Result<&String, String> {
            args.get(i + 1)
                .ok_or_else(|| format!("{} needs a value", args[i]))
        };
        let parse = |v: &String, flag: &str| -> Result<u64, String> {
            v.parse::<u64>()
                .map_err(|_| format!("{flag}: not a number: {v}"))
        };
        match args[i].as_str() {
            "--fixtures" => dir = Some(PathBuf::from(need(i)?)),
            "--warmup" => budget.warmup = parse(need(i)?, "--warmup")? as usize,
            "--iters" => budget.iters = parse(need(i)?, "--iters")? as usize,
            "--throughput-ms" => budget.throughput_ms = parse(need(i)?, "--throughput-ms")?,
            "--throughput-runs" => budget.throughput_runs = parse(need(i)?, "--throughput-runs")? as u32,
            other => return Err(format!("unknown flag: {other}")),
        }
        i += 2;
    }

    if budget.iters == 0 {
        return Err("--iters must be at least 1".into());
    }
    if budget.throughput_runs == 0 || budget.throughput_ms == 0 {
        return Err("--throughput-ms and --throughput-runs must both be non-zero".into());
    }

    Ok((dir.ok_or("--fixtures <dir> is required")?, budget))
}

fn timer_floor_micros() -> f64 {
    let mut probes = Vec::with_capacity(2000);
    for _ in 0..2000 {
        let t0 = Instant::now();
        probes.push(t0.elapsed().as_secs_f64() * 1e6);
    }
    probes.sort_by(|a, b| a.partial_cmp(b).unwrap());
    probes[probes.len() / 2]
}

/// One decision, from the bytes a proxy would actually hand over.
///
/// The input is re-parsed from JSON **text** every time, because that is what
/// zopa and OPA are charged for in the same table: an engine handed a
/// pre-deserialised value is not doing the same work. `eval_only` below
/// measures the other half, with the request built once.
fn decide(
    authorizer: &Authorizer,
    policies: &PolicySet,
    entities: &Entities,
    principal: &EntityUid,
    action: &EntityUid,
    resource: &EntityUid,
    input_text: &str,
) -> Result<i32, String> {
    let value: Value = serde_json::from_str(input_text).map_err(|e| e.to_string())?;
    let context = Context::from_json_value(value, None).map_err(|e| e.to_string())?;
    let request = Request::new(
        principal.clone(),
        action.clone(),
        resource.clone(),
        context,
        None,
    )
    .map_err(|e| e.to_string())?;
    let response = authorizer.is_authorized(&request, policies, entities);
    // Cedar is deny-by-default with no third state, so there is no undefined
    // to map: allow is 1, everything else denies. Same mapping as cedar.mjs.
    Ok(i32::from(response.decision() == Decision::Allow))
}

fn measure_fixture(path: &Path, budget: &Budget, floor: f64) -> Result<Option<Value>, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let fixture: Value = serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;

    // Only fixtures carrying a Cedar policy, matching cedar.mjs. Writing one
    // from the Rego would be guessing at a semantic mapping, which is what
    // the agreement gate exists to make impossible.
    let Some(policy_text) = fixture.get("cedar").and_then(Value::as_str) else {
        return Ok(None);
    };
    if policy_text.is_empty() {
        return Ok(None);
    }
    let name = fixture
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{}: fixture has no name", path.display()))?;
    let input = fixture
        .get("input")
        .ok_or_else(|| format!("{name}: fixture has no input"))?;
    let input_text = serde_json::to_string(input).map_err(|e| e.to_string())?;

    let principal: EntityUid = PRINCIPAL.parse().map_err(|e| format!("principal: {e}"))?;
    let action: EntityUid = ACTION.parse().map_err(|e| format!("action: {e}"))?;
    let resource: EntityUid = RESOURCE.parse().map_err(|e| format!("resource: {e}"))?;
    let entities = Entities::empty();
    let authorizer = Authorizer::new();

    // Cold start for a linked-in library is policy parse plus first decision.
    // There is no instantiate and no process spawn to count -- which is most
    // of why this row exists.
    let cold_t0 = Instant::now();
    let policies: PolicySet = policy_text
        .parse()
        .map_err(|e| format!("{name}: parsing cedar policy: {e}"))?;
    let decision = decide(
        &authorizer,
        &policies,
        &entities,
        &principal,
        &action,
        &resource,
        &input_text,
    )
    .map_err(|e| format!("{name}: {e}"))?;
    let cold_start_ms = cold_t0.elapsed().as_secs_f64() * 1e3;

    for _ in 0..budget.warmup {
        decide(
            &authorizer,
            &policies,
            &entities,
            &principal,
            &action,
            &resource,
            &input_text,
        )
        .map_err(|e| format!("{name}: {e}"))?;
    }

    let mut samples = Vec::with_capacity(budget.iters);
    for _ in 0..budget.iters {
        let t0 = Instant::now();
        let d = decide(
            &authorizer,
            &policies,
            &entities,
            &principal,
            &action,
            &resource,
            &input_text,
        )
        .map_err(|e| format!("{name}: {e}"))?;
        samples.push((t0.elapsed().as_secs_f64() * 1e6 - floor).max(0.0));
        // The decision is read rather than discarded so the optimiser cannot
        // delete the call it is supposed to be timing.
        if d != decision {
            return Err(format!("{name}: decision changed mid-run: {decision} then {d}"));
        }
    }

    let ops_per_sec = throughput(budget, || {
        decide(
            &authorizer,
            &policies,
            &entities,
            &principal,
            &action,
            &resource,
            &input_text,
        )
        .is_ok()
    });

    // The evaluator alone, with the request built once. This is the figure the
    // proposal wanted and the one the wasm binding cannot show: no JSON, no
    // serialisation boundary, just `is_authorized` against a parsed policy set.
    let eval_only = {
        let value: Value = serde_json::from_str(&input_text).map_err(|e| e.to_string())?;
        let context = Context::from_json_value(value, None).map_err(|e| e.to_string())?;
        let request = Request::new(
            principal.clone(),
            action.clone(),
            resource.clone(),
            context,
            None,
        )
        .map_err(|e| e.to_string())?;
        for _ in 0..budget.warmup {
            authorizer.is_authorized(&request, &policies, &entities);
        }
        let mut evals = Vec::with_capacity(budget.iters);
        for _ in 0..budget.iters {
            let t0 = Instant::now();
            let r = authorizer.is_authorized(&request, &policies, &entities);
            evals.push((t0.elapsed().as_secs_f64() * 1e6 - floor).max(0.0));
            if (r.decision() == Decision::Allow) != (decision == 1) {
                return Err(format!("{name}: eval-only decision disagrees with the full path"));
            }
        }
        let ops = throughput(budget, || {
            authorizer.is_authorized(&request, &policies, &entities).decision() == Decision::Allow
        });
        let s = summarise(&mut evals);
        json!({ "p50": s.0, "p95": s.1, "p99": s.2, "amortizedMicros": 1e6 / ops })
    };

    let (p50, p95, p99, mean) = summarise(&mut samples);
    Ok(Some(json!({
        "name": name,
        "decision": decision,
        "p50": p50,
        "p95": p95,
        "p99": p99,
        "mean": mean,
        "opsPerSec": ops_per_sec,
        "amortizedMicros": 1e6 / ops_per_sec,
        "coldStartMs": cold_start_ms,
        "evalOnly": eval_only,
    })))
}

/// Best of several short windows, for the reason `run.mjs` gives: one window
/// that catches a scheduler hiccup reports well below what the engine can do,
/// and at sub-microsecond costs a single pause dominates the average.
fn throughput<F: FnMut() -> bool>(budget: &Budget, mut f: F) -> f64 {
    let window_ms = (budget.throughput_ms / u64::from(budget.throughput_runs)).max(1);
    let window = std::time::Duration::from_millis(window_ms);
    let mut best = 0.0f64;
    for _ in 0..budget.throughput_runs {
        let start = Instant::now();
        let mut n = 0u64;
        while start.elapsed() < window {
            std::hint::black_box(f());
            n += 1;
        }
        let elapsed = start.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            best = best.max(n as f64 / elapsed);
        }
    }
    best
}

fn summarise(samples: &mut [f64]) -> (f64, f64, f64, f64) {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let at = |p: f64| samples[((samples.len() as f64 * p) as usize).min(samples.len() - 1)];
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    (at(0.50), at(0.95), at(0.99), mean)
}
