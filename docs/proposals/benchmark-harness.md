# Benchmark harness vs OPA / Cedar

Status: **Implemented**, except Cedar and the checked-in result history. Goal 1 minus Cedar and goals 2 and 3 landed after v0.3.1: `bench/run.mjs` runs zopa against OPA-in-wasm (`opa_eval`) and an OPA HTTP sidecar, gated on all engines agreeing on the decision first, and reports p50/p95/p99 plus an uninstrumented amortised cost, throughput, memory after warm-up, deployed artifact size, and cold start. CI runs it in `--quick` mode on every PR. **Cedar is deferred** — no first-party binding is reachable from Node without a dependency, and a second harness in Rust for one engine is not worth maintaining. `bench/results/` committed from `main` (goal 4's second half) is also not built. The numbers, including the two that do not favour zopa, are in [`bench/README.md`](../../bench/README.md). Tracking: ROADMAP.md → Near term ("Compiled-policy benchmark").

## Motivation

The README claims zopa is "two orders of magnitude smaller" than OPA's WASM build. That's a statement about binary size only. We don't yet publish numbers for the things that actually matter at runtime: evaluation latency, memory floor, cold-start time, throughput under load.

Without numbers, the project can't honestly recommend itself for a production proxy filter, and PRs that touch the eval hot path can regress without anyone noticing.

## Goals

1. A reproducible bench harness that runs:
   - zopa (`evaluate` direct + via Envoy/proxy-wasm).
   - OPA WASM SDK (one-shot `opa_eval`).
   - OPA HTTP sidecar (out-of-process baseline, network hop included).
   - Cedar via its native API (no proxy-wasm path; native baseline).
1. Metrics:
   - p50 / p95 / p99 latency per evaluation.
   - Memory floor after warm-up (pages, RSS, wasm linear memory).
   - Cold-start (instantiate + first eval).
   - Throughput at saturation.
1. A small fixture set of policies covering increasing complexity:
   - Static `allow=true`.
   - Single header equality.
   - Nested `every` over `input.required_perms`.
   - Worst-case: deeply nested AST near the recursion cap.
1. CI job that runs a smoke version (low iteration counts) on every PR, full bench on `main` post-merge, results checked into `bench/results/`.

## Non-goals

- Comparing to non-CNCF authorization engines (Casbin, Oso, etc). Optional later.
- Microbenchmarking individual AST nodes. The bench measures the user-facing path, not internal hot loops.
- Beating OPA on every metric. We expect zopa to win on size and cold-start, lose on Rego coverage. The bench should make that legible, not hide it.

## Design sketch

### Layout

```text
bench/
  Cargo.toml             # criterion runner (Rust; for OPA WASM + Cedar)
  build.zig              # zopa direct path (zig benchmark target)
  fixtures/
    01_static.json       # input + AST + Rego + Cedar source
    02_header_eq.json
    03_every_perms.json
    04_deep_nest.json
  hosts/
    zopa_direct.zig      # evaluate(input, ast) over wasmtime embed
    opa_wasm.rs          # opa_eval via wasmtime-rust
    opa_http.rs          # localhost OPA over reqwest
    cedar_native.rs      # cedar-policy crate
  results/
    YYYY-MM-DD-<sha>.json
    latest.md            # human-readable summary
```

### Fixture format

Each fixture carries the same logical policy in three syntaxes:

```json
{
  "name":   "header_eq",
  "input":  { "method": "GET" },
  "rego":   "package authz\nallow if input.method == \"GET\"\n",
  "ast":    { "type": "module", "rules": [ ... ] },
  "cedar":  "permit(principal, action == Action::\"GET\", resource);"
}
```

The runner loads the fixture, hands each engine the form it expects, and asserts every engine returns the same decision before timing anything.

### Metrics format

JSON, one record per (host, fixture, metric) tuple. Aggregated into `latest.md` with a small Python script for the README.

## API impact

None. Bench code lives under `bench/` and never ships in the wasm artifact.

## Test plan

- Smoke run in CI on every PR (~5 seconds, low iteration counts) to catch obvious regressions.
- Full run nightly on `main`, results committed via a GitHub Action with `[skip ci]`.
- Compare-to-baseline check: fail the CI job if p95 regresses by more than 20% vs the latest committed baseline.

## Open questions

- Where do we host the full nightly results? Inline markdown in the repo is honest but noisy. A `gh-pages` site is more browseable but is more infra to maintain.
- Should we fix Envoy / OPA / Cedar versions in `bench/Cargo.lock` and bump them deliberately, or follow latest? Pinning is more reproducible; following latest catches upstream regressions.
- Can the OPA HTTP host be skipped on PR runs and only included nightly? Network-bound benches add variance.
