# bench/

Cross-engine benchmark: zopa against the two shapes it exists to replace — OPA compiled to WASM and loaded in-process, and OPA run as an out-of-process sidecar over HTTP.

## The rule this harness is built around

No engine is timed until every engine has been shown to return the same decision for the fixture. A latency number for an engine that answers differently is not a comparison, it is two unrelated measurements printed next to each other. Disagreement is a hard failure with a non-zero exit, not a footnote — and the decision each engine reached is printed in the table so the agreement is visible rather than asserted.

This is why the comparison did not ship in v0.2.0 alongside the zopa-only harness: without the conformance bridge there was no way to state that zopa and OPA were being asked the same question. `tools/rego2ast.py` and `zig build test-conformance` closed that, so each fixture now carries both an AST and the Rego it corresponds to, and the harness checks they agree at run time.

## Layout

```text
bench/
  run.mjs              orchestrator: agreement gate, then metrics
  engines/
    zopa.mjs           generic `evaluate(input, ast)`: policy handed over per call
    zopa-compiled.mjs  `policy_compile` once, then `evaluate_compiled(handle, input)`
    opa-wasm.mjs       `opa build -t wasm` + the opa_eval fast path
    opa-http.mjs       `opa run --server` over loopback HTTP
    cedar.mjs          `@cedar-policy/cedar-wasm`, policy set preparsed
    cedar-native.mjs   drives `native/cedar` and reports what it measured
  native/
    cedar/             Rust: `cedar-policy` linked in, timing itself (opt-in)
  fixtures/
    01_static.json       literal allow:true
    02_header_eq.json    input.method == "GET"
    03_rbac.json         default-deny RBAC: path prefix + role + every/some over perms
    04_deep_nest.json    24 nested frames, driving the depth cap (zopa-only)
  README.md
```

Each fixture is a JSON object with `name`, `input`, `ast`, and — when the policy has a readable equivalent in that language — `rego` and `cedar`. Fixtures missing one are skipped for the engines that need it rather than guessed at: writing a policy on the fly from the AST would be inventing a semantic mapping, and the agreement gate exists precisely so nothing is invented. `04_deep_nest` has neither; there is no natural Rego or Cedar that compiles to 24 levels of expression nesting.

## Running

```bash
zig build bench               # all available engines, full iteration counts
```

`zig build bench` builds its own `ReleaseSmall` artifact and measures that, whatever `-Doptimize` you passed. The test suites run correctly at any optimize mode; a benchmark does not, and measuring the ~940 KB debug build reports a wrong number rather than failing.

Options can be passed through the build step (`zig build bench -- --quick`), or by invoking the harness directly:

```bash
node bench/run.mjs path/to/zopa.wasm        # benchmark a specific build
node bench/run.mjs                          # falls back to zig-out/bin/zopa.wasm
node bench/run.mjs --quick                  # CI smoke counts (seconds, not minutes)
node bench/run.mjs --engines=zopa,opa-wasm  # subset
node bench/run.mjs --json=bench/results/local.json
```

The OPA engines need an `opa` CLI on `PATH`; Cedar needs `@cedar-policy/cedar-wasm` resolvable from this directory:

```bash
npm i --no-save @cedar-policy/cedar-wasm
```

Anything missing is **skipped and named**, and the run still reports whatever is available — so `zig build bench` does something useful on a machine that has never heard of either. Nothing is vendored and this repository still has no `package.json`: the OPA WASM ABI is bound directly in `engines/opa-wasm.mjs`, and Cedar resolves at run time or skips.

`cedar-native` is **opt-in** rather than skipped-if-missing, because building it pulls ~100 crates and takes a minute or two cold — not something every `zig build bench` should decide to do on its own:

```bash
zig build bench -- --engines=zopa,zopa-compiled,cedar,cedar-native
ZOPA_BENCH_CEDAR_NATIVE=1 zig build bench
```

It is also the one engine this harness does not time. `run.mjs` times `decide()` inside the Node process, and driving a Rust child from there would put a pipe round trip — tens of microseconds — inside the timed path, which is larger than every in-process engine here put together. So `native/cedar` measures itself under the same budget, with the same clock-read floor subtraction and the same best-of-N throughput windows, and the engine module reports what it found; the agreement gate still checks its decision, because correctness has no deadline. Any engine can do this by exporting `measure()`.

## Regression gate

`bench/results/baseline.json` records, for each fixture, the ratio of every engine's amortised cost to `zopa-compiled` **on the same run**. CI compares each PR's smoke run against it:

```bash
node bench/compare.mjs bench-smoke.json bench/results/baseline.json
```

Ratios, never absolute microseconds. A shared runner cannot measure a sub-microsecond p99 meaningfully, and storing its numbers as a baseline would mean re-seeding whenever the runner pool changed. A runner that is simply slow today scales every engine in the same process equally, so the ratios hold; a change that makes zopa's own evaluation slower moves them. That is the only cross-machine comparison this data honestly supports.

The threshold is 1.5x, deliberately wide. It exists to catch something like a per-request policy parse creeping back into the compiled path, not to police a few percent of drift — a gate that cries wolf gets ignored, which is worse than not having one. Verified in both directions: three consecutive `--quick` runs against the committed baseline pass with the worst ratio at 0.66x, and reintroducing the per-request AST parse into `zopa-compiled` trips all 13 ratios, by up to 19.7x on `04_deep_nest`.

The gate's own exit-code contract is tested — `node --test bench/compare.test.mjs`, also run in CI before the gate is trusted to gate anything. Pass, regressed, reference-engine-missing and nothing-overlapped are each asserted, because a later edit reopening the fail-open case is precisely the failure this design is guarding against.

To re-seed after an intended change:

```bash
zig build bench -- --json=run.json
node bench/compare.mjs run.json > bench/results/baseline.json
```

Seed from a full run, never from `--quick`: 300 iterations is enough for the agreement gate but not for a number anything else is compared against.

## Metrics

- **p50 / p95 / p99** per decision, from per-iteration samples, minus a measured clock-read floor.
- **amort** — the same cost measured with no instrumentation inside the loop (a fixed time window divided by the count). Where `amort` sits well below `p50`, the clock reads around each iteration were most of what `p50` captured. Trust `amort` for the level and the percentiles for the shape of the tail; at the default iteration counts they converge, and in `--quick` mode they do not.
- **ops/s** for a single sequential caller, taken as the **best of several short windows** rather than one long one. For the in-process engines that is CPU-bound; for the sidecar it is bounded by the round trip, which is the point. Best-of matters at these costs: a single window that catches a GC pause reports well below what the engine can do, and an early revision of this harness measured `zopa-compiled` at 3.84 µs amortised against a 1.38 µs p50 on the same run — interference, not the engine.
- **mem KiB** after warm-up: WASM linear memory for the in-process engines, and for the sidecar the resident figure from OPA's own `/metrics` (read over HTTP rather than via `ps`, which needs permission to inspect another process and differs per platform).
- **artifact KiB** — the deployed artifact. For zopa this is one module that serves every policy; for OPA WASM it is one module *per policy*.
- **cold ms** — instantiate plus first decision. `opa build` is deliberately outside this: it is a build step, not a runtime one, so the compiled bundle is memoised and cold start measures what a deployment actually pays.

## What the numbers said when this landed

Apple M-series laptop, Node 26, OPA 1.20.2, Cedar 4.12.0 (both the WASM binding and the native crate), `--release=small` at v0.5.0. Every column comes from one run of `node bench/run.mjs --engines=zopa,zopa-compiled,opa-wasm,opa-http,cedar,cedar-native`, so the rows are comparable to each other; treat the absolute values as machine-specific and the ratios as the result.

Per-decision cost, microseconds (`amort`):

| fixture | zopa (evaluate) | zopa (compiled) | OPA (wasm) | Cedar (native) | Cedar (wasm) | OPA (HTTP sidecar) |
| --- | --- | --- | --- | --- | --- | --- |
| `01_static` | 0.35 | **0.09** | 0.86 | 2.83 | 11.9 | 140 |
| `02_header_eq` | 1.00 | **0.21** | 0.99 | 5.26 | 15.6 | 133 |
| `03_rbac` | 5.87 | **1.37** | 2.26 | 34.8 | 52.4 | 157 |
| `04_deep_nest` | 5.98 | **0.37** | — | — | — | — |

The Cedar rows are two measurements of the same engine, and the `native` column is charged for the same work as every other column: parsing the request from JSON text. With the request already built, Cedar's evaluator alone answers in **0.63 / 1.00 / 1.63 µs** on the three fixtures — competitive with `zopa-compiled`. Everything between that and the 2.83 / 5.26 / 34.8 above is Cedar converting a JSON request into its own value types, which is not overhead you can opt out of if you are handing it a request off the wire.

Footprint and start-up:

| | zopa | OPA (wasm) | OPA (HTTP sidecar) |
| --- | --- | --- | --- |
| deployed artifact | **69 KiB**, all policies | 131 KiB **per policy** | — |
| memory after warm-up | 1.3–1.6 MiB | **128 KiB** | 23 MiB |
| cold start | **0.4–0.9 ms** | 0.6–2.2 ms | 60–190 ms |

Six things to take from that, including the ones that do not favour zopa:

1. **Handing the policy over on every call is most of the cost.** The gap between the two zopa rows is exactly what the AST parse and build cost, because nothing else differs between them. If you drive the same policy across requests through `evaluate`, that is what you are paying for the convenience.
2. **With the policy held, zopa is faster than OPA's wasm build on every fixture** — 1.37 µs against 2.26 on the realistic RBAC policy, where the one-shot path lost. An earlier revision of this file predicted exactly this and could not demonstrate it, because no export took a pre-built policy. `policy_compile` / `evaluate_compiled` is that export.
3. **Both in-process wasm engines beat the sidecar by two orders of magnitude.** This is the claim zopa was built on and it holds with room to spare. It is also the least surprising row: it measures a loopback TCP round trip against a function call.
4. **The WASM binding was costing Cedar about 3–4x, and the rest is not the evaluator either.** Earlier revisions of this file said the `Cedar (wasm)` row was dominated by the wasm-bindgen boundary and that a native embedding would look different, without measuring it. Now it is measured: native is 2.83 / 5.26 / 34.8 µs against the binding's 11.9 / 15.6 / 52.4, so the boundary was real and it was roughly a 3–4x tax. But native is still 25x `zopa-compiled` on `03_rbac`, and that remainder is *not* evaluation — Cedar's evaluator answers the same fixture in 1.63 µs once it holds the request. It is `Context::from_json_value` plus `Request::new`: converting a JSON document into Cedar's own typed values, schema-less, with the RBAC fixture's arrays becoming sets. That is a design difference, not a slow evaluator. Cedar is built for a request you assemble from typed application state; zopa and OPA are built for one that arrives as JSON on the wire.
5. **Cedar's evaluator is roughly as fast as zopa's.** 0.63 / 1.00 / 1.63 µs against `zopa-compiled`'s 0.09 / 0.21 / 1.37, on the one comparison where both hold everything they need. The gap on the realistic fixture is 1.2x. Any reading of this table that concludes zopa has a faster *evaluator* than Cedar is reading the request-conversion column.
6. **zopa holds more WASM memory than OPA's module does** — about 1.4–1.6 MiB against 128 KiB. That is the arena working as designed: it is reset with `.retain_capacity` after every request so `memory.grow` stops firing once warm, trading a steady-state floor for never allocating again. OPA rewinds its heap pointer instead. Against the sidecar's 23 MiB both are rounding errors, but "smaller binary" does not imply "smaller runtime footprint" and the table should not be read as if it did.

## Not measured

- **Cedar with a schema.** The native harness calls `Context::from_json_value` with no schema, matching what the WASM engine passes, so Cedar infers types per request. A schema would let it skip some of that, and request conversion is most of the native row — so the `Cedar (native)` figure is an upper bound on a schema-less deployment, not Cedar's floor.
- **The in-Envoy path.** These numbers are single-process and CPU-bound; the proxy-wasm path adds host calls and header serialisation. The `zopa (compiled)` row is the closest proxy of the two, since it does the same per-request work the shim does — input parse plus rule walk against a policy built at configure time. See `examples/envoy/`.
- **Concurrency.** `ops/s` is one sequential caller. A saturation number across many in-flight requests would say more about the sidecar than about the engines, and it is the sidecar row that is already unambiguous.
