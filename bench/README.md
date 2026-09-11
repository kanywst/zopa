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
    zopa.mjs           generic `evaluate(input, ast)` export
    opa-wasm.mjs       `opa build -t wasm` + the opa_eval fast path
    opa-http.mjs       `opa run --server` over loopback HTTP
  fixtures/
    01_static.json       literal allow:true
    02_header_eq.json    input.method == "GET"
    03_rbac.json         default-deny RBAC: path prefix + role + every/some over perms
    04_deep_nest.json    24 nested frames, driving the depth cap (zopa-only)
  README.md
```

Each fixture is a JSON object with `name`, `input`, `ast`, and — when the policy has a readable Rego equivalent — `rego`. Fixtures without `rego` are zopa-only by construction and are skipped for the other engines rather than guessed at. `04_deep_nest` is one: there is no natural Rego that compiles to 24 levels of expression nesting.

## Running

```bash
zig build --release=small     # produces zig-out/bin/zopa.wasm
zig build bench               # all available engines, full iteration counts
```

Or directly, for the options:

```bash
node bench/run.mjs                          # same as `zig build bench`
node bench/run.mjs path/to/zopa.wasm        # benchmark a specific build
node bench/run.mjs --quick                  # CI smoke counts (seconds, not minutes)
node bench/run.mjs --engines=zopa,opa-wasm  # subset
node bench/run.mjs --json=bench/results/local.json
```

The OPA engines need an `opa` CLI on `PATH`. Without one they are **skipped and named**, and the run still reports zopa — so `zig build bench` does something useful on a machine that has never heard of OPA. No npm dependency is involved: the OPA WASM ABI is bound directly in `engines/opa-wasm.mjs`, because adding a package manager to compare against would make the benchmark harder to run than the thing it measures.

## Metrics

- **p50 / p95 / p99** per decision, from per-iteration samples, minus a measured clock-read floor.
- **amort** — the same cost measured with no instrumentation inside the loop (a fixed time window divided by the count). Where `amort` sits well below `p50`, the clock reads around each iteration were most of what `p50` captured. Trust `amort` for the level and the percentiles for the shape of the tail; at the default iteration counts they converge, and in `--quick` mode they do not.
- **ops/s** for a single sequential caller. For the in-process engines that is CPU-bound; for the sidecar it is bounded by the round trip, which is the point.
- **mem KiB** after warm-up: WASM linear memory for the in-process engines, and for the sidecar the resident figure from OPA's own `/metrics` (read over HTTP rather than via `ps`, which needs permission to inspect another process and differs per platform).
- **artifact KiB** — the deployed artifact. For zopa this is one module that serves every policy; for OPA WASM it is one module *per policy*.
- **cold ms** — instantiate plus first decision. `opa build` is deliberately outside this: it is a build step, not a runtime one, so the compiled bundle is memoised and cold start measures what a deployment actually pays.

## What the numbers said when this landed

Apple M-series laptop, Node 26, OPA 1.20.2, `--release=small`. Reproduce with `zig build bench`; treat the absolute values as machine-specific and the ratios as the result.

Per-decision cost, microseconds (`amort`):

| fixture | zopa | OPA (wasm) | OPA (HTTP sidecar) |
| --- | --- | --- | --- |
| `01_static` | **0.32** | 0.82 | 133 |
| `02_header_eq` | 0.98 | **0.95** | 140 |
| `03_rbac` | 5.80 | **2.24** | 145 |

Footprint and start-up:

| | zopa | OPA (wasm) | OPA (HTTP sidecar) |
| --- | --- | --- | --- |
| deployed artifact | **61 KiB**, all policies | 131 KiB **per policy** | — |
| memory after warm-up | 1.3–1.5 MiB | **128 KiB** | 23 MiB |
| cold start | **0.4 ms** | 0.5 ms | 30–63 ms |

Three things to take from that, including the two that do not favour zopa:

1. **Both in-process engines beat the sidecar by roughly 150x.** This is the claim zopa was built on and it holds with a wide margin. It is also the least surprising row in the table: it is measuring a loopback TCP round trip against a function call.
2. **OPA's WASM build is faster than zopa on the realistic policy** — 2.24 µs against 5.80 µs on `03_rbac`, a 2.6x loss. The cause is structural and known: the generic `evaluate` export receives the AST bytes on every call and cannot know they are the ones it parsed last time, so a policy parse is inside every measurement. On `03_rbac` that parse is most of the number. The proxy-wasm path does not work this way — `proxy_on_configure` builds the policy once onto a long-lived arena — but there is no exported entry point that takes a pre-built policy handle, so the path that would win here is the one this harness cannot reach. Read the zopa column as an upper bound on the in-Envoy cost, and read this row as the strongest argument yet for exporting that handle.
3. **zopa holds more WASM memory than OPA's module does** — about 1.4 MiB against 128 KiB. That is the arena working as designed: it is reset with `.retain_capacity` after every request so `memory.grow` stops firing once warm, which trades a steady-state floor for never allocating again. OPA rewinds its heap pointer instead. Against the sidecar's 23 MiB both are rounding errors, but "smaller binary" does not imply "smaller runtime footprint" and the table should not be read as if it did.

## Not measured

- **Cedar.** The proposal lists it as a native baseline with no proxy-wasm path. There is no first-party Cedar binding reachable from Node without adding a dependency, and a Rust harness for one engine would mean maintaining two harnesses. Deferred deliberately, not forgotten.
- **The in-Envoy path.** These numbers are single-process and CPU-bound; the proxy-wasm path adds host calls and header serialisation. See `examples/envoy/`.
- **Concurrency.** `ops/s` is one sequential caller. A saturation number across many in-flight requests would say more about the sidecar than about the engines, and it is the sidecar row that is already unambiguous.
