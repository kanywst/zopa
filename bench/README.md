# bench/

Latency benchmarks for `zopa.wasm`. v1 covers the zopa side only.

OPA WASM SDK, OPA HTTP sidecar, and Cedar comparisons are deferred
until the conformance harness lands (see
`docs/proposals/opa-conformance-harness.md`). Without conformance,
"same answer" cannot be asserted, so a head-to-head latency number
isn't honest.

## Layout

```text
bench/
  run.mjs           Node runner (drives evaluate via the same Node host as test/run.mjs)
  fixtures/
    01_static.json     fixture: literal allow:true
    02_header_eq.json  fixture: input.method == "GET"
    03_rbac.json       fixture: default-deny RBAC (path prefix + role + every/some over perms)
  README.md
```

Each fixture is a JSON object with `name`, `input`, `ast`, and (when
applicable) the source forms in `rego` / `cedar` for cross-engine
runs added later.

## Running

```bash
zig build --release=small        # produces zig-out/bin/zopa.wasm
zig build bench                  # invokes node bench/run.mjs
```

The runner loads each fixture, executes `evaluate` 10,000 iterations
after a 1,000-iteration warm-up, and prints p50 / p95 / p99 / mean
latency in microseconds.

## Output

```text
fixture                 |    p50 |    p95 |    p99 |   mean
------------------------+--------+--------+--------+-------
01_static               |  X.XX  |  X.XX  |  X.XX  |  X.XX
02_header_eq            |  X.XX  |  X.XX  |  X.XX  |  X.XX
```

Numbers are wall-clock, single-process, CPU-bound. They are not a
substitute for the proxy-wasm in-Envoy path (which adds
serialisation + host-call overhead). For the in-Envoy story, see
`examples/envoy/`.

## What these numbers include

The runner drives the generic `evaluate(input, ast)` export, which
re-parses and rebuilds the policy AST on every call -- it receives the
AST bytes per request and cannot know they are the same ones as last
time. On `03_rbac` that parse is most of the measured time.

The proxy-wasm path does not work that way: `proxy_on_configure` parses
and builds the policy once onto a long-lived arena, so per-request work
there is the input parse plus the rule walk. Read the table as an upper
bound on the in-Envoy per-request cost, not an estimate of it.

Measuring the compiled path directly needs an export that takes a
pre-built policy handle, which would widen the public surface. That is
a deliberate omission for now rather than an oversight.
