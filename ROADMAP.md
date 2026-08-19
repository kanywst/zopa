# Roadmap

Plans are best-effort. Priorities shift with adoption signals; if
something here matters to you, open an issue.

## Done in v0.2.0

- **Body-aware policies.** New `allow_body` target rule fires from
  `proxy_on_request_body` against `{body, body_raw}` once end of
  stream is reached. Phase opts in via the rule's presence so v0.1
  request-only policies still pass response and body phases through
  unchanged. Per-context request snapshot deferred to v2 (see
  `docs/proposals/body-aware-policies.md`).
- **Response-side policies.** `allow_response` target rule fires
  from `proxy_on_response_headers` against `{response: {status,
  headers}}`. Deny replaces the upstream response with a fixed 503
  (structured replacement deferred).
- **Compiled-policy benchmark.** `zig build bench` runs a Node-based
  latency benchmark with p50/p95/p99/mean per fixture. zopa-only;
  cross-engine comparison is a follow-up once conformance is wider.
- **AST conformance harness.** `tools/rego2ast.py` converts `opa
  parse --format json` output into zopa's AST; `test/conformance/`
  drives a small fixture suite end-to-end. CI runs it on every PR.
- **Set/object refs.** `iterItems` resolves refs into JSON objects;
  `some` / `every` pick `kind: "keys" | "values"` (default keys).
- **Function calls.** `startswith`, `endswith`, `contains`, `count`
  via the new `call` AST node.
- **Multiple policies.** New `Modules` bundle and `package` field on
  `Module`. `evaluate_addressed(input, ast, package, rule)` wasm
  export dispatches by `(package, rule)`.
- **Distroless OCI image.** `Dockerfile` + `.github/workflows/oci.yml`
  publish a multi-arch, cosign-signed image to `ghcr.io/kanywst/zopa`
  on every tag.
- **Static body-deps analyser.** `src/body_deps.zig` classifies a
  policy's body usage as `no_body_refs` / `prefix_only` / `full_tree`
  at configure time (foundation for the streaming runtime below).

## Near term

- **Streaming evaluation runtime.** Build on the body-deps analyser
  to skip body buffering when no body refs exist, or short-circuit
  as soon as referenced prefixes resolve. Design in
  `docs/proposals/streaming-evaluation.md`.
- **Conformance corpus expansion.** Vendor a slice of the OPA
  upstream test corpus and grow `tools/rego2ast.py` to cover
  enough of the Rego subset for `pass / total` to become a
  meaningful coverage number.
- **Structured response replacement.** Surface a `json.Value` from
  the evaluator so a denied `allow_response` rule can return
  `{status, body, headers}` instead of the fixed 503.
- **Per-context request snapshot.** Surface `:method` / `:path` /
  selected headers under `proxy_on_request_body` so body rules can
  reason about request context too.

## Medium term

- **Cross-engine benchmark.** Once the conformance harness covers
  enough of Rego to assert "same answer" between zopa and OPA, run
  a real head-to-head latency / memory-floor / cold-start bench.
- **proxy-wasm 0.3.x** when the spec stabilizes (design in
  `docs/proposals/proxy-wasm-0-3.md`).

## Longer term

- **CNCF Sandbox application** once there are at least three
  unaffiliated adopters using zopa in production.

## Out of scope

- Compiling Rego source inside the wasm artifact. The walker lives
  in `tools/rego2ast.py` and runs against `opa parse` output. The
  wasm module stays a runtime, not a language.
- WASI support. zopa targets `wasm32-freestanding`; WASI would pull
  in syscalls we don't need.
- A query language separate from Rego. The AST is Rego-shaped on
  purpose.
