# Roadmap

Plans are best-effort. Priorities shift with adoption signals; if something here matters to you, open an issue.

## Where this sits in 2026

Four things moved in the ecosystem zopa lives in, and they shape what is worth building next.

**AuthZEN 1.0 is final.** The OpenID Foundation approved [Authorization API 1.0][authzen] as a Final Specification on 12 January 2026, standardising the PEP↔PDP wire format. This is the most directly relevant of the four: an AuthZEN Access Evaluation request is already a valid zopa input, so a compliant PDP can use zopa as its decision core without an adapter. The mapping, the error case, and a conformance fixture are in [`docs/authzen.md`](docs/authzen.md). Building an HTTP PDP is out of scope for this repository -- zopa is the engine, not the server -- but the mapping staying correct is not.

**proxy-wasm 0.3.0 has not shipped.** The milestone is still open in [proxy-wasm/spec][pw] with unresolved issues filed through mid-2026; work continues in the `vNEXT` ABI directory rather than a cut release. The one concrete vNEXT change zopa already carries is `proxy_on_memory_allocate`, exported alongside `malloc` so the module loads on either generation of host. Chasing the rest of 0.3 before it stabilises would buy nothing.

**Envoy dynamic modules are the competing extension path.** Loading a shared library skips the VM entirely and is faster for body-heavy filters. It also gives up the sandbox and pins you to an Envoy version per build. That trade is real, and it is why the README says plainly when *not* to reach for zopa. Where a policy engine is loading attacker-adjacent configuration into a shared proxy, the isolation boundary is the feature.

**Wasm 3.0 (Dec 2025) and WASI 0.3 (June 2026) landed.** Neither changes much here: zopa is `wasm32-freestanding`, uses no GC, no exceptions, no 64-bit memory, and no syscalls. The component model is worth revisiting once it reaches 1.0 and proxy-wasm hosts speak it, but today a component wrapper would add size for no capability.

[authzen]: https://openid.net/specs/authorization-api-1_0.html
[pw]: https://github.com/proxy-wasm/spec

## Unreleased

- **Cedar measured natively.** `bench/native/cedar` links `cedar-policy` in and times itself, so the benchmark no longer has to caveat its Cedar row as a measurement of the WASM binding. The binding was costing Cedar 3-4x; what is left after that is request conversion rather than evaluation, and Cedar's evaluator answers the RBAC fixture in 1.63 us against `zopa-compiled`'s 1.37. Opt-in, since building it pulls ~100 crates. This closes the last item of `docs/proposals/benchmark-harness.md`.

## Done in v0.5.0

- **`targets[]` in the proxy-wasm plugin configuration.** A deployment names which `(package, rule)` pairs each phase evaluates and whether a deny enforces, so an audit rule can ride alongside the enforcing one on the same input without becoming a way to fail a request. Enforcing targets are ANDed; advisory ones never block, which is the one place the shim deliberately does not fail closed, and why `deny` is the default. The bare-AST configuration is unchanged. This closes the last open goal of `docs/proposals/multiple-policies.md`.
- **`:=` assignment and array indexing.** The two Rego idioms the coverage table named as practically missing. `zig build test-coverage` goes from 32/48 constructs to 36/52.

## Done in v0.4.x

- **Cross-engine benchmark.** `zig build bench` runs zopa (both generic-ABI shapes), OPA compiled to wasm, an OPA HTTP sidecar, and Cedar over the same fixtures, gated on every engine agreeing on the decision before anything is timed. Reports p50/p95/p99, an uninstrumented amortised cost, throughput, memory after warm-up, deployed artifact size, and cold start. `bench/results/baseline.json` turns it into a regression gate in CI. Numbers and caveats in [`bench/README.md`](bench/README.md).
- **Compiled-policy export.** `policy_compile` / `policy_release` / `evaluate_compiled` / `evaluate_compiled_addressed` let a generic-ABI host build a policy once and evaluate against a handle, which is what the proxy-wasm path has always done internally. This was the benchmark's clearest finding: through `evaluate` zopa answered the RBAC fixture in 5.76 us against OPA-in-wasm's 2.24; against a held policy it answers in 1.32. The AST parse was the entire difference.
- **`zig build test-coverage`: which Rego constructs the converter reaches.** The coverage ledger the conformance harness was supposed to double as, made explicit — and it immediately found four constructs (`with`, partial rules, `else`, function definitions) that `rego2ast.py` was converting with exit 0 while changing what they mean.
- **Supply chain.** Releases carry a signed CycloneDX SBOM alongside the wasm, its sha256, a cosign bundle and SLSA v1.0 provenance. `LICENSE` was restored to the canonical Apache License 2.0 text after three years of shipping a paraphrase. `SECURITY.md` documents verifying a release end to end.

## Done in v0.3.0

- **Fail-closed everywhere.** Six paths could reach "allow" without having decided: an oversized body, a chunked body evaluated on its tail, a body the host would not hand over, a header map that would not decode, an empty plugin configuration, and a deny that returned `Continue` after answering the request. All deny now. See the `CHANGELOG.md` entry for 0.3.0.
- **Rego agreement on rule dispatch.** A package split across modules is one rule set; conflicting definitions are an error rather than resolved by bundle order; two `default` declarations for one rule are rejected when the policy is built, as OPA rejects them at compile time.
- **Parser agreement.** RFC 8259 number grammar and last-wins duplicate keys, so zopa and the service behind it read a request the same way.
- **AuthZEN mapping.** [`docs/authzen.md`](docs/authzen.md) plus a conformance fixture, following the Authorization API 1.0 Final specification.
- **The proxy-wasm ABI is tested in CI**, against a pinned upstream Envoy, covering all three phases rather than only request headers.
- **Policy compiled once at configure time** instead of re-parsed per request.

## Done in v0.2.0

- **Body-aware policies.** New `allow_body` target rule fires from `proxy_on_request_body` against `{body, body_raw}` once end of stream is reached. Phase opts in via the rule's presence so v0.1 request-only policies still pass response and body phases through unchanged. Per-context request snapshot deferred to v2 (see `docs/proposals/body-aware-policies.md`).
- **Response-side policies.** `allow_response` target rule fires from `proxy_on_response_headers` against `{response: {status, headers}}`. Deny replaces the upstream response with a fixed 503 (structured replacement deferred).
- **Compiled-policy benchmark.** `zig build bench` runs a Node-based latency benchmark over `bench/fixtures/`. Extended after v0.3.1 into the cross-engine comparison below.
- **AST conformance harness.** `tools/rego2ast.py` converts `opa parse --format json` output into zopa's AST; `test/conformance/` drives a small fixture suite end-to-end. CI runs it on every PR.
- **Set/object refs.** `iterItems` resolves refs into JSON objects; `some` / `every` pick `kind: "keys" | "values"` (default keys).
- **Function calls.** `startswith`, `endswith`, `contains`, `count` via the new `call` AST node.
- **Multiple policies.** New `Modules` bundle and `package` field on `Module`. `evaluate_addressed(input, ast, package, rule)` wasm export dispatches by `(package, rule)`.
- **Distroless OCI image.** `Dockerfile` + `.github/workflows/oci.yml` publish a multi-arch, cosign-signed image to `ghcr.io/kanywst/zopa` on every tag.
- **Static body-deps analyser.** `src/body_deps.zig` classifies a policy's body usage as `no_body_refs` / `prefix_only` / `full_tree` at configure time (foundation for the streaming runtime below).

## Near term

- **Streaming evaluation runtime.** Build on the body-deps analyser to skip body buffering when no body refs exist, or short-circuit as soon as referenced prefixes resolve. Design in `docs/proposals/streaming-evaluation.md`.
- **Conformance corpus expansion.** `zig build test-coverage` now answers "which constructs" (36 of 52 as of v0.5.0), so the number exists. What is still missing is breadth: vendor a slice of the OPA upstream test corpus rather than a hand-written probe, and close the constructs the ledger reports as out of reach.
- **Structured response replacement.** Surface a `json.Value` from the evaluator so a denied `allow_response` rule can return `{status, body, headers}` instead of the fixed 503.
- **Per-context request snapshot.** Surface `:method` / `:path` / selected headers under `proxy_on_request_body` so body rules can reason about request context too.

## Medium term

- **Per-root-context policies.** `proxy_on_configure` currently ignores the root context id, so a VM shared by two filter configurations (an explicit shared `vm_id`) keeps only the last policy. Supporting more than one needs a root-context table plus a stream→root mapping recorded in `proxy_on_context_create`.
- **proxy-wasm 0.3.x** when the spec stabilizes (design in `docs/proposals/proxy-wasm-0-3.md`). Still an open milestone upstream as of August 2026; `proxy_on_memory_allocate` is the only vNEXT piece adopted so far.
- **Reference AuthZEN PDP.** A thin HTTP server -- separate repository -- that exposes `/access/v1/evaluation` over a zopa instance, so the mapping in `docs/authzen.md` has an executable counterpart. Deliberately not part of the wasm module.

## Longer term

- **CNCF Sandbox application** once there are at least three unaffiliated adopters using zopa in production.

## Out of scope

- Compiling Rego source inside the wasm artifact. The walker lives in `tools/rego2ast.py` and runs against `opa parse` output. The wasm module stays a runtime, not a language.
- WASI support. zopa targets `wasm32-freestanding`; WASI would pull in syscalls we don't need. This holds for WASI 0.3 (June 2026) as much as for 0.2 -- the async primitives it adds solve a problem zopa doesn't have, since evaluation never blocks.
- An HTTP server, a management plane, or bundle distribution. Those are what OPA is for. zopa is a decision function.
- A query language separate from Rego. The AST is Rego-shaped on purpose.
