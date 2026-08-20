# Changelog

All notable changes are recorded here. Format follows
[Keep a Changelog][kac]; releases follow [Semantic Versioning][semver]
once the first stable tag ships.

## [Unreleased]

## [0.3.0] - 2026-08-20

A hardening release. Every change below exists because some path could
reach "allow" without having actually decided, or because zopa and the
service behind it could read the same bytes differently.

**Upgrading is not transparent.** Requests and policies that worked
under 0.2.0 can behave differently:

- A filter configured without a `configuration` block no longer starts.
  It used to load and pass every request through unevaluated.
- A policy with two definitions of the same rule that hold at once with
  different values now evaluates to `-1` (deny) instead of whichever
  came first in the bundle. Two `default` declarations for one rule are
  now rejected outright when the policy is built.
- Input documents containing `01`, `1.`, `.5`, `+1`, or `1e` no longer
  parse, and duplicate object keys resolve to the last occurrence
  rather than the first.
- A request body over the 64 KiB cap, a body the host will not hand
  over, and a header map that will not decode all deny rather than
  being evaluated against whatever was available.

Read the *Security* section before upgrading; each entry says what the
old behaviour let through.

### Security

- **Oversized request bodies no longer fail open.** The body phase caps
  buffering at 64 KiB. A larger body was silently truncated, which made
  the JSON parse fail, which made `input.body` null, which made a deny
  rule watching `input.body.amount` find nothing to match -- so sending
  a big body bypassed the rule. A truncated body now denies whenever
  the policy reads the body (`body_deps.analyzeTarget` decides whether
  it does). Covered end to end in `examples/envoy/run.sh` with a
  payload that would be *allowed* if zopa saw all of it.
- **Chunked request bodies are buffered before evaluation.**
  `proxy_on_request_body` returned `Continue` on non-final chunks, so
  the host forwarded each fragment as it arrived and the buffer at end
  of stream held only the tail. A policy reading the body was deciding
  on a suffix. Non-final chunks now return `StopIterationAndBuffer`.
- **A missing or invalid policy is a configuration failure.**
  `proxy_on_configure` previously accepted an empty configuration and
  every request then passed through unevaluated. It now returns 0 and
  logs, so Envoy refuses to start the filter (503 with the default
  `fail_open: false`) instead of protecting nothing quietly.
- **JSON parsing agrees with the backend.** Numbers now follow the
  RFC 8259 grammar exactly (`01`, `1.`, `.5`, `+1`, `1e` are rejected)
  instead of whatever `parseFloat` accepted, and duplicate object keys
  resolve last-wins as they do in Go, JavaScript, and OPA. Both were
  parser differentials: a document zopa and the service behind it read
  differently is a way to smuggle a value past a policy.
- **A deny on the request phase returns `Pause`.** It returned
  `Continue` after `proxy_send_local_response`, asking the host to keep
  running the filter chain on a request that had already been answered.

### Fixed

- **Rule dispatch is package-scoped, not module-scoped.** Rules were
  evaluated one module at a time and the results OR-ed, which broke a
  package split across modules two ways: a `default` rule only covered
  its own module, and a module returning `true` short-circuited past a
  later module's explicit `"value": false` deny. All rules contributed
  to a package are now one rule set, matching Rego. Documented under
  "Rule dispatch" in `docs/ast.md`.
- **Conflicting rule definitions error instead of resolving by
  order.** `allow` is a complete rule, and OPA raises
  `eval_conflict_error` ("complete rules must not produce multiple
  outputs") when two definitions hold at once with different values.
  zopa returned whichever came first in the bundle, so the decision
  depended on file layout -- something that carries no meaning in Rego
  and changes when modules are reordered or split -- and answered
  `allow` where OPA refuses to answer. It now returns `-1`, which every
  caller denies on. Definitions that agree are still fine, and a
  `default` never conflicts. Checked against real `opa parse` output in
  `test/conformance/fixtures/10_rule_conflict.json`.
- **`input.body_raw` counts as reading the body.** `body_deps` only
  looked for the path segment `body`, so a policy whose sole body
  dependency was `contains(input.body_raw, "...")` classified as
  `no_body_refs` and skipped the truncation gate entirely -- the same
  fail-open the gate exists to close, reached through the sibling
  field. `input.body_truncated` deliberately still does not count: a
  policy reading the flag is asking to handle truncation itself, and
  refusing the request first would take that away.
- **Two `default` declarations for the same rule are rejected.** The
  last one silently won, so the fallback depended on bundle ordering --
  quietly, since a fallback only applies to requests where nothing else
  matched. OPA rejects this at compile time (`rego_type_error: multiple
  default rules data.authz.allow found`); zopa now rejects it when the
  AST is built, which fails `proxy_on_configure` rather than skewing
  decisions at runtime.
- **A zero-length body is evaluated instead of skipped.** The body
  callback returned early on `body_size <= 0`, which skipped
  `allow_body` and its `default`. Note this was not reachable through
  Envoy, which does not invoke the callback at all for a request with
  no body -- pinned by a check in `examples/envoy/run.sh` -- but the
  early return was wrong for any host that does, and a condition that
  must hold for every request belongs in `allow` regardless.
- **An unreadable header map denies.** A host error or a buffer that
  didn't decode produced an empty header set, which is not the same
  thing: a rule shaped `deny if input.headers["x-blocked"]` sees the
  header as absent and lets the request through. Same mistake as
  deciding on a truncated body. A map with zero entries is still a
  legitimate answer.
- **A body the host refuses to hand over denies.** `readBodyBytes`
  folded a failed `proxy_get_buffer_bytes` into an empty slice, which
  is indistinguishable downstream from a request that carried no body:
  a rule watching for a marker found nothing in `""` and let the
  request through.
- `free(0)` no longer reads a length prefix from below address zero;
  the export takes a nullable pointer and ignores null.
- `body_deps.zig` is actually wired into the shim. Its doc comment
  claimed the proxy-wasm layer used it to make buffering decisions;
  nothing called it.

### Added

- `proxy_on_memory_allocate` export, the name proxy-wasm ABI vNEXT uses
  for the allocator. Hosts probe for it before falling back to
  `malloc`, so exporting both keeps the module loadable on either
  generation.
- `src/wire.zig`: header-map decoding and per-phase input synthesis,
  split out of `proxy_wasm.zig`. That file's `extern "env"` declarations
  make it unlinkable on the host, so this code -- including the
  length-prefixed binary header-map decoder, the most malformed-input-
  exposed surface in the module -- had no unit tests at all. It now has
  a malformed-buffer table, a 32-bit-overflow case per length field, and
  a round-trip property test proving a header value cannot break out of
  its JSON string literal.
- `std.testing.fuzz` targets over the JSON parser, end-to-end
  evaluation, and the header-map decoder. They run as smoke tests under
  `zig build test-unit`; `--fuzz` mode is blocked by an upstream
  compile error in Zig 0.16.0's own test runner.
- `body_truncated` in the body-phase input, so a policy can key on
  truncation directly rather than only relying on the shim's refusal.
- `evaluate_addressed` is now exercised from a host in `test/run.mjs`
  and `test/run_wasmtime.py`. The export shipped in 0.2.0 with no
  host-side caller outside the conformance harness, and the wasmtime
  harness did not even bind it -- so the suite that exists to catch
  runtime-specific divergence could not reach package dispatch at all.
  Rule dispatch and parser agreement now run under both runtimes.
- Envoy end-to-end coverage of the body and response phases
  (`examples/envoy/envoy-phases.yaml`). The previous bootstrap ended in
  `direct_response`, which Envoy answers before reading the request
  body -- so a body-phase test there would have passed by never
  running. The new scenario proxies to a loopback listener instead.
- `test-envoy` runs in CI against a pinned, checksummed upstream Envoy
  release binary. The proxy-wasm ABI was previously only ever exercised
  on a maintainer's laptop.
- `.github/workflows/claude-review.yml`: an advisory automated review
  pass on pull requests, prompted with this project's actual invariants
  (fail-closed, allocator boundaries, parser agreement, 32-bit length
  arithmetic, size budget) rather than generic style feedback. Skips
  fork PRs, which do not receive secrets.
- [`docs/authzen.md`](docs/authzen.md): mapping from an OpenID AuthZEN
  Authorization API 1.0 Access Evaluation request onto zopa's input,
  plus the error-case mapping (`-1` must become `decision: false`).
  Checked by `test/conformance/fixtures/09_authzen_evaluation.json`.
- `bench/fixtures/03_rbac.json`: a default-deny RBAC policy, so the
  benchmark reports something closer to a policy people write.
- Release build size: ~60 KB → ~62 KB. The increase covers the
  conflict and duplicate-default checks, the body-deps wiring, and the
  fail-closed paths.

### Changed

- The proxy-wasm shim compiles the policy once at configure time onto a
  dedicated arena and keeps the built AST. Per-request work is now the
  input parse plus the rule walk; the policy AST is no longer re-parsed
  on every request. A reconfigure builds the new policy before
  discarding the old one, so a bad config cannot strand a healthy
  filter with nothing loaded.
- `eval.evaluateCompiled` is the new entry point for hosts that hold a
  policy across requests. `evaluate`, `evaluate_target`, and
  `evaluate_addressed` are unchanged.
- `build.zig.zon` now carries the real version. It still said `0.1.0`
  when 0.2.0 shipped, so anything resolving the package by version saw
  the wrong one.
- Repository moved from `0-draft/zopa` to `kanywst/zopa`. GitHub
  redirects the old URL, and `build.zig.zon` never carried the org, so
  clones and `zig fetch` keep working. Forward-looking references
  (README badges, `Dockerfile` source label, ROADMAP, the distroless
  proposal) now point at `kanywst`; entries under released versions
  keep the paths those releases actually shipped with.
- `.github/workflows/oci.yml` derives the image name from
  `$GITHUB_REPOSITORY`, so images built from the next tag publish to
  `ghcr.io/kanywst/zopa`. The existing `ghcr.io/0-draft/zopa` tags are
  untouched.

## [0.2.0] - 2026-05-10

Public surface still alpha. Existing v0.1 policies (single `allow`
target rule, flat request-side input) keep working unchanged: the
new body and response phases are opt-in via the matching rule
(`allow_body` / `allow_response`) appearing in the policy.

### Added

- AST node `call` plus four builtins: `startswith`, `endswith`,
  `contains`, `count`. Type errors and unknown names resolve to
  `nil` (deny in body position).
- `some` / `every` iteration over JSON objects via a new optional
  `kind` field (`"keys"` default, `"values"`).
- `Modules` bundle wrapper (`{"type": "modules", "modules": [...]}`)
  and an optional `package` field on `Module`.
- `proxy_on_request_body` evaluates `allow_body` against
  `{body, body_raw}` once end of stream is signalled. Body buffer
  cap: 64 KiB. Body parsed as JSON when possible; otherwise `body`
  is `null` and `body_raw` carries the bytes.
- `proxy_on_response_headers` evaluates `allow_response` against
  `{response: {status, headers}}`. Deny replaces the upstream
  response with a 503.
- New wasm exports `evaluate_target(input, ast, target_rule)` and
  `evaluate_addressed(input, ast, package, target_rule)` for hosts
  driving non-default rules without proxy-wasm.
- `src/body_deps.zig`: configure-time analyser that classifies a
  module's body references as `no_body_refs` / `prefix_only` /
  `full_tree`. Foundation for the streaming runtime; not wired into
  the proxy-wasm shim yet.
- `zig build bench`: Node-based latency benchmark over
  `bench/fixtures/`, reporting p50/p95/p99/mean.
- `zig build test-conformance`: drives `opa parse` →
  `tools/rego2ast.py` → zopa for each fixture in
  `test/conformance/fixtures/`. Six starter fixtures cover bool
  comparators, builtins, `every`, `not`, `count`, missing-path
  semantics.
- Distroless multi-arch OCI image at `ghcr.io/0-draft/zopa`,
  cosign-signed, built on every tag via
  `.github/workflows/oci.yml`.
- CI gains `test-unit`, `bench (smoke)`, and `test-conformance`
  jobs alongside the existing `build`, `test`, `test-wasmtime`, and
  the `lint` workflow's `zig-fmt` / `markdownlint` / `shellcheck`.

### Changed

- Public eval surface layered: `evaluate` is now a thin wrapper over
  `evaluateWithTarget`, which is a wrapper over `evaluateAddressed`.
  Behaviour at the `evaluate` entry point is unchanged.
- Missing path inside `compare` (and any other `resolveValue` site)
  now resolves to `Value.nil` rather than propagating
  `error.PathNotFound`. Aligns with Rego's "missing is undefined"
  semantics: a body using `input.user.role == "admin"` against `{}`
  now denies (0) instead of erroring (-1).
- `proxy_on_request_body` and `proxy_on_response_headers` short-
  circuit at configure time when their target rule (`allow_body`,
  `allow_response`) is absent from the policy. Detection is a
  substring match in the policy JSON. Pre-v0.2 callers with a
  request-only policy retain the v0.1 pass-through behaviour for
  the body and response phases.
- Release build size: ~50 KB → ~60 KB. The increase covers `call`,
  object iteration, the `Modules` bundle, the two new target-rule
  paths, and the body-deps analyser.

## [0.1.0] - 2026-05-07

First tagged release. Public surface (export names, AST schema,
callback semantics) is still alpha and may change before 1.0.

### Added

- Initial implementation: `wasm32-freestanding` build, ~50 KB
  release binary.
- In-tree JSON parser with surrogate-pair handling and zero-copy
  string aliasing.
- Per-request arena allocator with `retain_capacity` reset.
- Policy AST: `value`, `ref`, `compare` (`eq`/`neq`/`lt`/`lte`/`gt`/`gte`),
  `not`, `set`, `some`, `every`, `Module`, `Rule`.
- proxy-wasm 0.2.1 lifecycle exports: `proxy_on_vm_start`,
  `proxy_on_configure`, `proxy_on_context_create`,
  `proxy_on_request_headers`, `proxy_on_request_body` (no-op
  pending body-aware policy work), `proxy_on_response_headers`
  (no-op), `proxy_on_done`.
- Length-prefixed `malloc`/`free` exports compatible with
  proxy-wasm host buffer ownership conventions.
- Integration tests in Node, wasmtime, and a real Envoy
  (`zig build test`, `test-wasmtime`, `test-envoy`).
- Automated releases on `v*` tags with SLSA v1.0 build provenance and
  cosign keyless signatures. Each release attaches `zopa-<tag>.wasm`,
  `.sha256`, `.intoto.jsonl`, and `.sigstore.json`.

### Fixed

- README badges (CI, OpenSSF Scorecard) now resolve. They were left
  pointing at `kanywst/zopa` after the repo moved to `0-draft/zopa`.

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html
[Unreleased]: https://github.com/kanywst/zopa/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/kanywst/zopa/releases/tag/v0.3.0
[0.2.0]: https://github.com/kanywst/zopa/releases/tag/v0.2.0
[0.1.0]: https://github.com/kanywst/zopa/releases/tag/v0.1.0
