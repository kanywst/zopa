# Changelog

All notable changes are recorded here. Format follows
[Keep a Changelog][kac]; releases follow [Semantic Versioning][semver]
once the first stable tag ships.

## [Unreleased]

### Changed

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

[0.2.0]: https://github.com/kanywst/zopa/releases/tag/v0.2.0

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
[Unreleased]: https://github.com/kanywst/zopa/compare/v0.2.0...HEAD
[0.1.0]: https://github.com/kanywst/zopa/releases/tag/v0.1.0
