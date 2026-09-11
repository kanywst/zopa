# proxy-wasm 0.3.x support

Status: **Open, blocked upstream.** proxy-wasm 0.3.0 has not been cut — the milestone is still open with unresolved issues filed through mid-2026, and work continues in the `vNEXT` ABI directory rather than a release. The one concrete vNEXT change zopa already carries is `proxy_on_memory_allocate`, exported alongside `malloc` so the module loads on either generation of host. Chasing the rest before it stabilises buys nothing; see ROADMAP.md.
Tracking: ROADMAP.md → Longer term.

## Motivation

zopa implements proxy-wasm 0.2.1, which is what stable Envoy ships
today. The 0.3.x line of the spec is in active development at
[proxy-wasm/spec](https://github.com/proxy-wasm/spec) and brings:

- WIT-based ABI definitions (Component Model alignment).
- Cleaner buffer ownership (host-owned buffers with a borrow-style
  contract instead of malloc/free dance).
- Standardized error encoding for host calls.
- Lifecycle changes around plugin reconfiguration.

Hosts will eventually pick 0.3.x up. Migrating zopa late means a
period where the only release artifact won't load on hosts that have
moved on. Migrating too early means losing the Envoy / wamr
integration we already test against. The right move is a planned
dual-version window.

## Goals

1. Track upstream `proxy-wasm/spec` and trigger this work when 0.3.x
   stabilizes (a tagged final, or Envoy main begins shipping it).
1. Refactor `src/proxy_wasm.zig` to expose a single internal
   "evaluate-headers" entry, with two separate ABI shims:

   ```text
   src/proxy_wasm.zig            (internal: builds input, calls evaluate)
   src/proxy_wasm_v0_2_1.zig     (current; existing exports)
   src/proxy_wasm_v0_3_x.zig     (new; future exports)
   ```

1. The build emits a single binary that exports both ABI version
   markers (`proxy_abi_version_0_2_1` and `proxy_abi_version_0_3_x`).
   A host that recognizes either picks the matching set.
1. Drop the v0.2.1 shim only after at least 2 releases ship dual
   support and the changelog calls out the deprecation window.

## Non-goals

- Anticipating a draft of 0.3.x that hasn't stabilized. We don't
  guess at the surface area. The PR that lands this references a
  specific spec commit / tag and freezes against it.
- Component Model migration. WIT bindings produce identical wasm
  modules in the freestanding profile we use; we revisit if Component
  Model becomes the only way to load a filter.
- Breaking the AST. Policy AST schema is unaffected.

## Design sketch

### Refactor first, migrate later

Step 1 is a no-op refactor that moves the proxy-wasm shim's
input-building and decision-routing logic into a small internal
module. The current 0.2.1 shim stays as a thin adapter on top.

This isolates the version-specific surface (export names,
host-import signatures, buffer ownership rules) from the
version-agnostic policy-evaluation flow. Until the refactor lands,
adding a second ABI version multiplies a lot of code.

### Detect-then-route at the host

Hosts that load a wasm module advertise a single ABI version. zopa
exports both empty marker functions; the host picks one and only
calls into the matching set. This is how a few other proxy-wasm
modules handle the transition (e.g., `wasm-image-population` had a
similar dual-version window in 2024).

### Tests

`zig build test-envoy` continues to use 0.2.1 hosts.
`zig build test-envoy-0-3` (new) uses an Envoy build that ships
0.3.x once one exists, and runs the same scenario suite to assert
parity.

## API impact

- Two ABI version markers exported from the same wasm module.
- Internal-only refactor of the proxy-wasm shim.
- AST schema unchanged. `evaluate` (generic ABI) unchanged.

## Test plan

- All existing 0.2.1 tests continue to pass against the refactored
  shim.
- New conformance scenario: same Envoy bootstrap with the 0.3.x
  filter type, asserts the same allow/deny matrix.
- Long-running compatibility test: load the same wasm in a wamr-based
  test, then a v8-based test, then a wasmtime-based test, asserting
  decisions are identical.

## Open questions

- Trigger condition: do we wait for a 0.3.x final, or jump as soon as
  Envoy main begins shipping it? Probably the latter, since Envoy's
  `proxy-wasm-cpp-host` is the integration that matters most.
- Code-size budget: an extra version's worth of host import
  signatures and dispatch tables will grow `zopa.wasm`. We should
  measure and decide how much we're willing to add (target: stay
  under ~70 KB even with both versions, since the `--release=small`
  story is core to the project).
- Long-term: do we keep dual support permanently? Probably not;
  document a sunset policy alongside the dual-shim PR.
