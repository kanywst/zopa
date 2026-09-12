# Multiple policies per VM

Status: **Implemented.** Goals 1, 2 and 4 shipped in v0.2.0 (the `{"type": "modules"}` bundle, the optional `package` field, and `evaluate_addressed` for fully qualified lookup), and v0.3.0 made dispatch package-scoped. Goal 3 -- the `targets[]` plugin config with a per-target `on_deny` -- landed after v0.4.1: the proxy-wasm shim accepts a `{"policy": ..., "targets": [...]}` wrapper naming which `(package, rule)` pairs each phase evaluates and whether a deny enforces. The bare-AST configuration still works and still behaves identically. See [`docs/proxy-wasm.md`](../proxy-wasm.md). Tracking: ROADMAP.md → Medium term ("Multiple policies").

## Motivation

Today the plugin configuration is a single `module`, evaluated against a hard-coded target rule named `"allow"`. That's enough for one filter doing one job. Real deployments often want:

- Separate authn and authz rules in distinct, independently authored modules.
- An audit policy whose decision is "log this" rather than "block this", evaluated alongside the allow policy.
- Per-route policy bundles where the dispatch happens by package name, mirroring how OPA addresses rules as `data.<package>.<rule>`.

Stuffing all of those into one module loses the boundaries that make the policies maintainable.

## Goals

1. Plugin config accepts either a single module (current shape, still supported) or a list of modules:

   ```json
   { "modules": [
       { "package": "authz",  "type": "module", "rules": [ ... ] },
       { "package": "audit",  "type": "module", "rules": [ ... ] }
   ]}
   ```

1. Each `module` gains an optional `package` string. Defaults to `""` (the implicit single-module case).
1. The proxy-wasm shim grows a new plugin config field `targets[]` to pick which `package.rule` pairs are evaluated:

   ```yaml
   targets:
     - package: authz
       rule: allow
       on_deny: send_local_response_403
     - package: audit
       rule: log
       on_deny: noop  # decision is recorded out-of-band, not enforced
   ```

1. Evaluator gains a fully qualified rule lookup: `evalModule(modules, "authz.allow", input)` instead of just rule-by-name within a single module.

## Non-goals

- Cross-module data references (`data.audit.events` from inside an authz rule). Modules stay independent. If you need shared data, put it in `input`.
- Hot-reload of individual modules. Replace the full plugin config or reconfigure the filter; no per-module surgery.
- A package import system. There's no `import data.helpers` because there are no shared helpers.

## Design sketch

### AST builder

`src/ast.zig` gains a `Modules` (plural) container. The existing `Module` keeps its `rules` field plus an optional `package` slice.

### Evaluator

`evalModules(target_pkg, target_rule, input)`:

1. Find all modules whose `package` equals `target_pkg`.
1. Within those, OR-combine all rules whose name equals `target_rule`, reusing the existing `evalModule` body.
1. Apply the same `default` handling.

### Proxy-wasm shim

The `proxy_on_request_headers` callback iterates `targets[]`. For each:

- Evaluate `package.rule`.
- If decision is deny and `on_deny` is `send_local_response_403`, short-circuit immediately.
- If decision is recorded but not enforced (`on_deny: noop`), call `proxy_log` with a structured line, continue.

This makes "authz blocks, audit logs" a config decision, not a code decision.

### Config compatibility

A bare module (current shape, no `modules` wrapper) is wrapped into a synthetic single-element list with `package: ""` and a synthetic `targets[]` of `[{ package: "", rule: "allow", on_deny: send_403 }]`. Existing configs keep working unchanged.

## API impact

- New plugin config shape `modules[]` + `targets[]` (additive).
- New AST optional field `package` on `module` (additive).
- Existing single-module configs still work.

## Test plan

- Unit tests for `evalModules` covering: same package different rules, same rule different packages, missing package (returns deny by default).
- Integration test: two modules (`authz`, `audit`) with the audit policy logging-only.
- Envoy example: extend `examples/envoy/envoy.yaml` to demonstrate the audit-without-enforce target.

## Open questions

- Naming: `targets` vs `evaluations` vs `gates`? `targets` reads as "what to look for", which matches the existing single-target vocabulary.
- Should `on_deny: noop` be allowed without a matching `proxy_log` call, i.e., is silent "informational evaluation" useful? A flag-day decision; safer default is "log on every audit decision".
- Order of evaluation within `targets[]`: declaration order, or topologically (audit always before allow)? Declaration order is simpler and documentable.
