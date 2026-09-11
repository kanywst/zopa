# Composite ref iteration

Status: **Partially implemented.** Goal 1 shipped in v0.2.0 as the optional `kind` field on `some` / `every` — but `keys` and `values` only. `pairs` was never built: `Expr.IterKind` has two variants (`src/ast.zig`). **Goals 2 and 3 are still open** — there are no fixtures walking a `set`-typed value through a ref, and there is no `in` node, so membership still has to be written as a `some`.
Tracking: ROADMAP.md → Medium term ("Set/object refs").

## Motivation

`some` and `every` already accept `ref` sources for arrays and sets
(see `iterItems` in `src/eval.zig:191`). What's missing:

1. **Objects (maps).** A ref that resolves to a JSON object is not
   currently iterable. `iterItems` returns `null`, which becomes deny
   in body position. There's no way to write "every key in
   `input.user.attributes` matches some predicate".
1. **Set ref pairs.** A ref into a value tree where the leaf was
   originally produced by `set` (rather than a JSON array) needs
   first-class equality and membership rules. Today `set` literals
   work; refs into stored sets are less exercised.
1. **Membership on the right of `compare`.** "X is in this composite"
   requires `some` today, even when a direct `in` comparator would
   read better.

These are common in real Rego. Without them, hand-written zopa AST
ends up flattening data the host already has structured.

## Goals

1. Extend `iterItems` to handle JSON objects:
   - Iterate the **keys** by default.
   - Allow `kind: "values"` or `kind: "pairs"` opt-in via a new
     optional field on `some` / `every` to iterate values or
     `[key, value]` tuples.
1. Confirm and test ref-to-set semantics end to end. Add fixtures that
   stash a `set`-typed value under `input.*` (via the host) and walk
   it.
1. Add a new AST shorthand `in` for membership:

   ```json
   { "type": "in",
     "left":  { "type": "ref", "path": ["input", "tenant"] },
     "right": { "type": "ref", "path": ["input", "allowed_tenants"] } }
   ```

   which desugars to `some x in right: x == left`.

## Non-goals

- Generic comprehensions (`[ x | x := input.users[_]; x.active ]`).
  Out of scope for v1; revisit after string-builtins lands.
- Object destructuring. Iteration is over scalar keys / values; nested
  destructuring stays the caller's job.
- Indexing semantics. zopa keeps Rego's "missing path is undefined,
  body=false" stance.

## Design sketch

### Updated `iterItems`

```zig
const IterKind = enum { keys, values, pairs };

fn iterItems(
    source: *const ast.Expr,
    kind: IterKind,
    input: json.Value,
    scope: ?*const Scope,
    depth: u32,
) HelperError!?[]const json.Value {
    const v = try resolveValue(source, input, scope, depth);
    return switch (v) {
        .array => |xs| xs,
        .set   => |xs| xs,
        .object => |obj| switch (kind) {
            .keys   => projectKeys(obj),
            .values => projectValues(obj),
            .pairs  => projectPairs(obj),
        },
        else => null,
    };
}
```

`projectKeys` / `projectValues` / `projectPairs` allocate on
`request_arena`, so they survive only the current evaluation.

### Updated AST schema

`some` / `every` gain an optional `kind` field:

```json
{
  "type": "every", "var": "k", "kind": "keys",
  "source": { "type": "ref", "path": ["input", "user", "attributes"] },
  "body": { "type": "compare", "op": "neq",
            "left":  { "type": "ref", "path": ["k"] },
            "right": { "type": "value", "value": "internal" } }
}
```

Default is `keys`, matching the principle of least surprise for "for
each entry in this object".

### `in` shorthand

Pure desugaring at AST build time. No new evaluator path.

## API impact

- New optional field `kind` on `some` / `every`. Backward compatible
  (omitting it preserves current array/set behavior; objects flip
  from "deny" to "iterate keys").
- New AST type `in`. Backward compatible (additive).

## Test plan

- Unit tests in `src/eval.zig` covering each `kind` over an object
  source.
- Conformance harness (see `opa-conformance-harness.md`) gains
  fixtures that exercise the new iteration semantics.
- Negative test: a ref that resolves to a scalar still returns
  `false` in body position, not an error.

## Open questions

- Should `kind` default to `keys` or be required when the source is
  an object? Required is safer (no behavior flip on existing policies
  that didn't expect object support); default is more ergonomic.
- Order: Rego treats object iteration as unordered. zopa should match
  but tests must not depend on order. Worth a fuzz test that shuffles.
- Does `in` deserve to become a first-class evaluator path for
  performance, instead of pure desugaring?
