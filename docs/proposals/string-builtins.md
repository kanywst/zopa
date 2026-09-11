# String and collection builtins

Status: **Implemented.** The `call` node and all four builtins — `startswith`, `endswith`, `contains`, `count` — shipped in v0.2.0 and live in `src/builtins.zig`. Type errors and unknown names resolve to `nil`, which denies in body position. Kept for the reasoning; see `docs/ast.md` for the node schema. Tracking: ROADMAP.md → Medium term ("Function calls").

## Motivation

Equality + iteration covers a useful slice of authorization rules but falls down on the most common string tests:

- "path starts with `/admin/`"
- "user-agent contains `Bot`"
- "host ends with `.internal`"
- "list of granted scopes has at least 3 entries"

Today these need to be pre-computed by the host (split the string before handing it to zopa), or expressed as awkward equality chains. That pushes policy logic out of the policy and into the host.

A small, fixed set of builtins lets these be expressed in the AST without opening the floodgates to user-defined functions or arbitrary imports.

## Goals

1. New AST node type `call`:

   ```json
   {
     "type": "call",
     "name": "startswith",
     "args": [
       { "type": "ref", "path": ["input", "path"] },
       { "type": "value", "value": "/admin/" }
     ]
   }
   ```

   Returns a `Value`. In body position it must resolve to boolean, matching the rest of zopa's evaluator contract.

1. Initial set of builtins (Rego-compatible names and arities):

   | Name         | Arity | Args                         | Returns |
   | ------------ | ----- | ---------------------------- | ------- |
   | `startswith` | 2     | (string, string)             | boolean |
   | `endswith`   | 2     | (string, string)             | boolean |
   | `contains`   | 2     | (string, string)             | boolean |
   | `count`      | 1     | (array, set, object, string) | number  |
   | `lower`      | 1     | (string)                     | string  |
   | `upper`      | 1     | (string)                     | string  |

   `lower` / `upper` are tentative (case-insensitive comparisons are a common ask). Lock the v1 set in the PR review before implementation.

1. Type errors during evaluation are non-fatal: `count(undefined)` returns undefined, treated as `false` in body position. This matches Rego's "missing path is undefined" deny-by-default posture.

## Non-goals

- User-defined functions. Stays out until there's a clear need that builtins can't cover.
- Regex. Compiling a regex inside the wasm runtime is far more code than the rest of the evaluator combined; revisit if a real ask appears.
- Arbitrary OPA stdlib (string formatting, time, JSON encode/decode, cryptography). Each adds a separate code-size budget. The list above is intentionally minimal.

## Design sketch

### Code layout

A new file `src/builtins.zig` with one function per builtin, plus a small dispatch table:

```zig
const Builtin = struct {
    name: []const u8,
    arity: u32,
    impl: *const fn (
        args: []const json.Value,
        arena: std.mem.Allocator,
    ) BuiltinError!json.Value,
};

const table = [_]Builtin{
    .{ .name = "startswith", .arity = 2, .impl = startswith },
    .{ .name = "endswith",   .arity = 2, .impl = endswith },
    .{ .name = "contains",   .arity = 2, .impl = contains },
    .{ .name = "count",      .arity = 1, .impl = count },
    .{ .name = "lower",      .arity = 1, .impl = lower },
    .{ .name = "upper",      .arity = 1, .impl = upper },
};
```

`lower` / `upper` allocate the result on the per-request arena. String args are aliased into the input bytes (no copy) where possible.

### Evaluator integration

`src/eval.zig` gains a `call` case in `resolveValue`:

```zig
.call => |c| try evalCall(c, input, scope, depth + 1),
```

`evalCall` resolves each arg, looks up the builtin by name, and calls `impl`. Unknown name → `error.UnsupportedNode` → `-1` from `evaluate`, treated as deny.

### AST builder

`src/ast.zig` gains a `Call` variant on `Expr` and a builder that validates `name` is a string and `args` is an array.

## API impact

- New AST type `call`. Backward compatible (additive).
- No new exports / imports.

## Test plan

- Unit tests per builtin in `src/builtins.zig` (happy path + type mismatch + empty args).
- Integration tests in `test/run.mjs` exercising each builtin in body and value position.
- Conformance harness picks up additional Rego cases as the table grows.

## Open questions

- Lock the v1 set: do we ship `lower` / `upper` immediately or defer? Argument for deferring: every builtin is permanent surface area.
- Naming: stay 1:1 with Rego (`startswith`, no underscore) for conformance harness compatibility, even though it reads oddly.
- Do we accept Rego's three-arg variant of `contains` (substring with start-index) or trim to two? Two is simpler; three matches Rego.
- Type error policy: silent `undefined` (deny-friendly) vs `error.TypeMismatch` (loud, surfaces bugs in CI but drops requests in prod).
