# Policy AST reference

zopa's AST is plain JSON. Every node is an object with a `type` field
and node-specific properties. The shape mirrors a useful subset of
Rego.

## Module

A complete policy:

```json
{
  "type": "module",
  "package": "authz",
  "rules": [ <Rule>, ... ]
}
```

| Field     | Meaning                                                                                                              |
| --------- | -------------------------------------------------------------------------------------------------------------------- |
| `rules`   | Required. List of `Rule` objects.                                                                                    |
| `package` | Optional. Default `""`. Used by `Modules` bundles (below) to address a specific module via `(package, target_rule)`. |

Evaluation walks every rule whose `name` matches the target rule
(default `"allow"`), in declaration order, and the first one whose body
holds decides. See [Rule dispatch](#rule-dispatch) for the exact
ordering, which matters once a package spans several modules. A bare
expression at the top level (without `"type": "module"`) is wrapped
into a synthetic `allow` rule -- handy for tests and small policies.

## Modules bundle

A wrapper that lets a single VM hold more than one module:

```json
{
  "type": "modules",
  "modules": [
    { "type": "module", "package": "authz", "rules": [ ... ] },
    { "type": "module", "package": "audit", "rules": [ ... ] }
  ]
}
```

The host dispatches into a specific package via `evaluate_addressed`
or `evaluateAddressed`. The default `evaluate` entry implicitly
targets package `""` + rule `"allow"`.

A bare `Module` (or bare expression) is treated as a one-element
bundle with `package = ""` -- existing single-module configs keep
working unchanged.

## Rule

```json
{
  "type": "rule",
  "name": "allow",
  "default": false,
  "body":  [ <Expr>, ... ],
  "value": <Expr>
}
```

| Field     | Meaning                                                                                                                  |
| --------- | ------------------------------------------------------------------------------------------------------------------------ |
| `name`    | Required. The rule name to dispatch against.                                                                             |
| `default` | Optional, default `false`. When true, this rule's `value` is the fallback when no other rule with the same name fires.   |
| `body`    | Optional. Implicit AND of expressions. Every entry must evaluate truthy for the rule to fire. Empty body = always fires. |
| `value`   | Optional. Resolved when the body fires. Defaults to boolean `true`. Non-boolean values are treated as truthy.            |

## Rule dispatch

Given a target `(package, rule)`, evaluation collects the rules named
`rule` from **every module in the bundle whose `package` matches**, in
bundle order, and treats them as one rule set. Then:

1. The first non-default rule whose `body` holds decides. Its `value`
   is resolved and coerced to a decision; no later rule runs.
2. If no non-default rule holds, the `default` rule's `value` decides.
   A `default` declared in any module of the package covers the whole
   package -- not just the module it appears in.
3. If there is neither, the decision is deny.

The package-wide part matters. In Rego a package split across files is
one rule set, so `default allow = false` in one file governs
`allow if ...` in another. Evaluating each module in isolation and
OR-ing the results gets this wrong twice: the default would only cover
its own module, and an early module returning `true` would short-circuit
past a later module's explicit `"value": false` deny.

Ordering is the contract. A rule that fires wins outright, including
when its `value` is `false` -- that is how a deny-override rule is
written:

```json
{ "type": "modules", "modules": [
  { "type": "module", "package": "authz", "rules": [
    { "type": "rule", "name": "allow", "default": true,
      "value": { "type": "value", "value": true } } ] },

  { "type": "module", "package": "authz", "rules": [
    { "type": "rule", "name": "allow",
      "body": [ { "type": "eq",
        "left":  { "type": "ref", "path": ["input", "user", "role"] },
        "right": { "type": "value", "value": "banned" } } ],
      "value": { "type": "value", "value": false } } ] }
]}
```

Put deny-override rules ahead of the rules they need to override.

## Expressions

### `value` -- literal

```json
{ "type": "value", "value": <JSON value> }
```

`<JSON value>` is any JSON scalar or composite. Composites (arrays,
objects) are projected to internal `Value` form.

### `ref` -- path lookup

```json
{ "type": "ref", "path": ["input", "user", "role"] }
```

Refs walk the active scope chain first, then the input root. A
leading `"input"` segment is stripped (it just names the input root,
matching Rego's convention).

A missing path is *undefined*, treated as `false` in body position --
deny-by-default.

### `compare` -- binary comparison

```json
{
  "type": "compare",
  "op":   "eq" | "neq" | "lt" | "lte" | "gt" | "gte",
  "left":  <Expr>,
  "right": <Expr>
}
```

Equality (`eq` / `neq`) works on every value kind. Order operators
(`lt` / `lte` / `gt` / `gte`) work on numbers and strings; mixed
types compare as `false`.

Shorthand: any of the op names as the `type` directly.

```json
{ "type": "eq", "left": ..., "right": ... }
```

is identical to

```json
{ "type": "compare", "op": "eq", "left": ..., "right": ... }
```

### `not` -- negation

```json
{ "type": "not", "expr": <Expr> }
```

Boolean negation of the inner expression.

### `set` -- set literal

```json
{ "type": "set", "items": [ <JSON value>, ... ] }
```

Used as the `source` of a `some` / `every`, or as a literal compared
for equality. Order doesn't matter; duplicates are preserved but
ignored by equality.

### `some` -- existential

```json
{
  "type": "some",
  "var":  "x",
  "kind": "keys" | "values",
  "source": <Expr>,
  "body":   <Expr>
}
```

Resolves `source` to an array, set, or object, then evaluates
`body` once for each element with `x` bound. True iff any
iteration's body holds. An empty source yields `false`.

`kind` only matters when `source` resolves to a JSON object. With
`"keys"` (the default), `x` binds to each key as a string; with
`"values"`, to each member's value. Arrays and sets ignore `kind`
and bind elements directly.

### `every` -- universal

```json
{
  "type": "every",
  "var":  "x",
  "kind": "keys" | "values",
  "source": <Expr>,
  "body":   <Expr>
}
```

Same shape as `some`, but the body must hold for every element.
An empty source yields `true` (vacuous). `kind` works as for
`some`.

### `call` -- builtin function

```json
{
  "type": "call",
  "name": "startswith",
  "args": [ <Expr>, <Expr>, ... ]
}
```

Invokes one of the builtin functions on its resolved arguments and
folds the result back into a `Value`. Type mismatches resolve to
`nil` (treated as falsy / undefined in body position), matching
Rego's missing-path posture.

| Name         | Arity | Args                         | Returns |
| ------------ | ----- | ---------------------------- | ------- |
| `startswith` | 2     | (string, string)             | boolean |
| `endswith`   | 2     | (string, string)             | boolean |
| `contains`   | 2     | (string, string)             | boolean |
| `count`      | 1     | (array, set, object, string) | number  |

The argument cap is 8 (`max_builtin_args` in `src/eval.zig`); calls
beyond that resolve to `nil`. Unknown builtin names also resolve to
`nil`.

## Decision encoding

`evaluate(input, ast)` returns a single `i32`:

| Code | Meaning                                                                     |
| ---- | --------------------------------------------------------------------------- |
| `1`  | Allow. The target rule fired with a truthy value.                           |
| `0`  | Deny. No rule fired and no truthy default rule.                             |
| `-1` | Error. Parse failure, unknown node type, recursion cap, etc. Treat as deny. |

## JSON strictness

zopa reads the same bytes as the service behind the proxy. Anywhere the
two parsers could disagree about a document is a place to make a policy
read one value while the backend reads another, so the parser is
deliberately strict and deliberately conventional:

- **Numbers follow the RFC 8259 grammar exactly.** `01`, `1.`, `.5`,
  `+1`, `1e`, and `1_000` are all rejected, matching Go, JavaScript, and
  OPA. A document containing one fails to parse and the decision is
  `-1`, i.e. deny.
- **Duplicate object keys resolve last-wins.** `{"role":"admin",
  "role":"guest"}` means `guest`, which is what Go's `encoding/json` and
  `JSON.parse` do.
- **Control bytes below `0x20` must be escaped**, per the spec. The
  proxy-wasm shim escapes them when it synthesises input from headers,
  so a header carrying a raw control byte can't produce a document zopa
  then refuses.
- **Lone surrogates are rejected**; valid surrogate pairs decode to the
  non-BMP code point.

## Limits

- Maximum JSON nesting depth: 64.
- Maximum evaluation recursion depth: 32 (`compare` / `not` / `some` /
  `every` / `resolveValue`).
- Maximum request body buffered by the proxy-wasm shim: 64 KiB. A body
  over the cap denies when the policy reads the body -- see
  [`proxy-wasm.md`](proxy-wasm.md).

The limits are constants in the source -- bump them if you have a
documented need.
