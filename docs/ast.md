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

Evaluation runs every rule whose `name` matches the target rule
(default `"allow"`). Rules that hold and agree on a value produce that
decision; rules that hold and disagree are a conflict, not a race that
the earlier one wins. See [Rule dispatch](#rule-dispatch) for the
details, which matter once a package spans several modules. A bare
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

1. Every non-default rule is evaluated. Each one whose `body` holds
   contributes its `value` (defaulting to boolean `true`).
2. If the satisfied rules all contribute the same value, that value is
   the decision. If two contribute *different* values, the result is an
   error (`-1`), which every caller treats as deny.
3. If no non-default rule holds, the `default` rule's `value` decides.
   A `default` declared in any module of the package covers the whole
   package -- not just the module it appears in.
4. If there is neither, the decision is deny.

The package-wide part matters. In Rego a package split across files is
one rule set, so `default allow = false` in one file governs
`allow if ...` in another. Evaluating each module in isolation and
OR-ing the results gets this wrong twice: the default would only cover
its own module, and an early module returning `true` would short-circuit
past a later module's explicit `"value": false` deny.

The conflict part matters just as much. `allow` is a *complete* rule,
and OPA rejects a complete rule that produces two outputs at once:

```console
$ opa eval -d policy.rego -I 'data.authz.allow' <<< '{"tenant":"acme","role":"banned"}'
{"errors":[{"message":"complete rules must not produce multiple outputs",
            "code":"eval_conflict_error", ...}]}
```

Rego does not resolve that by source order, so neither does zopa.
Picking whichever definition came first in the bundle would make the
decision depend on file layout -- which carries no meaning in Rego and
changes when modules are reordered, split, or renamed -- and would let
zopa answer `allow` where OPA refuses to answer at all.

Definitions that agree are fine, which is what makes the ordinary
`allow if A` / `allow if B` shape work:

```json
{ "type": "module", "rules": [
  { "type": "rule", "name": "allow", "default": true,
    "value": { "type": "value", "value": false } },

  { "type": "rule", "name": "allow", "body": [ ...A... ] },
  { "type": "rule", "name": "allow", "body": [ ...B... ] }
]}
```

A `default` never conflicts with a regular rule: it is a fallback, not
a competing definition. Two `default` declarations for the *same* rule
are a different matter -- OPA rejects them when it compiles the policy
(`rego_type_error: multiple default rules data.authz.allow found`), and
zopa rejects the AST at build time with the same reasoning it applies
to conflicting rules: keeping the last one would make the fallback
depend on bundle ordering, and a fallback only shows up on the requests
where nothing else matched, so the divergence would be quiet. On the
proxy-wasm path that surfaces as a configuration failure; through the
generic exports it is `-1`. So the deny-override shape below is well defined
no matter where the rules sit, and it is what the `allow_response` and
`allow_body` phases use:

```json
{ "type": "module", "rules": [
  { "type": "rule", "name": "allow_response", "default": true,
    "value": { "type": "value", "value": true } },

  { "type": "rule", "name": "allow_response",
    "body": [ { "type": "gte",
      "left":  { "type": "ref", "path": ["input", "response", "status"] },
      "right": { "type": "value", "value": 500 } } ],
    "value": { "type": "value", "value": false } }
]}
```

What you cannot do is write two *non-default* rules that disagree and
expect one of them to win. Express the override against the default
instead, or narrow the bodies so they cannot both hold.

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
