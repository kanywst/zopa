# zopa as an AuthZEN evaluation core

[OpenID AuthZEN Authorization API 1.0][spec] became an OpenID Final Specification on 12 January 2026. It standardises the wire format between a Policy Enforcement Point (PEP) and a Policy Decision Point (PDP), so a PEP can be pointed at any compliant PDP without knowing how it decides.

zopa is not an AuthZEN server -- it has no HTTP surface, by design. What it is is the part in the middle: a ~60 KB decision function that takes a JSON document and returns allow/deny. An AuthZEN Access Evaluation request *is* that JSON document, so the mapping needs no adapter code.

This page documents the mapping and the one edge that isn't a mapping (the error case).

## Request mapping

An AuthZEN Access Evaluation request is posted to `/access/v1/evaluation`:

```json
{
  "subject":  { "type": "user", "id": "alice@example.com" },
  "resource": { "type": "account", "id": "123" },
  "action":   { "name": "can_read", "properties": { "method": "GET" } },
  "context":  { "time": "1985-10-26T01:22-07:00" }
}
```

Hand that body to zopa unchanged as the `input` argument. The four top-level fields become the ref paths a policy addresses:

| AuthZEN field           | zopa ref path                                |
| ----------------------- | -------------------------------------------- |
| `subject.type`          | `["input", "subject", "type"]`               |
| `subject.id`            | `["input", "subject", "id"]`                 |
| `subject.properties.*`  | `["input", "subject", "properties", "..."]`  |
| `resource.type`         | `["input", "resource", "type"]`              |
| `resource.id`           | `["input", "resource", "id"]`                |
| `action.name`           | `["input", "action", "name"]`                |
| `context.*`             | `["input", "context", "..."]`                |

Nothing is reserved and nothing is rewritten: zopa treats the input as an opaque JSON tree, so a request carrying additional fields keeps them addressable.

## Response mapping

`evaluate` returns an `i32`. The PDP wrapper turns it into the response body:

| zopa returns | Meaning                        | AuthZEN response         |
| ------------ | ------------------------------ | ------------------------ |
| `1`          | allow                          | `{"decision": true}`     |
| `0`          | deny                           | `{"decision": false}`    |
| `-1`         | evaluation error               | `{"decision": false}`    |

The `-1` row is the part worth being deliberate about. AuthZEN's `decision` is a boolean with no third state, so an evaluation error has to become one of the two. It must become `false`. An unparseable input or a policy that trips the recursion guard is not a grant, and a PDP that answers `true` when it failed to decide is a PDP that fails open. Log the `-1` separately so the failure is visible; the *response* still denies.

Nothing stops a wrapper from filling in the optional `context.reason_user` field on a denial, but zopa itself returns a decision, not a reason -- see "Limits" below.

## Example policy

The Rego a PDP would compile:

```rego
package authz

default allow = false

allow if {
    input.subject.type == "user"
    input.action.name == "can_read"
    input.resource.type == "account"
}
```

Compiled to zopa's AST (via `opa parse --format json` piped through `tools/rego2ast.py`):

```json
{
  "type": "module",
  "package": "authz",
  "rules": [
    {
      "type": "rule",
      "name": "allow",
      "default": true,
      "value": { "type": "value", "value": false }
    },
    {
      "type": "rule",
      "name": "allow",
      "body": [
        {
          "type": "eq",
          "left":  { "type": "ref", "path": ["input", "subject", "type"] },
          "right": { "type": "value", "value": "user" }
        },
        {
          "type": "eq",
          "left":  { "type": "ref", "path": ["input", "action", "name"] },
          "right": { "type": "value", "value": "can_read" }
        },
        {
          "type": "eq",
          "left":  { "type": "ref", "path": ["input", "resource", "type"] },
          "right": { "type": "value", "value": "account" }
        }
      ]
    }
  ]
}
```

This exact policy and four request bodies are checked end to end in `test/conformance/fixtures/09_authzen_evaluation.json`, which runs `opa parse` over the Rego, converts it, and asserts zopa's decision on every CI run.

## Multiple resources in one VM

A PDP that serves several policy domains can load them as a `Modules` bundle and dispatch per request with the `evaluate_addressed(input, ast, package, rule)` export, keeping one wasm instance for all of them. See [`ast.md`](ast.md) for the bundle shape.

## Limits

Be honest with your users about where this stops:

- **No HTTP layer.** zopa gives you the decision function. The endpoint, discovery metadata (`/.well-known/authzen-configuration`), authentication, and transport are the wrapper's job.
- **No Search API.** AuthZEN's subject/resource/action Search endpoints ask "which resources can this subject act on", which is an enumeration problem, not a decision problem. zopa answers one question at a time.
- **No reasons.** The engine returns a boolean. Populating `context.reason_user` means the wrapper has to know why, which zopa does not tell it.
- **Rego subset.** zopa evaluates a compiled AST covering the subset in [`ast.md`](ast.md), not the full Rego language. A policy that needs the rest belongs in OPA.

[spec]: https://openid.net/specs/authorization-api-1_0.html
