# OPA conformance harness

Walks `test/conformance/fixtures/*.json` and verifies that each one, when fed through `opa parse` + `tools/rego2ast.py`, evaluates the same way zopa does.

## Layout

```text
test/conformance/
  README.md
  run.py                      # driver
  fixtures/
    01_static_allow.json
    02_role_admin.json
    03_startswith_path.json
    04_not_banned.json
    05_every_keys.json
    06_count_perms.json
```

Each fixture is a JSON object:

```json
{
  "name":  "<short slug>",
  "rego":  "<full Rego source>",
  "cases": [
    { "input": { ... }, "expected": 1 },
    { "input": { ... }, "expected": 0 }
  ]
}
```

`expected` is the int returned by zopa's `evaluate` export: `1` allow, `0` deny, `-1` error.

## Running

```bash
zig build test-conformance
```

Or directly:

```bash
zig build --release=small         # produces zig-out/bin/zopa.wasm
.venv-test/bin/python test/conformance/run.py
```

Requires:

- `opa` CLI on PATH (`brew install opa` / `go install github.com/open-policy-agent/opa@latest`)
- `wasmtime` Python module (`pip install -r test/requirements.txt`)

## Outcomes

| Marker | Meaning                                                               |
| ------ | --------------------------------------------------------------------- |
| `PASS` | zopa's decision matches the fixture                                   |
| `SKIP` | `rego2ast` bailed (unsupported Rego node) -- recorded, not a failure  |
| `FAIL` | wrong decision, or `rego2ast` / `opa parse` errored                   |

Exit code is non-zero on any FAIL. SKIP is informational so that new fixtures exercising features we haven't taught the walker yet can sit alongside passing ones.

## Walker scope (v1)

`tools/rego2ast.py` covers:

- `default <rule> = <literal>`
- `<rule> if <body>` with comparator builtins `==` / `!=` / `<` / `<=` / `>` / `>=`
- `not <expr>`
- `every <var> in <ref> { <expr> }` (single-expression body)
- builtins `startswith`, `endswith`, `contains`, `count`
- bare ref / value literal in body position

Out of scope (rejected with a clear `Unsupported` error so the case SKIP s):

- user-defined functions
- `with` overrides
- partial evaluation
- multi-statement `every` bodies
- `some <var> in ...` (bridged via two body statements; merging is a walker rewrite to be added in v2)
- comprehensions (`[x | x := arr[_]]`)
- numeric ref segments (array indexing)

When you add a fixture that hits one of the unsupported nodes, the runner prints `SKIP` with the exact reason from the walker. That is the signal to either expand `rego2ast.py` or restructure the policy.
