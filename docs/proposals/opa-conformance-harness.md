# OPA conformance harness

Status: **Implemented.** Shipped in v0.2.0: `tools/rego2ast.py` converts `opa parse --format json` output into zopa's AST, and `zig build test-conformance` drives rego → `opa parse` → rego2ast → zopa over `test/conformance/fixtures/` (ten fixtures as of v0.3.1). Rego the converter cannot express makes it bail with `Unsupported`, which the runner records as SKIP rather than FAIL — so the harness also doubles as the coverage ledger this document asked for. Tracking: ROADMAP.md → Near term ("AST conformance harness").

## Motivation

The README says "Use OPA's compiler to produce" the AST. In practice there is no working bridge yet:

- `opa parse` emits the full Rego AST in OPA's own JSON shape, not zopa's. Today this requires a hand-written subset converter; none ships.
- We have no automated way to know which Rego inputs zopa handles correctly. Every claim about "Rego-shaped" coverage is anecdotal.

This proposal adds the missing bridge plus a CI-driven coverage report, so we can replace "Rego-shaped subset" with "passes X of Y official OPA test cases".

## Goals

1. A small Rego → zopa AST transformer (Go program in `tools/rego2ast/`) that:
   - Imports `github.com/open-policy-agent/opa` as a library.
   - Calls `ast.ParseModule` to get OPA's AST.
   - Walks it and emits zopa-shaped JSON (`module` / `rule` / `compare` / `ref` / `value` / `not` / `set` / `some` / `every`).
   - Emits a structured error when it hits a node zopa doesn't support (function definitions, builtins, partial eval, `with`, etc).
1. A conformance runner (Python in `test/conformance/`) that:
   - Clones / vendors the upstream OPA test corpus (`github.com/open-policy-agent/opa/topdown/testdata`).
   - For each test case: feeds the Rego through `rego2ast`, runs the resulting AST through `evaluate` against the test input, compares against OPA's expected output.
   - Outputs `coverage.json` with PASS / SKIP-unsupported / SKIP-needs-builtin / FAIL counts.
1. A CI job that fails when total PASS regresses vs the committed `coverage.json` baseline.

## Non-goals

- Full Rego support. The harness will skip cases that hit unsupported nodes (functions, builtins outside the planned set, `with`, partial eval). Skipped is honest; failing silently is not.
- Generating a Rego compiler in Zig. We piggyback on OPA's parser and emit JSON.
- Replacing OPA's official conformance suite. We mirror the public fixtures.

## Design sketch

### `tools/rego2ast/`

```text
tools/rego2ast/
  go.mod
  main.go              # CLI: rego2ast < module.rego > module.json
  internal/walker/     # OPA AST → zopa AST conversion
  internal/walker/walker_test.go
```

Conversion table (initial):

| OPA AST node           | zopa AST node                                                |
| ---------------------- | ------------------------------------------------------------ |
| `Module`               | `module`                                                     |
| `Rule` (default)       | `rule` with `default: true` and a literal `value`            |
| `Rule` (regular)       | `rule` with `body[]`                                         |
| `Expr` (`==` / `!=` …) | `compare` with matching `op`                                 |
| `Ref`                  | `ref` (with leading `input.` segment dropped)                |
| `Term` literal         | `value`                                                      |
| `Some`                 | `some` (variable + iterated source)                          |
| `Every`                | `every`                                                      |
| `Negation`             | `not`                                                        |
| `Call` (any function)  | error: unsupported (until `string-builtins.md` lands)        |
| `With`                 | error: unsupported                                           |

### `test/conformance/`

```text
test/conformance/
  __init__.py
  fetch_corpus.py     # vendors a pinned OPA test corpus
  run.py              # iterates fixtures, calls rego2ast + zopa, reports
  coverage.json       # checked in, updated by run.py
  README.md
```

Sample `coverage.json`:

```json
{
  "opa_ref": "v0.71.0",
  "total":   2148,
  "pass":    687,
  "skip_unsupported": 1304,
  "skip_needs_builtin": 142,
  "fail":    15,
  "first_fail_seqs": ["topdown/some_every/0042", "..."]
}
```

## API impact

None for the wasm artifact. New tooling under `tools/` and `test/conformance/`.

## Test plan

- Unit tests for `tools/rego2ast/internal/walker` covering each conversion in the table above.
- The conformance runner itself is the integration test.
- CI gates on `coverage.json.pass` not regressing.

## Open questions

- Pin OPA version or follow latest? Pinning gives reproducibility; following latest catches Rego language changes early. Probably pin with a renovate-style update job.
- `rego2ast` in Go vs Rust? Go is the natural choice (uses OPA as a library). Rust could use `regorus`, but adds a second moving part.
- How to surface coverage publicly? A badge on the README sourced from `coverage.json` is the minimum useful thing.
