# Contributing

Thanks for considering a contribution. zopa is small enough that
nothing here should surprise you.

## Before you start

- Open an issue first if the change is non-trivial. It's faster than
  rewriting a PR after maintainer feedback.
- For typo fixes, comment polish, or one-line bug fixes, just open
  the PR.

## Local setup

You need Zig 0.16.0, Node 22+, and Python 3.12+.

```bash
zig build           # builds zig-out/bin/zopa.wasm
zig build test      # runs the Node integration suite
```

For the optional wasmtime suite:

```bash
python3 -m venv .venv-test
.venv-test/bin/pip install -r test/requirements.txt
zig build test-wasmtime
```

For the optional Envoy end-to-end check (requires `brew install envoy`
or equivalent, with the `wamr` runtime built in):

```bash
zig build test-envoy
```

If your Envoy ships V8 rather than wamr -- the upstream release binary
does -- set the runtime:

```bash
ZOPA_ENVOY_RUNTIME=envoy.wasm.runtime.v8 zig build test-envoy
```

`zig build test-all` runs every suite that's available on the host.

## Where a test belongs

Pick the layer that would actually catch a regression:

| Change                                                                      | Test goes in                              |
| --------------------------------------------------------------------------- | ----------------------------------------- |
| Parser, AST builder, evaluator semantics                                    | `src/*.zig` unit tests                    |
| Anything a host calls across the wasm boundary                              | `test/run.mjs` and `test/run_wasmtime.py` |
| proxy-wasm behaviour: phases, buffering, local responses, configure failure | `examples/envoy/run.sh`                   |
| Rego-facing behaviour and `tools/rego2ast.py` coverage                      | `test/conformance/fixtures/`              |

`examples/envoy/run.sh` is the only suite that exercises the shim.
The other three call `evaluate` directly and would keep passing with a
completely broken proxy-wasm layer, so a change to `src/proxy_wasm.zig`
that isn't covered there isn't covered at all.

Two habits worth keeping. Write the test so it fails for the reason
you think it does -- the oversized-body case in `run.sh` uses a payload
that would be *allowed* if zopa saw all of it, so a pass can only mean
the truncation check fired. And when you touch `src/wire.zig` or
`src/json.zig`, add a case to the matching fuzz test rather than only a
fixed example.

## Fuzzing

`src/json.zig`, `src/eval.zig`, and `src/wire.zig` carry
`std.testing.fuzz` targets over the three surfaces that take hostile
bytes: the JSON parser, end-to-end evaluation, and the proxy-wasm
header-map decoder. They run as single-iteration smoke tests during a
normal `zig build test-unit`.

Running them as actual fuzzers (`zig build test-unit --fuzz`) does not
work on Zig 0.16.0: the toolchain's own `compiler/test_runner.zig`
fails to compile in fuzz mode with a `StackTrace` type mismatch. That
is upstream, not something this repository can fix. The targets are
written so they start working the moment it is.

## Code style

- `zig fmt src test build.zig build.zig.zon` before committing.
- Public functions get a one-line doc comment that says *why* the
  function exists, not *what* it does. Don't restate the signature.
- Comments explain non-obvious memory ownership, lifetime, or
  invariants. If a comment doesn't add information beyond the code,
  remove it.

## Commit messages

Conventional Commits style: `feat(scope): summary`,
`fix(scope): summary`, `chore: summary`, `docs: summary`. Keep the
subject under 72 characters. Body wraps at 80.

One commit per logical change. Don't mix refactors with behavior
changes.

## DCO

Sign every commit with `git commit -s`. The Developer Certificate of
Origin appends a `Signed-off-by:` trailer. CI rejects commits without
it.

## Pull requests

- Rebase onto `main` before opening the PR.
- Include test coverage for behavior changes. The integration suites
  in `test/` are the right place for most additions.
- Update `CHANGELOG.md` under the *Unreleased* section.

## License

Contributions are accepted under [Apache 2.0](LICENSE).
