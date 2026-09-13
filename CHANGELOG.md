# Changelog

All notable changes are recorded here. Format follows [Keep a Changelog][kac]; releases follow [Semantic Versioning][semver] once the first stable tag ships.

## [Unreleased]

### Added

- **`targets[]` in the proxy-wasm plugin configuration.** A deployment can now name which `(package, rule)` pairs each phase evaluates, and whether a deny enforces or is only recorded -- the audit-alongside-enforcement case `docs/proposals/multiple-policies.md` was written for, and the last of that proposal's goals.

  The configuration accepts a `{"policy": ..., "targets": [...]}` wrapper alongside the historical bare-AST form. No AST node has a top-level `policy` member, so the two cannot be confused, and without a `targets` block the shim behaves exactly as every release before it.

  Enforcing targets are **ANDed**: with more than one, all must allow. ORing would let an added rule widen access. An advisory target (`"on_deny": "log"`) is evaluated on the same input and never blocks, and its errors do not deny either -- a broken audit rule is a broken audit trail, not a reason to reject traffic. That is the one place the shim deliberately does not fail closed, which is why `deny` is the default: a misspelled field cannot quietly make a blocking rule advisory.

  Everything the block can get wrong fails configure -- unknown phase, unknown `on_deny`, a rule the policy does not define, a malformed entry, and a block naming no enforcing request-phase target -- because a target that never fires is worse than a filter that refuses to start. That last one was a bypass caught in review before merge: the request phase has no existence gate, so an empty list made it allow from an empty loop and `{"targets": []}` alone would have disabled authorization while looking configured. A truncated body is refused if any *enforcing* body target reads the body -- not just the first. Advisory body targets deliberately do not raise that gate: it denies the whole request, and an advisory target must never be able to do that, so adding an audit rule cannot start rejecting oversized bodies that were previously fine. Every target on a phase is evaluated even once an enforcing one has denied, so the audit trail does not lose exactly the requests an operator most wants on it. The target logic lives in `src/targets.zig`, which imports no host functions, so `zig build test-unit` reaches the validation that previously needed a real Envoy. Release build: ~68 KB.

### Fixed

- **The Envoy suite could test the wrong process.** Scenario 2 never stopped its Envoy, and `start_envoy` waits on the admin port, which a stale Envoy answers as happily as a fresh one -- so a scenario whose instance failed to bind silently ran against the previous one's policy. It cost me two checks that "passed" against the wrong filter and two that failed for an unrelated reason. The suite now stops each scenario's Envoy and refuses to start when either port is already held.

### Added

- **`:=` assignment in a rule body.** `role := input.user.role` binds a name visible to every expression after it in the same body -- the last of the two Rego idioms the coverage table named as practically missing. `zig build test-coverage` goes 34/49 to 36/51.

  Bodies are now evaluated recursively rather than as a flat loop, because an assignment scopes over its **siblings** where `some` and `every` own the single expression they bind over. That distinction is why the scope chain existed for four releases without needing this.

  A binding whose right-hand side is undefined makes the body undefined rather than binding null: otherwise `x := input.missing` would compare equal to another missing field and quietly hold. An explicit JSON `null` does bind, though -- zopa spells both with `Value.nil`, and conflating them would deny a policy OPA allows. Which meaning applies depends on the right-hand side: a literal may be null, a ref reports a missing path distinctly, and everything else (a builtin call, a comparison, an iterator) yields nil only when it could not compute -- so `n := count(input.missing)` denies rather than binding nil and letting `n != 0` hold. A body ending in a binding still holds, matching Rego (`allow if { x := 1 }` is true, checked against `opa eval`), but nested where there is nothing to scope over -- inside `not`, or as a `some` body -- it is an error and denies. Binding a name twice in one body is refused at both layers: Rego is single-assignment per scope and `opa check` rejects it, but this pipeline runs `opa parse`, which does not -- so accepting it would have made zopa run last-write-wins semantics no OPA policy can produce. Destructuring targets are refused too.

  `body_deps` sees through a binding, so `x := input.body.amount` still counts as reading the body. Missing that would have classified such a policy as touching nothing and let the shim evaluate it against a truncated prefix -- the fail-open that analyser exists to prevent, arriving through a node that postdates it. Release build: ~64 KB, up 763 bytes.

### Fixed

- **The SBOM step never checked what it scanned.** Its hash guard proves the document names the right artifact and says nothing about how it was produced -- so an input rename in a future `sbom-action`, or an accidental default to the workspace, would publish the ~60 Actions and `.zig-cache` false positives the whole design exists to avoid, with every other check still passing. It now asserts zero dependency components (which is the answer, since `build.zig.zon` declares none) and prints what it found when that fails. The Apache-2.0 claim is now gated on `LICENSE` hashing to the canonical Apache License 2.0 -- reading the id back out of the document it just wrote proved nothing, and a substring match on "Apache License" would have accepted Apache 1.1. That also keeps the v0.4.1 restoration honest: an edited LICENSE fails the release rather than being signed as Apache-2.0. `file:` was also verified to be a real input of `anchore/sbom-action` at the pinned commit, not silently ignored.
- **The jq that decides whether a release ships had no test.** It lived inline in a workflow `run:` block, where nothing could exercise it short of pushing a tag. It is now `tools/sbom-annotate.sh`, covered by `test/sbom_annotate_test.py` for both CycloneDX `tools` shapes and each condition it refuses on, run in CI. `shellcheck` was scoped to `examples/` and so had never seen it; it now scans the repository.
- **The benchmark baseline could be seeded empty.** The compare path refused a run without the reference engine; the seed path did not, so re-seeding from a run where `zopa-compiled` failed to build would emit a valid-looking baseline with an empty `ratios` object and exit 0 -- the same fail-open, on the other branch of the same script, surfacing much later as "nothing was compared".

### Changed

- **Two conformance fixtures claimed more than they pin.** `12_partial_set` and `13_partial_object` verify that the construct is refused end to end; they cannot verify that the dropped set or key would be caught by a decision, because zopa has no complete rule that could hold one. Their notes say so now. `with` and `else` have fixtures that do discriminate.
- **A nullary function definition is a recorded limitation.** `f() if ...` and `f if ...` produce byte-identical heads in OPA's AST -- neither carries `args` -- so the guard on function definitions cannot see the nullary case, and it converts into a rule named `f`. Documented in `docs/ast.md` and pinned by a test that fails if OPA ever distinguishes them.

### Added

- **Array indices in ref paths.** `input.groups[1].name` now converts and evaluates; a `ref` path segment is a JSON string for a member lookup or a non-negative whole number for an index. This was the most-used Rego idiom zopa could not express -- `zig build test-coverage` goes from 32/48 to 34/49.

  The two kinds of segment stay distinct end to end. Indexing `{"groups": {"1": {...}}}` does **not** resolve, and looking up the key `"1"` does not index an array. Collapsing them -- encoding an index as the string `"0"` -- would let a supplied object stand in for the array a policy meant to index, which is a policy bypass rather than a convenience. Both directions are asserted in the unit tests, both host suites, a conformance fixture, and end to end through a real Envoy filter.

  A negative, fractional, or non-numeric index is rejected when the AST is built rather than resolving to undefined on every request: a malformed policy should fail at configure time, not become a silent permanent deny. Release build: ~63 KB, up 6 bytes -- the evaluator reuses the walker it already had for bound values rather than materialising the path.

## [0.4.1] - 2026-09-12

**The module does not change.** `zopa-v0.4.1.wasm` is byte-for-byte `zopa-v0.4.0.wasm` (SHA-256 `d60e29fa1f26aa8037b05e66b1864435a6f1935c2dbfc8de510d5032f23e0082`); nothing under `src/` was touched. Everything here is the toolchain, the benchmark, and what a release ships alongside the wasm.

**One thing will break, deliberately.** `tools/rego2ast.py` now refuses four Rego constructs it used to convert: `with`, partial rules, `else` branches, and function definitions. If your build starts failing on one of them, it was already producing an AST that answered a different question than your Rego -- see *Fixed* below. A patch rather than a minor because no deployed artifact changes and the refusals correct a wrong answer rather than remove a working feature, but it is a toolchain break and worth reading before upgrading.

### Fixed

- **`rego2ast.py` silently changed what four constructs mean.** `with`, partial rules, `else` fallback branches and function definitions all converted with exit 0 while emitting an AST that answered a different question. `else` kept only the first branch, dropping the fallback -- an allow path or a deny path depending on which it was. A function definition became a rule whose parameter resolved against the input document instead of binding, so `f(x) if x == 1` silently became a test on `input.x`. Details on the first two: Both converted "successfully" into an AST that answered a different question than the Rego it came from. `allow if input.x == 1 with input.y as 2` produced exactly the AST of the same rule without the modifier -- OPA evaluates that body against a rewritten input, zopa against the original. Partial rules were flattened: `deny contains "x" if ...` became a plain boolean `deny` rule and `p[k] = v if ...` a complete rule with the key discarded, losing the collected set or object entirely and turning definitions OPA unions into definitions zopa reports as conflicting. The converter is documented to bail with `Unsupported` on Rego it cannot express, and the conformance runner records that as SKIP; these two slipped through as supported. Both now refuse. This is the same class of divergence the JSON parser is strict about -- a policy the two engines read differently -- arriving through the converter instead.
- **A standalone `some x in xs` crashed the converter** with an uncaught `KeyError` rather than bailing cleanly: a symbols declaration has no `type` key and fell through to the term walker. It now reports why the shape cannot be expressed.
- **Operators with no bare name reported nothing.** `in` arrives from OPA as `internal.member_2` and produced `unsupported call:` with an empty name; multi-segment refs are now described.

### Added

- **`zig build test-coverage`: which Rego constructs the converter reaches.** The README said the AST covered "a useful subset of Rego" without saying which. A corpus of one-construct policies is now walked through `opa parse` and `rego2ast.py`, and the result recorded in `test/conformance/coverage.json` -- **32 of 48** today, with the gaps named in the README. CI fails if reach changes in either direction without the table being re-recorded, so a construct quietly starting or stopping to convert shows up as a diff. It measures reach, not correctness; `test-conformance` still owns the question of whether what converts decides correctly, and gained fixtures for `with` and both partial spellings so the refusals are proven end to end. The `with` fixture is built to *fail* rather than skip if the silent drop ever returns: its body reads only the overridden field, so OPA allows where a dropping converter denies. `test-coverage` also asserts the text of each refusal, since a message naming the wrong construct still reads as "does not convert" in a boolean table.
- **A performance regression gate.** `bench/results/baseline.json` records each engine's amortised cost as a ratio to `zopa-compiled` on the same run, and CI compares every PR's smoke run against it. Ratios rather than absolute microseconds: a shared runner cannot measure a sub-microsecond p99 meaningfully, but a runner that is merely slow scales every engine in the same process equally, so the ratios survive it. The 1.5x threshold is deliberately wide -- it is there to catch a per-request policy parse creeping back into the compiled path, not to police drift. Verified both ways: three consecutive smoke runs pass against the committed baseline, and reintroducing the parse into `zopa-compiled` trips all 13 ratios by up to 19.7x.
- **Throughput is the best of several short windows** rather than one long one. A single window that catches a GC pause reports far below what an engine can do, and at these costs one pause dominates: the harness had measured `zopa-compiled` at 3.84 us amortised against a 1.38 us p50 on the same run. Across three consecutive runs the RBAC fixture now sits at 1.34-1.87 us, where a single window had produced a number implying OPA's wasm build was faster.
- **Cedar joins the benchmark.** An earlier note in `bench/README.md` said no first-party Cedar binding was reachable from Node without adding a dependency. That was wrong: `@cedar-policy/cedar-wasm` is published by the Cedar project and runs under `node` directly. The engine resolves it at run time and skips itself, by name, when it is absent -- nothing is vendored and this repository still has no `package.json`. `03_rbac` gained a Cedar policy so the comparison covers the realistic fixture too, and the agreement gate holds Cedar to the same decision as every other engine. The policy set is preparsed through `statefulIsAuthorized`, the fair analogue of `zopa-compiled` and OPA's prebuilt wasm; charging Cedar a policy parse per decision would be the unfairness this harness already avoids for OPA. The resulting number is dominated by the wasm-bindgen serialisation boundary rather than Cedar's evaluator, and both READMEs say so rather than letting the row be misread.
- **Releases carry a signed CycloneDX SBOM** (`zopa-<tag>.wasm.cdx.json`, plus its own cosign bundle). It is generated by scanning the built artifact, not the source tree: a `dir:.` scan of this repository reports 60-odd components -- the GitHub Actions pinned in the workflows, plus false positives syft reads out of `.zig-cache` -- none of which the shipped wasm depends on. Scanning the wasm reports **zero dependency components**, which is the accurate answer, and the document is annotated with the artifact's SHA-256, its licence, and the Zig version that built it. The release fails rather than publishing an SBOM whose recorded hash does not match the artifact. `SECURITY.md` documents how to verify a release end to end.

## [0.4.0] - 2026-09-12

A minor bump: the generic ABI gains a compiled-policy path, which is additive, but it changes what the fast way to drive zopa is. Nothing existing breaks -- `evaluate`, `evaluate_target` and `evaluate_addressed` are untouched.

The short version: if you drive the same policy across requests through `evaluate`, you are paying an AST parse per decision. `policy_compile` once and `evaluate_compiled` after it takes the benchmark's RBAC fixture from 5.76 us to 1.32 us. This release also corrects two README claims that turned out to be wrong once there was a benchmark to check them against.

### Added

- **Compiled policies on the generic ABI: `policy_compile`, `policy_release`, `evaluate_compiled`, `evaluate_compiled_addressed`.** `evaluate` receives the AST bytes on every call and cannot know they are the ones it parsed last time, so it rebuilds the policy per decision; the benchmark put that at 4.4 us of the 5.76 us it spent on the RBAC fixture, which is why OPA's WASM build was beating it there. A host can now build the policy once and evaluate against a handle -- the arrangement `proxy_on_configure` has always used internally -- which takes the same fixture to **1.32 us, ahead of OPA-in-wasm's 2.24**. Handles are validated, never pointers: a stale, doubled, zero, or forged handle returns `-1` and denies rather than following a dangling reference. A handle carries the generation of the slot it was issued for as well as the index, so releasing one and compiling another policy into the freed slot does not make the old handle resolve to the new policy -- a bare index would have turned a released handle into an authoritative decision from the wrong policy once the slot was reused. The host owns the handle and must release it; a dropped one leaks the policy for the life of the module, the same contract as `malloc`. Release build size: ~63 KB (+1.8 KB).
- **`zig build bench` builds its own `ReleaseSmall` artifact.** It depended on the install step, so with no `-Doptimize` flag it measured the ~940 KB debug build and printed the numbers without comment -- a silently wrong result rather than a failure. The test suites still depend on the install step, because they are correct at any optimize mode.
- **The benchmark measures both zopa shapes.** `bench/engines/zopa-compiled.mjs` sits beside the one-shot engine, so the gap between the two rows is a direct measurement of what the AST parse costs on each fixture.

- **`zig build bench` compares zopa against OPA.** The harness runs zopa's `evaluate` export, OPA compiled to WASM (`opa build -t wasm`, driven through the `opa_eval` fast path), and OPA as an HTTP sidecar (`opa run --server`) over the same fixtures, and refuses to time anything until all three return the same decision — each fixture already carried both an AST and its Rego, and the harness now checks they agree. Reports p50/p95/p99 minus a measured clock-read floor, an uninstrumented amortised cost, throughput, memory after warm-up, deployed artifact size, and cold start. The OPA engines are skipped and named when no `opa` is on `PATH`, so the step still works without one; CI runs it in `--quick` mode on every PR. No npm dependency: the OPA WASM ABI is bound directly. New fixture `04_deep_nest` drives 24 nested frames at the recursion cap (zopa-only — there is no natural Rego for it).

### Fixed

- **The README's central size claim was wrong by two orders of magnitude, in zopa's favour.** It said OPA's WASM build was "~30 MB" and "two orders of magnitude larger" than zopa. Measured: `opa build -t wasm` emits 134 KB for a one-line policy and 149 KB for a sixty-rule one, against zopa's 63 KB — roughly 2x, not 500x. The ~30 MB figure is the OPA *binary* (40 MB here), which is the right number for the sidecar comparison and the wrong one for the in-VM comparison. Corrected in `README.md` and the engine comparison table. zopa's remaining size advantage is real but different in kind: one module serves every policy, where OPA emits one per policy.
- **The README's latency table was stale and too pessimistic**, reporting p50s of 1.71 / 4.67 / 26.67 us where the current build measures 0.32 / 0.98 / 5.80. Replaced with the measured numbers alongside both OPA configurations, including the two rows that do not favour zopa: OPA's WASM build is 2.6x faster on the realistic RBAC policy (because `evaluate` re-parses the AST every call), and it holds far less WASM memory (128 KiB against zopa's ~1.4 MiB arena floor).

## [0.3.1] - 2026-09-12

A licensing correction, and nothing else. No source, AST, or evaluation semantics change: `zig build --release=small` on this tag reproduces the 0.3.0 release artifact byte for byte (SHA-256 `3513c6319aec36fa8a84c96117097189ab0cbac5a557cf444cb55c41924ed34f`). Take this release if you redistribute zopa -- the terms you were passing on were not the ones the project meant to grant. If you only run it, 0.3.0 is the same module.

### Fixed

- **`LICENSE` is the Apache License 2.0 again, byte for byte.** The file shipped since 0.1.0 was a paraphrase: clause 6 (Trademarks) dropped "reasonable and customary use in", and clause 9 (Accepting Warranty or Additional Liability) replaced the "choose to offer, and charge a fee for, acceptance of support, warranty, indemnity, or other liability" grant with different wording. The copyright line in the appendix boilerplate had also been filled in, which is why GitHub reported the repository's license as `NOASSERTION` rather than `Apache-2.0`. The canonical text is now restored verbatim (SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`) and the copyright assertion moved to a new `NOTICE` file, as the appendix instructs. Anyone who redistributed zopa 0.1.0-0.3.0 under the terms in the old file was relying on text that was not Apache 2.0; the intended license was always Apache 2.0 and that has not changed.

## [0.3.0] - 2026-08-20

A hardening release. Every change below exists because some path could reach "allow" without having actually decided, or because zopa and the service behind it could read the same bytes differently.

**Upgrading is not transparent.** Requests and policies that worked under 0.2.0 can behave differently:

- A filter configured without a `configuration` block no longer starts. It used to load and pass every request through unevaluated.
- A policy with two definitions of the same rule that hold at once with different values now evaluates to `-1` (deny) instead of whichever came first in the bundle. Two `default` declarations for one rule are now rejected outright when the policy is built.
- Input documents containing `01`, `1.`, `.5`, `+1`, or `1e` no longer parse, and duplicate object keys resolve to the last occurrence rather than the first.
- A request body over the 64 KiB cap, a body the host will not hand over, and a header map that will not decode all deny rather than being evaluated against whatever was available.

Read the *Security* section before upgrading; each entry says what the old behaviour let through.

### Security

- **Oversized request bodies no longer fail open.** The body phase caps buffering at 64 KiB. A larger body was silently truncated, which made the JSON parse fail, which made `input.body` null, which made a deny rule watching `input.body.amount` find nothing to match -- so sending a big body bypassed the rule. A truncated body now denies whenever the policy reads the body (`body_deps.analyzeTarget` decides whether it does). Covered end to end in `examples/envoy/run.sh` with a payload that would be *allowed* if zopa saw all of it.
- **Chunked request bodies are buffered before evaluation.** `proxy_on_request_body` returned `Continue` on non-final chunks, so the host forwarded each fragment as it arrived and the buffer at end of stream held only the tail. A policy reading the body was deciding on a suffix. Non-final chunks now return `StopIterationAndBuffer`.
- **A missing or invalid policy is a configuration failure.** `proxy_on_configure` previously accepted an empty configuration and every request then passed through unevaluated. It now returns 0 and logs, so Envoy refuses to start the filter (503 with the default `fail_open: false`) instead of protecting nothing quietly.
- **JSON parsing agrees with the backend.** Numbers now follow the RFC 8259 grammar exactly (`01`, `1.`, `.5`, `+1`, `1e` are rejected) instead of whatever `parseFloat` accepted, and duplicate object keys resolve last-wins as they do in Go, JavaScript, and OPA. Both were parser differentials: a document zopa and the service behind it read differently is a way to smuggle a value past a policy.
- **A deny on the request phase returns `Pause`.** It returned `Continue` after `proxy_send_local_response`, asking the host to keep running the filter chain on a request that had already been answered.

### Fixed

- **Rule dispatch is package-scoped, not module-scoped.** Rules were evaluated one module at a time and the results OR-ed, which broke a package split across modules two ways: a `default` rule only covered its own module, and a module returning `true` short-circuited past a later module's explicit `"value": false` deny. All rules contributed to a package are now one rule set, matching Rego. Documented under "Rule dispatch" in `docs/ast.md`.
- **Conflicting rule definitions error instead of resolving by order.** `allow` is a complete rule, and OPA raises `eval_conflict_error` ("complete rules must not produce multiple outputs") when two definitions hold at once with different values. zopa returned whichever came first in the bundle, so the decision depended on file layout -- something that carries no meaning in Rego and changes when modules are reordered or split -- and answered `allow` where OPA refuses to answer. It now returns `-1`, which every caller denies on. Definitions that agree are still fine, and a `default` never conflicts. Checked against real `opa parse` output in `test/conformance/fixtures/10_rule_conflict.json`.
- **`input.body_raw` counts as reading the body.** `body_deps` only looked for the path segment `body`, so a policy whose sole body dependency was `contains(input.body_raw, "...")` classified as `no_body_refs` and skipped the truncation gate entirely -- the same fail-open the gate exists to close, reached through the sibling field. `input.body_truncated` deliberately still does not count: a policy reading the flag is asking to handle truncation itself, and refusing the request first would take that away.
- **Two `default` declarations for the same rule are rejected.** The last one silently won, so the fallback depended on bundle ordering -- quietly, since a fallback only applies to requests where nothing else matched. OPA rejects this at compile time (`rego_type_error: multiple default rules data.authz.allow found`); zopa now rejects it when the AST is built, which fails `proxy_on_configure` rather than skewing decisions at runtime.
- **A zero-length body is evaluated instead of skipped.** The body callback returned early on `body_size <= 0`, which skipped `allow_body` and its `default`. Note this was not reachable through Envoy, which does not invoke the callback at all for a request with no body -- pinned by a check in `examples/envoy/run.sh` -- but the early return was wrong for any host that does, and a condition that must hold for every request belongs in `allow` regardless.
- **An unreadable header map denies.** A host error or a buffer that didn't decode produced an empty header set, which is not the same thing: a rule shaped `deny if input.headers["x-blocked"]` sees the header as absent and lets the request through. Same mistake as deciding on a truncated body. A map with zero entries is still a legitimate answer.
- **A body the host refuses to hand over denies.** `readBodyBytes` folded a failed `proxy_get_buffer_bytes` into an empty slice, which is indistinguishable downstream from a request that carried no body: a rule watching for a marker found nothing in `""` and let the request through.
- `free(0)` no longer reads a length prefix from below address zero; the export takes a nullable pointer and ignores null.
- `body_deps.zig` is actually wired into the shim. Its doc comment claimed the proxy-wasm layer used it to make buffering decisions; nothing called it.

### Added

- `proxy_on_memory_allocate` export, the name proxy-wasm ABI vNEXT uses for the allocator. Hosts probe for it before falling back to `malloc`, so exporting both keeps the module loadable on either generation.
- `src/wire.zig`: header-map decoding and per-phase input synthesis, split out of `proxy_wasm.zig`. That file's `extern "env"` declarations make it unlinkable on the host, so this code -- including the length-prefixed binary header-map decoder, the most malformed-input-exposed surface in the module -- had no unit tests at all. It now has a malformed-buffer table, a 32-bit-overflow case per length field, and a round-trip property test proving a header value cannot break out of its JSON string literal.
- `std.testing.fuzz` targets over the JSON parser, end-to-end evaluation, and the header-map decoder. They run as smoke tests under `zig build test-unit`; `--fuzz` mode is blocked by an upstream compile error in Zig 0.16.0's own test runner.
- `body_truncated` in the body-phase input, so a policy can key on truncation directly rather than only relying on the shim's refusal.
- `evaluate_addressed` is now exercised from a host in `test/run.mjs` and `test/run_wasmtime.py`. The export shipped in 0.2.0 with no host-side caller outside the conformance harness, and the wasmtime harness did not even bind it -- so the suite that exists to catch runtime-specific divergence could not reach package dispatch at all. Rule dispatch and parser agreement now run under both runtimes.
- Envoy end-to-end coverage of the body and response phases (`examples/envoy/envoy-phases.yaml`). The previous bootstrap ended in `direct_response`, which Envoy answers before reading the request body -- so a body-phase test there would have passed by never running. The new scenario proxies to a loopback listener instead.
- `test-envoy` runs in CI against a pinned, checksummed upstream Envoy release binary. The proxy-wasm ABI was previously only ever exercised on a maintainer's laptop.
- `.github/workflows/claude-review.yml`: an advisory automated review pass on pull requests, prompted with this project's actual invariants (fail-closed, allocator boundaries, parser agreement, 32-bit length arithmetic, size budget) rather than generic style feedback. Skips fork PRs, which do not receive secrets.
- [`docs/authzen.md`](docs/authzen.md): mapping from an OpenID AuthZEN Authorization API 1.0 Access Evaluation request onto zopa's input, plus the error-case mapping (`-1` must become `decision: false`). Checked by `test/conformance/fixtures/09_authzen_evaluation.json`.
- `bench/fixtures/03_rbac.json`: a default-deny RBAC policy, so the benchmark reports something closer to a policy people write.
- Release build size: ~60 KB → ~62 KB. The increase covers the conflict and duplicate-default checks, the body-deps wiring, and the fail-closed paths.

### Changed

- The proxy-wasm shim compiles the policy once at configure time onto a dedicated arena and keeps the built AST. Per-request work is now the input parse plus the rule walk; the policy AST is no longer re-parsed on every request. A reconfigure builds the new policy before discarding the old one, so a bad config cannot strand a healthy filter with nothing loaded.
- `eval.evaluateCompiled` is the new entry point for hosts that hold a policy across requests. `evaluate`, `evaluate_target`, and `evaluate_addressed` are unchanged.
- `build.zig.zon` now carries the real version. It still said `0.1.0` when 0.2.0 shipped, so anything resolving the package by version saw the wrong one.
- Repository moved from `0-draft/zopa` to `kanywst/zopa`. GitHub redirects the old URL, and `build.zig.zon` never carried the org, so clones and `zig fetch` keep working. Forward-looking references (README badges, `Dockerfile` source label, ROADMAP, the distroless proposal) now point at `kanywst`; entries under released versions keep the paths those releases actually shipped with.
- `.github/workflows/oci.yml` derives the image name from `$GITHUB_REPOSITORY`, so images built from the next tag publish to `ghcr.io/kanywst/zopa`. The existing `ghcr.io/0-draft/zopa` tags are untouched.

## [0.2.0] - 2026-05-10

Public surface still alpha. Existing v0.1 policies (single `allow` target rule, flat request-side input) keep working unchanged: the new body and response phases are opt-in via the matching rule (`allow_body` / `allow_response`) appearing in the policy.

### Added

- AST node `call` plus four builtins: `startswith`, `endswith`, `contains`, `count`. Type errors and unknown names resolve to `nil` (deny in body position).
- `some` / `every` iteration over JSON objects via a new optional `kind` field (`"keys"` default, `"values"`).
- `Modules` bundle wrapper (`{"type": "modules", "modules": [...]}`) and an optional `package` field on `Module`.
- `proxy_on_request_body` evaluates `allow_body` against `{body, body_raw}` once end of stream is signalled. Body buffer cap: 64 KiB. Body parsed as JSON when possible; otherwise `body` is `null` and `body_raw` carries the bytes.
- `proxy_on_response_headers` evaluates `allow_response` against `{response: {status, headers}}`. Deny replaces the upstream response with a 503.
- New wasm exports `evaluate_target(input, ast, target_rule)` and `evaluate_addressed(input, ast, package, target_rule)` for hosts driving non-default rules without proxy-wasm.
- `src/body_deps.zig`: configure-time analyser that classifies a module's body references as `no_body_refs` / `prefix_only` / `full_tree`. Foundation for the streaming runtime; not wired into the proxy-wasm shim yet.
- `zig build bench`: Node-based latency benchmark over `bench/fixtures/`, reporting p50/p95/p99/mean.
- `zig build test-conformance`: drives `opa parse` → `tools/rego2ast.py` → zopa for each fixture in `test/conformance/fixtures/`. Six starter fixtures cover bool comparators, builtins, `every`, `not`, `count`, missing-path semantics.
- Distroless multi-arch OCI image at `ghcr.io/0-draft/zopa`, cosign-signed, built on every tag via `.github/workflows/oci.yml`.
- CI gains `test-unit`, `bench (smoke)`, and `test-conformance` jobs alongside the existing `build`, `test`, `test-wasmtime`, and the `lint` workflow's `zig-fmt` / `markdownlint` / `shellcheck`.

### Changed

- Public eval surface layered: `evaluate` is now a thin wrapper over `evaluateWithTarget`, which is a wrapper over `evaluateAddressed`. Behaviour at the `evaluate` entry point is unchanged.
- Missing path inside `compare` (and any other `resolveValue` site) now resolves to `Value.nil` rather than propagating `error.PathNotFound`. Aligns with Rego's "missing is undefined" semantics: a body using `input.user.role == "admin"` against `{}` now denies (0) instead of erroring (-1).
- `proxy_on_request_body` and `proxy_on_response_headers` short-circuit at configure time when their target rule (`allow_body`, `allow_response`) is absent from the policy. Detection is a substring match in the policy JSON. Pre-v0.2 callers with a request-only policy retain the v0.1 pass-through behaviour for the body and response phases.
- Release build size: ~50 KB → ~60 KB. The increase covers `call`, object iteration, the `Modules` bundle, the two new target-rule paths, and the body-deps analyser.

## [0.1.0] - 2026-05-07

First tagged release. Public surface (export names, AST schema, callback semantics) is still alpha and may change before 1.0.

### Added

- Initial implementation: `wasm32-freestanding` build, ~50 KB release binary.
- In-tree JSON parser with surrogate-pair handling and zero-copy string aliasing.
- Per-request arena allocator with `retain_capacity` reset.
- Policy AST: `value`, `ref`, `compare` (`eq`/`neq`/`lt`/`lte`/`gt`/`gte`), `not`, `set`, `some`, `every`, `Module`, `Rule`.
- proxy-wasm 0.2.1 lifecycle exports: `proxy_on_vm_start`, `proxy_on_configure`, `proxy_on_context_create`, `proxy_on_request_headers`, `proxy_on_request_body` (no-op pending body-aware policy work), `proxy_on_response_headers` (no-op), `proxy_on_done`.
- Length-prefixed `malloc`/`free` exports compatible with proxy-wasm host buffer ownership conventions.
- Integration tests in Node, wasmtime, and a real Envoy (`zig build test`, `test-wasmtime`, `test-envoy`).
- Automated releases on `v*` tags with SLSA v1.0 build provenance and cosign keyless signatures. Each release attaches `zopa-<tag>.wasm`, `.sha256`, `.intoto.jsonl`, and `.sigstore.json`.

### Fixed

- README badges (CI, OpenSSF Scorecard) now resolve. They were left pointing at `kanywst/zopa` after the repo moved to `0-draft/zopa`.

[kac]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html
[Unreleased]: https://github.com/kanywst/zopa/compare/v0.4.1...HEAD
[0.4.1]: https://github.com/kanywst/zopa/releases/tag/v0.4.1
[0.4.0]: https://github.com/kanywst/zopa/releases/tag/v0.4.0
[0.3.1]: https://github.com/kanywst/zopa/releases/tag/v0.3.1
[0.3.0]: https://github.com/kanywst/zopa/releases/tag/v0.3.0
[0.2.0]: https://github.com/kanywst/zopa/releases/tag/v0.2.0
[0.1.0]: https://github.com/kanywst/zopa/releases/tag/v0.1.0
