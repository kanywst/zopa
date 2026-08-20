# zopa

Tiny, zero-allocation authorization engine for proxy-wasm and the edge.
~60 KB. No GC. No deps.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/kanywst/zopa/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/zopa/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kanywst/zopa/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kanywst/zopa)
[![Zig](https://img.shields.io/badge/zig-0.16.0-orange.svg)](https://ziglang.org)

**What it is:** an authorization engine that fits in a proxy-wasm filter, so you can enforce policy at the edge without putting a 30 MB sidecar next to every proxy.

**Why it exists:** the usual way to run policy in Envoy is to call out to OPA, or to load OPA's ~30 MB WASM build into the VM. zopa is ~60 KB, allocates from an arena it resets after every request, and answers in single-digit microseconds. You give up the Rego *language* -- zopa runs a compiled Rego-shaped AST, not source -- and keep the decisions.

Hosts hand it a request input and a policy AST, both as JSON; zopa returns allow, deny, or error. It runs as a [proxy-wasm][pw] filter in Envoy or any other proxy-wasm 0.2.1 host, and the same binary works as a plain `WebAssembly.Module` for hosts that just want to call `evaluate(input, ast)`.

**Status: alpha.** The AST covers a useful subset of Rego, and CI runs the suite under three wasm hosts (Node, wasmtime, and a real Envoy). Export names, AST schema, and callback semantics will change before 1.0.

[pw]: https://github.com/proxy-wasm/spec

## Quick start

Grab the module and make one decision, in about thirty seconds:

```bash
# from a release (cosign-signed, with SLSA provenance)
curl -fsSLO https://github.com/kanywst/zopa/releases/download/v0.3.0/zopa-v0.3.0.wasm
mv zopa-v0.3.0.wasm zopa.wasm

# or from the container image, rebuilt on every push to main
docker create --name zopa ghcr.io/kanywst/zopa:edge && \
  docker cp zopa:/zopa.wasm . && docker rm zopa
```

```javascript
// decide.mjs -- node decide.mjs
import { readFileSync } from 'node:fs';

const { instance } = await WebAssembly.instantiate(
  readFileSync('zopa.wasm'),
  { env: {
      proxy_log: () => 0,
      proxy_get_buffer_bytes: () => 1,
      proxy_get_header_map_pairs: () => 1,
      proxy_get_header_map_value: () => 1,
      proxy_send_local_response: () => 0,
  }},
);
const { malloc, free, evaluate, memory } = instance.exports;

const enc = new TextEncoder();
function write(obj) {
  const bytes = enc.encode(JSON.stringify(obj));
  const ptr = malloc(bytes.length);
  new Uint8Array(memory.buffer, ptr, bytes.length).set(bytes);
  return [ptr, bytes.length];
}

const [ip, il] = write({ user: { role: 'admin' } });
const [ap, al] = write({
  type: 'eq',
  left:  { type: 'ref',   path: ['input', 'user', 'role'] },
  right: { type: 'value', value: 'admin' },
});

console.log(evaluate(ip, il, ap, al)); // 1 = allow, 0 = deny, -1 = error
free(ip); free(ap);
```

Or build it yourself -- one command, no dependencies to resolve:

```bash
zig build --release=small        # -> zig-out/bin/zopa.wasm, ~60 KB
```

## Numbers

Release build, measured on this repository's own benchmark
(`zig build bench`, Node host, 10k iterations after 1k warm-up,
microseconds):

| Policy                                        | p50   | p95   | mean  |
| --------------------------------------------- | ----- | ----- | ----- |
| literal `allow = true`                        | 1.71  | 2.50  | 1.91  |
| `input.method == "GET"`                       | 4.67  | 5.17  | 4.74  |
| default-deny RBAC: path prefix + role + perms | 26.67 | 29.25 | 27.25 |

Artifact size is 61 KB. Every row above is reproducible from a clean
checkout, but the machine is a developer laptop -- treat the shape as
the signal and re-run `zig build bench` on your own hardware before
quoting a number.

Two caveats worth stating plainly. These are generic-ABI numbers,
which means each call re-parses the policy AST -- most of the RBAC row
is that parse. The proxy-wasm path compiles the policy once in
`proxy_on_configure` and keeps it, so per-request work there is input
parsing plus the rule walk. And there is no cross-engine comparison
here: asserting "same answer as OPA" needs the conformance corpus to
be much wider than it is, and a latency number without that assertion
isn't worth printing.

## Why zopa

**Size.** A release build is around 60 KB. OPA's WASM build is
two orders of magnitude larger; Cedar and Casbin don't ship as wasm
modules at all.

**Allocation profile.** Every evaluation runs against a single
`std.heap.ArenaAllocator` that is reset with `.retain_capacity` after
each call. After a brief warm-up, `memory.grow` doesn't fire again --
the wasm linear memory footprint stays flat regardless of throughput.

**proxy-wasm native.** `proxy_on_request_headers` runs the `allow`
target rule; `proxy_on_request_body` and `proxy_on_response_headers`
fire `allow_body` / `allow_response` when present. Lifecycle exports
are first-class. The repo ships an Envoy bootstrap
(`examples/envoy/`) exercised in CI against a real Envoy.

**Fails closed.** Every path that can't reach a decision denies: no
policy, a policy that won't parse, a host call that errors, a body
larger than the buffer cap. An authorization filter that fails open is
worse than no filter, because the deployment believes it is protected.

**No DSL to learn.** zopa accepts a Rego-flavored AST as JSON. Use
OPA's compiler to produce it (`tools/rego2ast.py` covers the v1
subset against `opa parse --format json`); zopa runs it. The wasm
module is the runtime, not the language.

**Standards-shaped input.** An [OpenID AuthZEN][authzen] Access
Evaluation request is already a valid zopa input -- no adapter, no
field renaming. See [`docs/authzen.md`](docs/authzen.md).

**No external dependencies.** Just Zig 0.16+ stdlib. The whole code
fits in `src/` and reads top-to-bottom.

[authzen]: https://openid.net/specs/authorization-api-1_0.html

## When not to use zopa

Reaching for the wrong tool costs more than the 60 KB saves:

- **You need the Rego language, not a subset.** Comprehensions,
  `http.send`, partial evaluation, most builtins -- none of that is
  here. Run OPA.
- **You need a management plane.** Bundle distribution, decision logs,
  status APIs, policy hot-reload from a server. That is what OPA is
  for; zopa is a decision function with a configure hook.
- **You need explanations, not decisions.** zopa returns a boolean. It
  can't tell you which rule fired or why.
- **Your filter is body-heavy and single-tenant.** [Envoy dynamic
  modules][dynmod] run native in-process with no VM and no
  serialisation, which is faster. You give up the sandbox and pin the
  build to an Envoy version. If the isolation boundary isn't buying
  you anything, take the speed.
- **You want a drop-in OPA replacement.** zopa answers a narrower
  question than OPA does, on purpose.

[dynmod]: https://www.envoyproxy.io/docs/envoy/latest/intro/arch_overview/advanced/dynamic_modules

## More ways to call it

### Exports

| Export                     | Signature                            | Purpose                                                           |
| -------------------------- | ------------------------------------ | ----------------------------------------------------------------- |
| `malloc`                   | `(len) -> ptr`                       | Allocate a buffer the host owns.                                  |
| `proxy_on_memory_allocate` | `(len) -> ptr`                       | Same allocator under the name proxy-wasm vNEXT hosts probe for.   |
| `free`                     | `(ptr)`                              | Release a buffer from `malloc`. The length lives in a prefix.     |
| `evaluate`                 | `(input, ast) -> i32`                | Decide `allow` in the default package.                            |
| `evaluate_target`          | `(input, ast, rule) -> i32`          | Decide a named rule: `allow_body`, `allow_response`, or your own. |
| `evaluate_addressed`       | `(input, ast, package, rule) -> i32` | Decide `package.rule` inside a `modules` bundle.                  |

The three decision exports return `1` (allow), `0` (deny), or `-1`
(error). Treat `-1` as deny; it means the input or policy could not be
evaluated, which is never a grant.

Buffers passed in must stay alive for the duration of the call --
string values in the parsed tree alias them rather than being copied.

### As an Envoy proxy-wasm filter

```yaml
http_filters:
  - name: envoy.filters.http.wasm
    typed_config:
      "@type": type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm
      config:
        configuration:
          "@type": type.googleapis.com/google.protobuf.StringValue
          value: |
            {"type":"module","rules":[
              {"type":"rule","name":"allow","default":true,
               "value":{"type":"value","value":false}},
              {"type":"rule","name":"allow","body":[
                {"type":"eq",
                 "left":{"type":"ref","path":["input","method"]},
                 "right":{"type":"value","value":"GET"}}]}
            ]}
        vm_config:
          runtime: envoy.wasm.runtime.v8   # or .wamr / .wasmtime
          code:
            local:
              filename: /etc/zopa/zopa.wasm
```

A complete bootstrap with end-to-end test runner is in
[`examples/envoy/`](examples/envoy/).

## Policy AST

The AST is Rego-shaped JSON. Full reference: [`docs/ast.md`](docs/ast.md).

```json
{ "type": "module", "rules": [
  { "type": "rule", "name": "allow", "default": true,
    "value": { "type": "value", "value": false } },

  { "type": "rule", "name": "allow", "body": [
    { "type": "eq",
      "left":  { "type": "ref", "path": ["input", "user", "role"] },
      "right": { "type": "value", "value": "admin" } }
  ]},

  { "type": "rule", "name": "allow", "body": [
    { "type": "every", "var": "p",
      "source": { "type": "ref", "path": ["input", "required_perms"] },
      "body": {
        "type": "some", "var": "g",
        "source": { "type": "ref", "path": ["input", "user", "perms"] },
        "body": { "type": "eq",
          "left":  { "type": "ref", "path": ["g"] },
          "right": { "type": "ref", "path": ["p"] } } } }
  ]}
]}
```

Supported nodes: `value`, `ref`, `compare` (`eq`/`neq`/`lt`/`lte`/`gt`/`gte`),
`not`, `set`, `some`, `every`, `call`, `module`, `modules`, `rule`.
The `type` field accepts shorthand for compare ops (`{"type": "eq", ...}`
is the same as `{"type": "compare", "op": "eq", ...}`).

Builtin functions surfaced via `call`: `startswith`, `endswith`,
`contains`, `count`. Object iteration supports `kind: "keys"`
(default) or `"values"` on `some` / `every`. Multi-package bundles
use `{"type": "modules", "modules": [...]}` and dispatch via
`evaluate_addressed(input, ast, package, rule)`.

## Architecture

```text
       host                              wasm (zopa)
   +----------+    malloc(n)          +-----------------+
   |  Envoy / |  ----------------->   |  host_allocator |
   |  any     |  <-----------------   |  (length-prefix)|
   |  runtime |    ptr                +-----------------+
   |          |
   |          |    evaluate(in,ast)   +-----------------+
   |          |  ----------------->   |  request arena  |
   |          |                       |  json.parse     |
   |          |                       |  ast.build      |
   |          |  <-----------------   |  evalBundle     |
   |          |    1 / 0 / -1         |  arena.reset    |
   +----------+                       +-----------------+
```

`host_allocator` (`std.heap.wasm_allocator`) lives for the module's
lifetime and backs every host-visible buffer. The request arena is
allocated on top of it and reset at the end of every `evaluate()`,
including the proxy-wasm callback path.

The proxy-wasm path adds one thing to the picture: the policy is
parsed and built once in `proxy_on_configure`, onto a second long-lived
arena, and kept. Per-request work there is the input parse plus the
rule walk -- `ast.build` does not run again until the filter is
reconfigured.

More detail in [`docs/architecture.md`](docs/architecture.md).

## Building from source

You need Zig 0.16.0:

```bash
brew install zig                # or download from ziglang.org
zig build                       # debug build
zig build --release=small       # ~60 KB optimized .wasm
```

The artifact is `zig-out/bin/zopa.wasm`.

## Testing

The same policies run under every host zopa claims to support, because
"it works in Node" says nothing about the proxy-wasm ABI. None of the
hosts are required locally; pick what's installed. CI runs all of them.

```bash
zig build test-unit         # Zig host-side unit tests, incl. fuzz smoke runs
zig build test              # Node.js integration (needs node 18+)
zig build test-wasmtime     # wasmtime via Python (see test/requirements.txt)
zig build test-envoy        # real Envoy: proxy-wasm ABI, body buffering, phases
zig build test-conformance  # `opa parse` + tools/rego2ast.py + zopa
zig build bench             # latency benchmark
zig build test-all          # everything available
```

Setup for the Python suites:

```bash
python3 -m venv .venv-test
.venv-test/bin/pip install -r test/requirements.txt
```

`zig build test-envoy` is the only suite that exercises proxy-wasm
itself -- configure, the three phase callbacks, body buffering, and
`send_local_response`. Everything else calls `evaluate` directly and
would keep passing with a broken shim.

## Comparison

|                  | [OPA][opa]     | [Cedar][cedar] | [Casbin][casbin] | zopa                       |
| ---------------- | -------------- | -------------- | ---------------- | -------------------------- |
| Language         | Go             | Rust           | Go (+ ports)     | Zig                        |
| Released as wasm | Yes (~30 MB)   | No             | No               | Yes (~60 KB)               |
| Allocation model | GC             | RC + arenas    | GC               | per-request arena          |
| proxy-wasm       | Side project   | No             | No               | First-class                |
| Policy input     | Rego source    | Cedar source   | CSV / source     | Compiled AST (Rego-shaped) |
| Maturity         | CNCF Graduated | Stable         | Mature           | Alpha                      |

[opa]: https://www.openpolicyagent.org/
[cedar]: https://www.cedarpolicy.com/
[casbin]: https://casbin.org/

zopa is not a replacement for OPA when you need the full Rego
language, the management plane, or bundles. It's a drop-in for the
narrow case where you've already compiled the policy and want to
evaluate it inside a proxy-wasm filter without a 30 MB sidecar.

## FAQ

**Do I have to write the AST by hand?**
No. Write Rego, run `opa parse --format json`, and pipe it through
`tools/rego2ast.py`. Hand-writing the AST is for tests and one-liners.

**What happens if my Rego uses something zopa doesn't support?**
`rego2ast.py` refuses to convert it rather than emitting something that
evaluates differently. The conformance runner records that as a SKIP,
not a pass. There is no silent degradation.

**Is it really zero-allocation?**
Not literally -- it allocates from an arena. What it doesn't do is grow
linear memory in steady state: the arena is reset with
`.retain_capacity` after every evaluation, so once the high-water mark
is reached, `memory.grow` stops firing. There is no GC and nothing to
tune.

**What does it do when something goes wrong?**
Denies. Unparseable input, a policy that won't build, a host call that
fails, a request body bigger than the 64 KiB buffer cap -- all deny.
The one place this is subtle is the body cap: a truncated body is
refused outright rather than evaluated against the prefix, because a
prefix that fails to parse would make a deny rule silently miss.

**Can I run more than one policy in a VM?**
Yes -- bundle them as `{"type":"modules","modules":[...]}` and address
`(package, rule)` with `evaluate_addressed`. What you can't do today is
give two Envoy filters sharing an explicit `vm_id` different policies;
the last configure wins. See ROADMAP.

**How does it handle a request body?**
Only if the policy has an `allow_body` rule. Without one, the body
callback returns immediately and nothing is buffered. With one, the
body is accumulated until end of stream and evaluated as
`{"body": ..., "body_raw": ..., "body_truncated": ...}`.

**Is the alpha label real?**
Yes. The engine is tested but the public surface will move: export
names, AST schema, and callback semantics are all still in play before
1.0. Pin a tag.

**Why Zig?**
Freestanding wasm with no runtime, no GC, and no allocator you didn't
ask for, plus explicit allocator passing -- which is what makes the
"one arena per request, reset at the end" model expressible at all.

## Roadmap

See [ROADMAP.md](ROADMAP.md). Streaming evaluation runtime,
proxy-wasm 0.3.x migration, and expanding the OPA conformance
corpus are the next big items.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers local setup, code style,
DCO, and PR expectations.

## Security

[SECURITY.md](SECURITY.md). Use GitHub's private vulnerability
reporting; don't open a public issue for security bugs.

## Acknowledgements

zopa would not exist without:

- [Open Policy Agent][opa] for the Rego language and reference
  implementation.
- [Cedar][cedar] for the example of a small, focused authorization
  language.
- [proxy-wasm/spec][pw] and the Envoy team for the ABI.

## License

[Apache 2.0](LICENSE).
