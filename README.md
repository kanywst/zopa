# zopa

Tiny, zero-allocation authorization engine for proxy-wasm and the edge.
~60 KB. No GC. No deps.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![CI](https://github.com/kanywst/zopa/actions/workflows/ci.yml/badge.svg)](https://github.com/kanywst/zopa/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/kanywst/zopa/badge)](https://securityscorecards.dev/viewer/?uri=github.com/kanywst/zopa)
[![Zig](https://img.shields.io/badge/zig-0.16.0-orange.svg)](https://ziglang.org)

zopa runs as a `wasm32-freestanding` module. Hosts hand it a request
input and a compiled policy AST, both as JSON; zopa returns an
allow/deny decision. There's no embedded language compiler, no GC,
and no scratch memory that survives a request -- a per-request arena
is reset at the end of each evaluation.

The intended deployment is as a [proxy-wasm][pw] filter in Envoy or
any other proxy-wasm 0.2.1 host. The same binary also works as a
plain `WebAssembly.Module` for hosts that just want to call
`evaluate(input, ast)` directly.

[pw]: https://github.com/proxy-wasm/spec

## Status

Alpha. The AST covers a useful subset of Rego, the proxy-wasm shim
boots in Envoy, and the integration tests pass under three different
hosts. Public surface (export names, AST schema, callback semantics)
will change before 1.0.

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
(`examples/envoy/`) exercised in CI.

**No DSL to learn.** zopa accepts a Rego-flavored AST as JSON. Use
OPA's compiler to produce it (`tools/rego2ast.py` covers the v1
subset against `opa parse --format json`); zopa runs it. The wasm
module is the runtime, not the language.

**No external dependencies.** Just Zig 0.16+ stdlib. The whole code
fits in `src/` and reads top-to-bottom.

## Quick start

### Generic ABI

```javascript
import { readFileSync } from 'node:fs';

const { instance } = await WebAssembly.instantiate(
  readFileSync('zig-out/bin/zopa.wasm'),
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
  type: 'compare', op: 'eq',
  left:  { type: 'ref',   path: ['input', 'user', 'role'] },
  right: { type: 'value', value: 'admin' },
});

console.log(evaluate(ip, il, ap, al)); // 1 = allow
free(ip); free(ap);
```

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
   |          |                       |  ast.buildModule|
   |          |  <-----------------   |  evalModule     |
   |          |    1 / 0 / -1         |  arena.reset    |
   +----------+                       +-----------------+
```

`host_allocator` (`std.heap.wasm_allocator`) lives for the module's
lifetime and backs every host-visible buffer. The request arena is
allocated on top of it and reset at the end of every `evaluate()`,
including the proxy-wasm callback path.

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

zopa runs the same suite under three hosts. None of them are
required; pick what's installed.

```bash
zig build test-unit         # Zig host-side unit tests
zig build test              # Node.js integration (must have node 18+)
zig build test-wasmtime     # wasmtime via Python (see test/requirements.txt)
zig build test-envoy        # real Envoy (brew install envoy)
zig build test-conformance  # `opa parse` + tools/rego2ast.py + zopa
zig build bench             # zopa-only latency benchmark
zig build test-all          # everything available
```

Setup for the Python suite:

```bash
python3 -m venv .venv-test
.venv-test/bin/pip install -r test/requirements.txt
```

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
