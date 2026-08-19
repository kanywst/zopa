# proxy-wasm integration

zopa implements the [proxy-wasm 0.2.1][spec] ABI. This document
covers what's exported, what's imported, and the assumptions zopa
makes about the host.

[spec]: https://github.com/proxy-wasm/spec/blob/master/abi-versions/v0.2.1/README.md

## ABI version negotiation

zopa exports a single empty function whose name encodes the supported
version:

```text
proxy_abi_version_0_2_1
```

A host that supports a different version should refuse to load.

## Exports

### Buffer ownership

| Name                       | Signature            | Notes                                                                                                               |
| -------------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------- |
| `malloc`                   | `(size: i32) -> i32` | Returns 0 on OOM. The block has a length prefix in front of the payload; the host sees only the payload pointer.    |
| `proxy_on_memory_allocate` | `(size: i32) -> i32` | The same allocator under the name proxy-wasm ABI vNEXT uses. Hosts probe for it first and fall back to `malloc`.    |
| `free`                     | `(ptr: i32) -> void` | Length is recovered from the prefix; no length argument needed. A null pointer is ignored rather than dereferenced. |

### Lifecycle

| Name                        | Signature                                         | Status                                                                                                                                                                                                                                                                                |
| --------------------------- | ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `proxy_on_vm_start`         | `(root_id, vm_config_size) -> i32`                | Returns 1 (OK).                                                                                                                                                                                                                                                                       |
| `proxy_on_configure`        | `(context_id, config_size) -> i32`                | Reads the policy AST JSON via `proxy_get_buffer_bytes(BufferType.PluginConfiguration)`, then parses and builds it onto a long-lived arena. Returns 0 -- an unrecoverable load failure, as far as Envoy is concerned -- if the configuration is empty, unreadable, or not a valid AST. |
| `proxy_on_context_create`   | `(context_id, parent_context_id) -> void`         | No-op.                                                                                                                                                                                                                                                                                |
| `proxy_on_request_headers`  | `(context_id, num_headers, end_of_stream) -> i32` | Builds the request-side input and evaluates against the `allow` target rule. `Action.Continue` on allow; on deny, sends a 403 via `proxy_send_local_response` and returns `Action.Pause`.                                                                                             |
| `proxy_on_request_body`     | `(context_id, body_size, end_of_stream) -> i32`   | Buffers (`StopIterationAndBuffer`) until end of stream, then reads up to `max_body_bytes` (64 KiB) and evaluates `allow_body`. 403 + Pause on deny. No-op when the policy has no `allow_body` rule.                                                                                   |
| `proxy_on_response_headers` | `(context_id, num_headers, end_of_stream) -> i32` | Builds a response-side input (`{response: {status, headers}}`) and evaluates against `allow_response`. Replaces the upstream response with a 503 on deny.                                                                                                                             |
| `proxy_on_done`             | `(context_id) -> i32`                             | Returns 1.                                                                                                                                                                                                                                                                            |

### Phase-to-target mapping

| Phase                       | Target rule      | Input shape                        | Deny status |
| --------------------------- | ---------------- | ---------------------------------- | ----------- |
| `proxy_on_request_headers`  | `allow`          | `{method, path, headers}`          | 403         |
| `proxy_on_request_body`     | `allow_body`     | `{body, body_raw, body_truncated}` | 403 + Pause |
| `proxy_on_response_headers` | `allow_response` | `{response: {status, headers}}`    | 503         |

The three phases evaluate independently. A single `Modules` bundle
can carry rules for each phase.

**Phase opt-in via rule name.** At configure time the shim walks the
compiled AST looking for rules named `allow_body` and `allow_response`.
If either is absent the corresponding callback short-circuits as a
no-op without running `evaluate`. This preserves v0.1.0 behaviour for
policies that only define `allow`: the body and response phases are
silent until the user opts in by writing a rule with the matching name.

Detection is a real AST walk, not a substring match over the policy
text, so a literal `"allow_body"` string sitting in policy *data*
cannot switch the body phase on.

**Body buffering.** The body callback returns `StopIterationAndBuffer`
for every chunk before end of stream. That is not optional: with
`Continue`, the host forwards each fragment as it arrives and the
buffer visible at end of stream holds only the tail, so a policy
reading `input.body.amount` on a body split across two TCP segments
would be deciding on a suffix. Buffering costs latency on multi-chunk
bodies, which is why the whole callback is gated on an `allow_body`
rule existing.

**Bodyless requests.** A zero-length body is evaluated like any other:
returning early would skip `allow_body` entirely, default included, so
a deny-by-default body policy would allow anything sent with
`Content-Length: 0`. What zopa cannot do is make the callback happen --
Envoy does not invoke `proxy_on_request_body` at all for a request that
carries no body, which `examples/envoy/run.sh` pins with a check. A
condition that must hold for *every* request belongs in the `allow`
rule, which fires on headers.

**Oversized bodies.** A body larger than `max_body_bytes` is refused
with a 403 whenever the policy actually reads the body -- which the
shim knows from `body_deps.analyzeTarget` at configure time. Reading
`input.body_raw` counts as reading the body: it is the whole payload as
a string, so a rule like `contains(input.body_raw, "...")` needs every
byte just as much as one addressing `input.body.amount`. Reading
`input.body_truncated` does not count, since a policy keying on the
flag is asking to handle truncation itself. Evaluating
the prefix instead would look safe and would not be: a truncated JSON
body fails to parse, `input.body` becomes null, the deny rule watching
`input.body.amount` finds nothing to match, and the oversized request
sails through. Sending a big body would be a one-line bypass. When the
policy's `allow_body` rules don't read the body at all, truncation
changes nothing and evaluation proceeds.

### Generic ABI (not proxy-wasm)

| Name                 | Signature                                                                                           | Notes                                                                                        |
| -------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------- |
| `evaluate`           | `(input_ptr, input_len, ast_ptr, ast_len) -> i32`                                                   | Targets package `""` + rule `"allow"`. 1=allow, 0=deny, -1=error. Arena reset on every exit. |
| `evaluate_target`    | `(input_ptr, input_len, ast_ptr, ast_len, target_ptr, target_len) -> i32`                           | Same as `evaluate` but with an explicit target rule (e.g. `allow_response`, `allow_body`).   |
| `evaluate_addressed` | `(input_ptr, input_len, ast_ptr, ast_len, package_ptr, package_len, target_ptr, target_len) -> i32` | Dispatches into a specific `(package, rule)` pair within a `{"type":"modules", ...}` bundle. |

## Imports

The host must provide all of these. zopa does not feature-test --
unresolved imports cause module instantiation to fail.

| Name                             | Signature                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| `env.proxy_log`                  | `(level, msg, len) -> i32`                                                                                   |
| `env.proxy_get_buffer_bytes`     | `(buffer_type, start, max_size, return_data, return_size) -> i32`                                            |
| `env.proxy_get_header_map_pairs` | `(map_type, return_data, return_size) -> i32`                                                                |
| `env.proxy_get_header_map_value` | `(map_type, key_data, key_size, return_data, return_size) -> i32`                                            |
| `env.proxy_send_local_response`  | `(status, details_data, details_size, body_data, body_size, headers_data, headers_size, grpc_status) -> i32` |

## Input shape

For request-side evaluation the input is built by reading the
request header map:

```json
{
  "method":  "GET",
  "path":    "/orders/42",
  "headers": {
    "host":          "api.example.com",
    "authorization": "Bearer ...",
    "user-agent":    "..."
  }
}
```

The body phase gets its own shape:

```json
{
  "body":           { "amount": 5000 },
  "body_raw":       "{\"amount\":5000}",
  "body_truncated": false
}
```

`body` is the parsed document when the bytes are valid JSON and `null`
otherwise, so a policy can still match on `body_raw` for non-JSON
payloads. `body_truncated` reports that the bytes are a prefix; the
shim already denies in that case when the policy reads the body, but
the flag is addressable so a policy can decide for itself.

Header keys and values are escaped when the input is synthesised,
including every control byte below `0x20`. A header value containing
`"` or `\` cannot terminate its string literal and inject a sibling
key -- there is a round-trip property test for exactly this in
`src/wire.zig`.

`:method` and `:path` are pulled via `proxy_get_header_map_value`
because some hosts (Envoy with the `wamr` runtime, in particular)
omit pseudo-headers from `proxy_get_header_map_pairs`. Real headers
come from `pairs`. Pseudo-headers in `pairs` are filtered to avoid
duplication.

## Configuration

The plugin configuration string passed to Envoy is the policy AST
JSON:

```yaml
config:
  configuration:
    "@type": type.googleapis.com/google.protobuf.StringValue
    value: |
      { "type": "module", "rules": [ ... ] }
```

zopa copies those bytes onto a dedicated arena, parses them, and builds
the AST there once. The built policy lives for the lifetime of the
module, so per-request work is the input parse plus the rule walk --
the policy is never re-parsed. Reconfiguration builds the new policy
first and only discards the old arena once the new one is known to
build, so a bad reconfigure cannot strand a healthy filter with no
policy loaded.

An empty or invalid configuration is a configuration failure, not a
runtime one: `proxy_on_configure` returns 0 and logs. With Envoy's
default `fail_open: false` the filter refuses to start and requests get
a 503, which is the loud version of the right answer. The alternative
-- accepting the config and passing every request through -- is an
authorization filter that silently protects nothing.

## Failure posture

Every path that cannot reach a decision denies:

| Situation                                       | Result                                    |
| ----------------------------------------------- | ----------------------------------------- |
| No policy configured                            | Configure fails                           |
| Policy does not parse or does not build         | Configure fails                           |
| Callbacks run with no policy loaded             | 403                                       |
| Input synthesis fails (host call errors, OOM)   | 403                                       |
| Host refuses the body read                      | 403                                       |
| Header map is malformed                         | Headers dropped, rules still have to hold |
| Body over the 64 KiB cap, policy reads the body | 403                                       |
| Evaluation returns an error (`-1`)              | 403                                       |
| Response phase denies                           | 503                                       |

## Runtime selection

The Envoy build matters: pick a build that ships the runtime your
distribution provides.

| Envoy build                                      | Runtimes shipped |
| ------------------------------------------------ | ---------------- |
| Homebrew                                         | `null`, `wamr`   |
| Official Docker (`envoyproxy/envoy:*`)           | `null`, `v8`     |
| Self-built with `--define wasm=wamr,wasmtime,v8` | All of the above |

zopa is plain `wasm32-freestanding` with only the proxy-wasm imports,
so any of these runtimes works. Pick whatever your host has.

## Host quirks discovered while integrating

- **Pseudo-headers:** Envoy/wamr does not surface `:method`, `:path`,
  or `:authority` through `proxy_get_header_map_pairs`. zopa works
  around this by reading them individually with
  `proxy_get_header_map_value`.
- **Response phase headers:** by the time `proxy_on_response_headers`
  fires the request header map has been cleared. A response policy
  can't reference `input.method` from inside that callback.
- **Body phase pseudo-headers:** same as the response phase --
  pseudo-headers are gone by `proxy_on_request_body`. Body-aware
  policies need to snapshot what they care about during
  `proxy_on_request_headers`.
