# Streaming evaluation

Status: **Open.** `src/body_deps.zig`, the configure-time analyser this design is built on, shipped in v0.2.0 and was wired into the shim in v0.3.0 — but it drives the truncated-body deny decision, not streaming. Nothing evaluates incrementally: the body phase still buffers to the 64 KiB cap and denies past it. This is the largest unbuilt design in the directory. Tracking: ROADMAP.md → Longer term.

## Motivation

The body-aware policy proposal (`body-aware-policies.md`) buffers the full request body up to `max_body_bytes` before evaluating. That's fine for small JSON payloads. It falls down for:

- Large file uploads. Buffering 50 MB to test "is this user allowed to POST to this path" is wasteful when the decision doesn't need the body at all.
- gRPC and protobuf streams where the policy may only need the first few framed messages.
- Latency-sensitive paths where blocking on the full body adds tens of milliseconds before the decision is even possible.

For policies that don't reference `input.body`, buffering should not happen at all. For policies that reference only a prefix (`input.body.action`, `input.body.user_id`), buffering should stop as soon as the prefix is decidable. Streaming evaluation makes those optimizations possible.

## Goals

1. Static AST analysis at configure time to classify each policy as one of:

   | Class                        | Body buffering required |
   | ---------------------------- | ----------------------- |
   | No body refs                 | None (decide on headers)|
   | Body refs, prefix-only       | Until prefix resolved   |
   | Body refs, full-tree         | Up to `max_body_bytes`  |

1. For prefix-only policies: a streaming JSON parser path that lets `evaluate` decide partway through the body when the referenced prefix is fully resolved. The rest of the body is allowed to flow through unbuffered.
1. For no-body-refs policies: skip `proxy_on_request_body` entirely. The decision is locked in at headers time.
1. The streaming path is opt-in. Policies that want strict, full-body eval continue to use the buffered path; the analysis classifies conservatively (when in doubt, full-tree).

## Non-goals

- Streaming response bodies. Same idea, but tracked separately under `response-side-policies.md` extensions.
- Decisions on partial header sets. Headers are atomic in proxy-wasm; no streaming there.
- Refusing the body mid-stream after data has already been forwarded. zopa decides allow/deny *before* the body forwards (Envoy buffers internally up to its own configured limits).

## Design sketch

### AST classifier

A static walk over the configured policy AST that records every `input.body...` ref encountered:

```zig
const BodyDeps = struct {
    refs_body:   bool = false,
    refs_paths:  std.ArrayList([]const []const u8),  // prefix tree
    refs_whole:  bool = false,                       // body referenced as a unit
};

fn classifyBodyDeps(module: *const ast.Module) BodyDeps;
```

`refs_whole = true` happens when the policy uses `input.body` directly (not just a sub-path) or when iteration would require the full parsed object. In that case, fall back to the buffered path.

### Streaming JSON parser

`src/json.zig` gains an iterative path that emits `(path, value)` events as the body streams in:

```zig
pub const StreamEvent = union(enum) {
    enter_object: []const u8,        // path so far
    leave_object: void,
    field: struct { path: [][]const u8, value: Value },
    done: void,
};
```

The streaming evaluator subscribes to events and binds resolved refs into the `input` lazily. As soon as every ref in the policy's prefix set is resolved, evaluation can run.

### Decision short-circuit

Once the streaming evaluator reaches a resolved decision, it tells the host:

- allow → return `Continue` from `proxy_on_request_body` for the current chunk and stop subscribing to body events.
- deny → call `proxy_send_local_response(403)` and return Pause.

If the body finishes before the prefix set is fully resolved (the caller didn't include the expected field), treat the missing path as undefined (deny-by-default per Rego semantics).

## API impact

- New plugin config field `streaming: { enabled: bool, max_buffer: size }`. Default `enabled: true` once the implementation has at least one full release of stability.
- Per-context state grows to hold the partial input being assembled.
- AST schema unchanged.

## Test plan

- Unit tests for `classifyBodyDeps` covering each class of policy.
- Streaming parser unit tests: feed a JSON byte-by-byte, assert events fire in order.
- Integration test: a policy that references only `input.body.action` decides before the full payload is delivered. Measure that evaluation latency is independent of payload size.
- Negative test: a policy that needs `input.body.items[*].sku` falls back to the buffered path even with `streaming.enabled: true`.

## Open questions

- The streaming parser nearly doubles the size of `src/json.zig`. Worth running a sizing experiment before committing: does `--release=small` keep zopa.wasm under 80 KB with both paths present?
- How aggressive is the prefix analysis? A conservative pass classifies more policies as "full-tree" and forfeits the optimization. A precise pass requires reasoning about `some` / `every` over body arrays, which is non-trivial.
- Should the streaming path also feed Envoy's body forwarding so large uploads don't pause? Probably yes, but the proxy-wasm body ABI semantics need a careful read first.
