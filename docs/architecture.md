# Architecture

## Modules

| File                 | Role                                                                                                                                     |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `src/main.zig`       | Generic ABI exports (`malloc`, `free`, `evaluate`). Pulls `proxy_wasm.zig` into the build via a `comptime` reference.                    |
| `src/memory.zig`     | Long-lived host allocator + per-request arena. Length-prefixed `hostMalloc` / `hostFree` for the proxy-wasm buffer ownership convention. |
| `src/json.zig`       | Recursive-descent JSON parser. Returns a `Value` tree shared with the AST module.                                                        |
| `src/ast.zig`        | `Module` / `Rule` / `Expr` types and the JSON-to-AST builders.                                                                           |
| `src/eval.zig`       | Evaluator. Linked-list scope frames for `some` / `every`. Explicit recursion cap.                                                        |
| `src/builtins.zig`   | Builtin function table for the `call` node.                                                                                              |
| `src/body_deps.zig`  | Configure-time analysis of how a policy references the request body. Decides whether a truncated body is decision-relevant.              |
| `src/wire.zig`       | Header-map decoding and per-phase input synthesis. Deliberately free of ABI imports so unit tests can reach it on the host.              |
| `src/proxy_wasm.zig` | proxy-wasm 0.2.1 ABI shim. Lifecycle exports, host imports, per-phase evaluation.                                                        |

## Memory model

### Two allocators

`host_allocator` is the standard wasm freelist allocator
(`std.heap.wasm_allocator`). It backs every buffer that crosses the
host boundary; lifetime is decided by the host.

`request_arena` is a `std.heap.ArenaAllocator` initialised lazily on
the first call. Every `evaluate()` runs against it and ends with a
`reset(.retain_capacity)`. Pages stay mapped, so steady-state
evaluation does not invoke `memory.grow`.

### Length-prefixed boundary buffers

proxy-wasm hosts call our `malloc(size)` and our `free(ptr)` -- with
no length on the free side. The standard wasm allocator wants a
length, so `hostMalloc` reserves `@sizeOf(usize)` bytes in front of
every block, writes the size there, and returns a pointer to the
payload. `hostFree` walks back and recovers the size.

The prefix is `usize`-aligned via `alignedAlloc`, so the load is
safe.

### Ownership rules

| Buffer                                                   | Owner             | Freed by                                 |
| -------------------------------------------------------- | ----------------- | ---------------------------------------- |
| `malloc(n)` return                                       | Host              | Host calls `free(ptr)`                   |
| `host_allocator.dupe()` (e.g. `configured_policy`)       | wasm module       | Module on reconfigure / shutdown         |
| `arena.allocator().alloc()`                              | Per-request arena | `resetRequestArena()` at end of evaluate |
| The compiled policy (bytes + AST nodes)                  | Policy arena      | Replaced wholesale on reconfigure        |
| Borrowed input slices in `evaluate(in_ptr, in_len, ...)` | Host              | Host (we never free these)               |

The single rule that holds it together: a pointer minted by one
allocator must only be released by the matching free path. The
proxy-wasm shim is careful to call `memory.hostFree` on host-supplied
buffers; the evaluator never calls `free` at all -- it leans entirely
on the arena reset.

## Request flow

```text
host                                    wasm
  |                                       |
  | proxy_on_configure(size)               |
  | -- proxy_get_buffer_bytes ----------> |
  |                                       | configured_policy = dupe(policy_bytes)
  |                                       |
  | proxy_on_request_headers(...)          |
  | -- proxy_get_header_map_value(":method")
  | -- proxy_get_header_map_value(":path")
  | -- proxy_get_header_map_pairs ------> |
  |                                       | input = build JSON on arena
  |                                       | evaluate(input, configured_policy)
  |                                       |   -> json.parse * 2  (on arena)
  |                                       |   -> ast.buildModule (on arena)
  |                                       |   -> evalModule
  |                                       | arena.reset(.retain_capacity)
  | <- action_continue (allow)             |
  |    or proxy_send_local_response(403)   |
```

## Evaluation

`evalModule` picks every rule whose name matches the target
(`"allow"` by default) and OR-combines the bodies. A `default` rule
remembers its literal value as the fallback if no other rule fires.

Bodies are an implicit AND. Every expression in the body must hold.

`compare` resolves both sides to `Value` via `resolveValue`, which
also handles nested `not` and `compare` (folded back to `boolean`).
Nested iterators (`some` / `every` inside a body or as a value)
follow the same path.

Variable bindings introduced by `some` / `every` live in a stack-
allocated `Scope` linked list. Each iterator pushes a frame for the
duration of one body evaluation; refs walk the chain before falling
back to the input root.

Scope is local to the iterator. Bindings introduced inside a rule
body are not visible from that rule's `value` expression -- the
value is resolved with a fresh, empty scope. A policy that needs to
reference a body-bound variable from `value` must move the
computation inside the body or restructure to compute the value
inline. Lifting body bindings into the value position is on the
roadmap.

Recursion is capped at `max_eval_depth = 32`. Hitting the cap returns
`error.EvalTooDeep`, which the export wrapper folds to `-1` and the
proxy-wasm shim treats as deny.

## Why `wasm32-freestanding`

WASI would pull in syscall stubs we never use. `freestanding` keeps
the binary tight and the import surface minimal -- the host only
needs to provide the proxy-wasm imports we declare in
`proxy_wasm.zig`.
