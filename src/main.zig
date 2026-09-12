//! Wasm entry point.
//!
//! Two ABIs share this module:
//!
//! - proxy-wasm 0.2.1 lifecycle callbacks, defined in `proxy_wasm.zig`.
//! - A generic ABI for hosts that don't speak proxy-wasm, in two
//!   flavours: `evaluate(input, ast)` hands over the policy on every
//!   call, while `policy_compile` / `evaluate_compiled` let a host
//!   build it once and keep it. The second is what proxy-wasm has
//!   always done internally, and what a host serving traffic wants.
//!
//! All of them use the `malloc` / `free` pair below for buffers that
//! cross the boundary. `free` takes only a pointer; the length lives in
//! a usize prefix in front of the payload.

const std = @import("std");
const memory = @import("memory.zig");
const eval = @import("eval.zig");
const policy = @import("policy.zig");

/// The one registry the compiled-policy exports address. Lives for the
/// module's lifetime; policies inside it live until the host releases
/// them. Held here rather than in `policy.zig` so that module stays
/// allocator-agnostic and testable off wasm.
var policies: policy.Registry = .{ .gpa = memory.host_allocator };

// Force the proxy-wasm module into the build graph. Without this
// reference its `export fn` declarations never reach the wasm export
// table.
comptime {
    _ = @import("proxy_wasm.zig");
}

/// Allocate `len` bytes in wasm linear memory and return the payload
/// pointer. Returns 0 on OOM.
export fn malloc(len: usize) ?[*]u8 {
    return memory.hostMalloc(len);
}

/// Same allocator under the name proxy-wasm ABI vNEXT uses. Hosts
/// probe for this export first and fall back to `malloc`; exporting
/// both costs one indirection and keeps the module loadable on either
/// generation of host.
export fn proxy_on_memory_allocate(len: usize) ?[*]u8 {
    return memory.hostMalloc(len);
}

/// Free a buffer previously returned by `malloc`.
///
/// The pointer is nullable because a host that hands back 0 would
/// otherwise send `hostFree` reading a length prefix from just below
/// address zero.
export fn free(ptr: ?[*]u8) void {
    if (ptr) |p| memory.hostFree(p);
}

/// Run one evaluation. Returns 1 (allow), 0 (deny), or -1 (error).
///
/// The arena reset in `defer` ensures every exit path -- success,
/// deny, or error -- leaves the per-request arena empty.
export fn evaluate(
    input_ptr: [*]const u8,
    input_len: usize,
    ast_ptr: [*]const u8,
    ast_len: usize,
) i32 {
    defer memory.resetRequestArena();

    const arena = memory.requestArena();
    const input = input_ptr[0..input_len];
    const ast_bytes = ast_ptr[0..ast_len];

    const decision = eval.evaluate(arena, input, ast_bytes) catch return -1;
    return if (decision) 1 else 0;
}

/// Run one evaluation against an explicit target rule. Same return
/// codes as `evaluate`. Hosts that want to drive a non-default rule
/// (`allow_response` for the response phase, `allow_body` for the
/// body phase, or any other target name) call this instead of the
/// default `evaluate`.
export fn evaluate_target(
    input_ptr: [*]const u8,
    input_len: usize,
    ast_ptr: [*]const u8,
    ast_len: usize,
    target_ptr: [*]const u8,
    target_len: usize,
) i32 {
    defer memory.resetRequestArena();

    const arena = memory.requestArena();
    const input = input_ptr[0..input_len];
    const ast_bytes = ast_ptr[0..ast_len];
    const target = target_ptr[0..target_len];

    const decision = eval.evaluateWithTarget(arena, input, ast_bytes, target) catch return -1;
    return if (decision) 1 else 0;
}

/// Run one evaluation against `package.rule`. Used by the
/// conformance harness to dispatch into a Rego module's specific
/// package (e.g. `authz`) without the host having to know about
/// zopa's internal `Modules` bundle representation.
export fn evaluate_addressed(
    input_ptr: [*]const u8,
    input_len: usize,
    ast_ptr: [*]const u8,
    ast_len: usize,
    package_ptr: [*]const u8,
    package_len: usize,
    target_ptr: [*]const u8,
    target_len: usize,
) i32 {
    defer memory.resetRequestArena();

    const arena = memory.requestArena();
    const input = input_ptr[0..input_len];
    const ast_bytes = ast_ptr[0..ast_len];
    const package = package_ptr[0..package_len];
    const target = target_ptr[0..target_len];

    const decision = eval.evaluateAddressed(arena, input, ast_bytes, package, target) catch return -1;
    return if (decision) 1 else 0;
}

// Compiled-policy ABI.
//
// `evaluate` and friends above re-parse and rebuild the policy on every
// call, because they are handed the AST bytes and cannot know they are
// the ones from last time. A host that drives the same policy across
// many requests -- which is every host that isn't a test -- should
// compile once here and evaluate against the handle. On the benchmark's
// RBAC fixture the parse is most of the per-call cost.

/// Build a policy and return a handle for it. Returns -1 if the AST
/// will not parse or will not build; the handle is otherwise a positive
/// integer the host holds until it calls `policy_release`.
///
/// Failing to release leaks the policy for the life of the module.
/// Nothing here can know when a host is finished with one, so this is
/// the same contract as `malloc`.
export fn policy_compile(ast_ptr: [*]const u8, ast_len: usize) i32 {
    // Building the policy allocates only on the policy's own arena, but
    // the JSON parse behind it can leave scratch on the request arena,
    // so reset it here as every other entry point does.
    defer memory.resetRequestArena();

    const handle = policies.compile(ast_ptr[0..ast_len]) catch return -1;
    return @intCast(handle);
}

/// Release a policy built by `policy_compile`. Returns 1 if a live
/// policy was freed and 0 if the handle was never issued or has already
/// been released -- a double release is a reported no-op, not a second
/// free.
export fn policy_release(handle: i32) i32 {
    if (handle <= 0) return 0;
    return if (policies.release(@intCast(handle))) 1 else 0;
}

/// Evaluate the default `allow` rule against a held policy. Same return
/// codes as `evaluate`: 1 allow, 0 deny, -1 error. A stale or forged
/// handle is an error, so it denies.
export fn evaluate_compiled(
    handle: i32,
    input_ptr: [*]const u8,
    input_len: usize,
) i32 {
    return evaluateCompiledAddressed(handle, input_ptr[0..input_len], "", eval.default_target_rule);
}

/// Evaluate `package.rule` against a held policy. The compiled-policy
/// counterpart of `evaluate_addressed`.
export fn evaluate_compiled_addressed(
    handle: i32,
    input_ptr: [*]const u8,
    input_len: usize,
    package_ptr: [*]const u8,
    package_len: usize,
    target_ptr: [*]const u8,
    target_len: usize,
) i32 {
    return evaluateCompiledAddressed(
        handle,
        input_ptr[0..input_len],
        package_ptr[0..package_len],
        target_ptr[0..target_len],
    );
}

fn evaluateCompiledAddressed(
    handle: i32,
    input: []const u8,
    target_package: []const u8,
    target_rule: []const u8,
) i32 {
    defer memory.resetRequestArena();

    if (handle <= 0) return -1;
    const arena = memory.requestArena();
    const decision = policies.evaluateAddressed(
        arena,
        @intCast(handle),
        input,
        target_package,
        target_rule,
    ) catch return -1;
    return if (decision) 1 else 0;
}
