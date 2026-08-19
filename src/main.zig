//! Wasm entry point.
//!
//! Two ABIs share this module:
//!
//! - proxy-wasm 0.2.1 lifecycle callbacks, defined in `proxy_wasm.zig`.
//! - A generic `evaluate(input, ast)` for hosts that don't speak
//!   proxy-wasm.
//!
//! Both use the `malloc` / `free` pair below for buffers that cross
//! the boundary. `free` takes only a pointer; the length lives in a
//! usize prefix in front of the payload.

const std = @import("std");
const memory = @import("memory.zig");
const eval = @import("eval.zig");

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
