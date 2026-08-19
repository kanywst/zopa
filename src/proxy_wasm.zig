//! proxy-wasm 0.2.1 shim. Spec: https://github.com/proxy-wasm/spec
//!
//! Lifecycle: `proxy_on_vm_start`, `proxy_on_configure`,
//! `proxy_on_context_create`, `proxy_on_request_headers`,
//! `proxy_on_request_body`, `proxy_on_response_headers`,
//! `proxy_on_done`. Request headers fire the "allow" target rule;
//! request body fires "allow_body" with `{"body": <parsed-json>,
//! "body_raw": <string>, "body_truncated": <bool>}` once the host
//! signals end of stream; response headers fire "allow_response" with
//! `{"response":{...}}`.
//!
//! Configuration: the policy AST JSON arrives via
//! `proxy_on_configure`. We copy it into `host_allocator` so it
//! outlives any single request.
//!
//! Memory: host-supplied buffers (header values, header pairs, body
//! bytes, configuration bytes) are allocated by the host calling our
//! `malloc`. We `hostFree` them once consumed.
//!
//! Failure posture: every path that can't reach a decision denies.
//! No policy, a policy that won't parse, a host call that errors, a
//! body we could only see part of -- all of them are a 403, never a
//! pass-through. An authorization filter that fails open is worse
//! than no filter, because the deployment believes it is protected.
//!
//! This file is deliberately thin. Anything that can run without a
//! wasm host -- header-map decoding, input synthesis -- lives in
//! `wire.zig`, where the unit tests can reach it.

const std = @import("std");
const ast = @import("ast.zig");
const body_deps = @import("body_deps.zig");
const eval = @import("eval.zig");
const json = @import("json.zig");
const memory = @import("memory.zig");
const wire = @import("wire.zig");

// ABI version negotiation: one empty export per supported version.

export fn proxy_abi_version_0_2_1() void {}

// Status codes from host functions (proxy-wasm 0.2.1).

const status_ok: i32 = 0;

// Buffer / map type identifiers.

const buffer_type_http_request_body: i32 = 0;
const buffer_type_plugin_configuration: i32 = 7;

const map_type_request_headers: i32 = 0;
const map_type_response_headers: i32 = 2;

// Action returned by stream callbacks.

const action_continue: i32 = 0;
const action_pause: i32 = 1;

/// Lifecycle callbacks return `1` for success in proxy-wasm.
const result_ok: i32 = 1;
const result_failed: i32 = 0;

// Log levels (proxy-wasm 0.2.1).

const log_level_warn: i32 = 3;
const log_level_error: i32 = 4;

// Target rule per phase. Disjoint names let one bundled policy carry
// rules for all three.
const request_target_rule: []const u8 = eval.default_target_rule;
const body_target_rule: []const u8 = "allow_body";
const response_target_rule: []const u8 = "allow_response";

/// Ceiling on how much request body we ask the host for. A policy
/// that reads the body and hits this cap denies -- see
/// `proxy_on_request_body`.
const max_body_bytes: usize = 64 * 1024;

// Host imports.

extern "env" fn proxy_log(
    level: i32,
    msg_data: [*]const u8,
    msg_size: usize,
) i32;

// Return-data pointers are nullable: per the proxy-wasm spec, hosts
// may signal "no data" with a null pointer + zero size for empty or
// missing values.
extern "env" fn proxy_get_buffer_bytes(
    buffer_type: i32,
    start: usize,
    max_size: usize,
    return_buffer_data: *?[*]u8,
    return_buffer_size: *usize,
) i32;

extern "env" fn proxy_get_header_map_pairs(
    map_type: i32,
    return_buffer_data: *?[*]u8,
    return_buffer_size: *usize,
) i32;

extern "env" fn proxy_get_header_map_value(
    map_type: i32,
    key_data: [*]const u8,
    key_size: usize,
    return_value_data: *?[*]u8,
    return_value_size: *usize,
) i32;

extern "env" fn proxy_send_local_response(
    response_code: i32,
    response_code_details_data: [*]const u8,
    response_code_details_size: usize,
    response_body_data: [*]const u8,
    response_body_size: usize,
    additional_headers_map_data: [*]const u8,
    additional_headers_size: usize,
    grpc_status: i32,
) i32;

// Hosts skip the pointer when the matching size is 0, but the type
// system still demands a non-null `[*]const u8`.
const empty_ptr: [*]const u8 = @ptrFromInt(1);

// Module-global state. proxy-wasm runs one VM per thread, so a
// plain global is safe.
//
// Known limitation: the root context id passed to `proxy_on_configure`
// is ignored, so a VM shared by two filter configurations keeps only
// the last policy. Envoy gives each `vm_config` its own VM unless
// `vm_id` is set explicitly, so the common deployment is unaffected;
// sharing a `vm_id` across filters with different policies is not
// supported. Tracked in ROADMAP.md.

/// Owns the policy bytes and the AST built from them. Separate from
/// the request arena because it has to survive every reset; separate
/// from raw `host_allocator` calls because the AST is a tree of small
/// nodes that would otherwise have to be walked to be freed. Replaced
/// wholesale on reconfigure.
var policy_arena: ?std.heap.ArenaAllocator = null;

/// The compiled policy. Built once at configure time, so the
/// per-request path is `json.parse(input)` plus the rule walk -- no
/// policy parse, no AST construction. On a realistic RBAC policy that
/// is most of the evaluation cost.
var compiled_policy: ?ast.Modules = null;

// Pre-flight facts computed at configure time so the body / response
// callbacks can short-circuit without paying the eval cost when the
// policy doesn't carry rules for those phases. Also preserves v0.1
// behaviour for users who only authored an `allow` rule: a missing
// `allow_response` rule must NOT replace every response with a 503.
//
// Detection is a real AST scan (not a substring match): we parse the
// policy JSON and walk every module's rule list looking for the
// target name. A literal string `"allow_body"` sitting in policy
// data therefore can't trip the flag and cause a spurious 403.
var has_allow_body: bool = false;
var has_allow_response: bool = false;

/// Whether the `allow_body` rules actually read the body. Set at
/// configure time from `body_deps.analyzeTarget`; decides whether a
/// truncated body is a problem.
var body_class: body_deps.Class = .no_body_refs;

// Lifecycle exports.

export fn proxy_on_vm_start(_: i32, _: i32) i32 {
    return result_ok;
}

/// Load the policy. Failing here is deliberate and loud: Envoy will
/// refuse to instantiate the filter, which (with the default
/// `fail_open: false`) means requests get a 503 instead of quietly
/// flowing through an authorization filter that holds no policy.
export fn proxy_on_configure(_: i32, configuration_size: i32) i32 {
    if (configuration_size <= 0) {
        logMsg(log_level_error, "zopa: no policy in plugin configuration; refusing to start");
        return result_failed;
    }

    var data: ?[*]u8 = null;
    var data_size: usize = 0;
    const status = proxy_get_buffer_bytes(
        buffer_type_plugin_configuration,
        0,
        @intCast(configuration_size),
        &data,
        &data_size,
    );
    if (status != status_ok) {
        logMsg(log_level_error, "zopa: could not read plugin configuration");
        return result_failed;
    }

    const ptr = data orelse {
        logMsg(log_level_error, "zopa: plugin configuration buffer was null");
        return result_failed;
    };
    defer if (data_size > 0) memory.hostFree(ptr);

    if (!compilePolicy(ptr[0..data_size])) {
        logMsg(log_level_error, "zopa: policy is not a valid AST; refusing to start");
        return result_failed;
    }

    return result_ok;
}

/// Copy, parse, and build the policy onto a fresh long-lived arena,
/// then record what the hot path needs to know: which phase target
/// rules exist, and whether the body rules read the body.
///
/// Returns false without touching the loaded policy if anything fails.
/// Failing configuration is better than accepting a policy that will
/// deny every request at runtime for a reason nobody can see, and
/// building the replacement before discarding the old arena means a bad
/// reconfigure can't strand a healthy filter with nothing loaded.
fn compilePolicy(policy_bytes: []const u8) bool {
    var arena = std.heap.ArenaAllocator.init(memory.host_allocator);

    // Not `errdefer`: this function reports failure as `false`, not as
    // an error, so `errdefer` would never fire and every rejected
    // policy would leak its arena.
    var adopted = false;
    defer if (!adopted) arena.deinit();

    const allocator = arena.allocator();

    // The AST aliases the policy bytes for every string, so the copy
    // has to live on the same arena as the nodes pointing into it.
    const policy = allocator.dupe(u8, policy_bytes) catch return false;
    const ast_value = json.parse(allocator, policy) catch return false;
    const bundle = ast.buildModulesBundle(allocator, ast_value) catch return false;

    var body_rules = false;
    var response_rules = false;
    for (bundle.modules) |module| {
        for (module.rules) |rule| {
            if (std.mem.eql(u8, rule.name, body_target_rule)) body_rules = true;
            if (std.mem.eql(u8, rule.name, response_target_rule)) response_rules = true;
        }
    }

    if (policy_arena) |*old| old.deinit();
    policy_arena = arena;
    adopted = true;
    compiled_policy = bundle;
    has_allow_body = body_rules;
    has_allow_response = response_rules;
    body_class = if (body_rules)
        body_deps.analyzeTarget(bundle, body_target_rule).class
    else
        .no_body_refs;

    return true;
}

export fn proxy_on_context_create(_: i32, _: i32) void {}

/// Evaluate against request headers under the `allow` target rule.
/// Deny short-circuits with a 403; allow lets the chain proceed.
/// `proxy_on_request_body` and `proxy_on_response_headers` then
/// fire `allow_body` / `allow_response` independently against their
/// own input shapes -- the three phases use disjoint target rules
/// so a single bundled policy can carry rules for each.
///
/// A deny returns `Pause`, not `Continue`. `proxy_send_local_response`
/// already ends the stream, and every proxy-wasm SDK's auth example
/// stops iteration afterwards; returning `Continue` asks the host to
/// keep running the filter chain on a request that has been answered.
///
/// Hosts clear `:method` / `:path` from the header map before
/// `proxy_on_request_body` fires, so a body rule that needs request
/// context still requires per-context snapshot plumbing. That is
/// tracked in `docs/proposals/body-aware-policies.md` § "v2".
export fn proxy_on_request_headers(_: i32, _: i32, _: i32) i32 {
    const policy = compiled_policy orelse {
        // Unreachable in a healthy deployment -- `proxy_on_configure`
        // refuses to start without a policy -- but if a host runs the
        // callbacks anyway, deny.
        logMsg(log_level_error, "zopa: request with no policy loaded; denying");
        denyWithStatus(403);
        return action_pause;
    };

    if (!evaluateRequest(policy)) {
        denyWithStatus(403);
        return action_pause;
    }
    return action_continue;
}

/// Evaluate against the request body under the `allow_body` target
/// rule, once the host signals end of stream.
///
/// Non-final chunks return `StopIterationAndBuffer` rather than
/// `Continue`. That is the only way the host accumulates the body:
/// with `Continue`, each chunk is forwarded upstream as it arrives and
/// the buffer visible at end of stream holds just the last fragment,
/// so a policy reading `input.body.amount` on a body split across two
/// TCP segments was deciding on a suffix. Buffering costs latency on
/// bodies that span chunks, which is why the whole callback is gated
/// on the policy actually having an `allow_body` rule.
///
/// A body larger than `max_body_bytes` is refused outright when the
/// policy reads the body. The alternative -- evaluate the prefix --
/// looks safe and isn't: a truncated JSON body fails to parse, `body`
/// becomes null, the deny rule that was watching `input.body.amount`
/// finds nothing to match, and the oversized request is allowed
/// through. Sending a big body would be a one-line bypass.
///
/// Hosts clear `:method` / `:path` from the header map by the time
/// this fires (Envoy/wamr behaviour), so a body rule that needs
/// header context still requires a per-context snapshot. Tracked in
/// `docs/proposals/body-aware-policies.md` § "v2".
export fn proxy_on_request_body(_: i32, body_size: i32, end_of_stream: i32) i32 {
    // Skip cheaply when the policy doesn't have an `allow_body` rule,
    // mirroring v0.1.0 behaviour where this callback was a no-op.
    if (!has_allow_body) return action_continue;
    if (end_of_stream == 0) return action_pause;
    if (body_size <= 0) return action_continue;

    const policy = compiled_policy orelse {
        denyWithStatus(403);
        return action_pause;
    };

    const size: usize = @intCast(body_size);
    const truncated = size > max_body_bytes;
    if (truncated and body_class != .no_body_refs) {
        logMsg(log_level_warn, "zopa: request body exceeds buffer cap; denying");
        denyWithStatus(403);
        return action_pause;
    }

    if (!evaluateBody(policy, size, truncated)) {
        denyWithStatus(403);
        return action_pause;
    }
    return action_continue;
}

/// Evaluate against response status + headers under the
/// `allow_response` target rule. Deny replaces the response with a
/// 503; allow lets the upstream response through unchanged.
///
/// This one returns `Continue` after the local response: on the
/// encode path Envoy has already committed to a response, and
/// stopping iteration there strands the stream rather than replacing
/// it.
///
/// Request-side policy targeting "allow" runs in
/// `proxy_on_request_headers`; the phases use disjoint target rules
/// so a single bundled policy can carry all of them.
export fn proxy_on_response_headers(_: i32, _: i32, _: i32) i32 {
    // Skip cheaply when the policy doesn't have an `allow_response`
    // rule. Without this gate every response would be replaced with
    // a 503 for any policy that only carried request-side rules.
    if (!has_allow_response) return action_continue;

    const policy = compiled_policy orelse {
        denyWithStatus(503);
        return action_continue;
    };

    if (!evaluateResponse(policy)) {
        denyWithStatus(503);
    }
    return action_continue;
}

export fn proxy_on_done(_: i32) i32 {
    return result_ok;
}

// ---------------------------------------------------------------------------
// Per-phase evaluation. Each one builds its input on the request arena
// and resets it on the way out, so an error path leaves nothing behind.
// Errors fold into deny -- never default to allow on failure.
// ---------------------------------------------------------------------------

fn evaluateRequest(policy: ast.Modules) bool {
    const arena = memory.requestArena();
    defer memory.resetRequestArena();
    const allocator = arena.allocator();

    const method = readSingleHeader(allocator, map_type_request_headers, ":method") catch return false;
    const path = readSingleHeader(allocator, map_type_request_headers, ":path") catch return false;
    const headers = readAllHeaders(allocator, map_type_request_headers);

    const input = wire.buildRequestInput(
        allocator,
        method orelse "",
        path orelse "",
        headers,
    ) catch return false;

    return decide(arena, input, policy, request_target_rule);
}

fn evaluateBody(policy: ast.Modules, body_size: usize, truncated: bool) bool {
    const arena = memory.requestArena();
    defer memory.resetRequestArena();
    const allocator = arena.allocator();

    const cap = @min(body_size, max_body_bytes);
    // A body we were told exists but could not read is a deny, not an
    // empty body evaluated as if the request carried nothing.
    const body = readBodyBytes(allocator, cap) catch {
        logMsg(log_level_warn, "zopa: could not read request body; denying");
        return false;
    };
    const input = wire.buildBodyInput(allocator, body, truncated) catch return false;

    return decide(arena, input, policy, body_target_rule);
}

fn evaluateResponse(policy: ast.Modules) bool {
    const arena = memory.requestArena();
    defer memory.resetRequestArena();
    const allocator = arena.allocator();

    const status = readSingleHeader(allocator, map_type_response_headers, ":status") catch return false;
    const headers = readAllHeaders(allocator, map_type_response_headers);

    const input = wire.buildResponseInput(allocator, status orelse "", headers) catch return false;

    return decide(arena, input, policy, response_target_rule);
}

/// Every phase dispatches into the implicit `""` package: a
/// proxy-wasm filter carries one policy and selects the rule by phase,
/// not by package. Multi-package addressing is a host-driven feature
/// and goes through the `evaluate_addressed` export instead.
fn decide(
    arena: *std.heap.ArenaAllocator,
    input: []const u8,
    policy: ast.Modules,
    target_rule: []const u8,
) bool {
    return eval.evaluateCompiled(arena, input, policy, "", target_rule) catch false;
}

// ---------------------------------------------------------------------------
// Host reads. These own the malloc/free dance with the host and hand
// plain slices to `wire.zig`.
// ---------------------------------------------------------------------------

/// Pull the request body from the host.
///
/// A host that refuses the read is an error, not an empty body. The two
/// are indistinguishable downstream -- both produce `body: null,
/// body_raw: ""` -- and that is a fail-open: a rule watching for a
/// marker in the body finds nothing in `""` and lets the request
/// through. The caller turns the error into a deny.
///
/// `data_size == 0` with an OK status is a genuinely empty body and is
/// returned as such, though `proxy_on_request_body` has already skipped
/// out on `body_size <= 0` before getting here.
fn readBodyBytes(allocator: std.mem.Allocator, cap: usize) ![]const u8 {
    var data: ?[*]u8 = null;
    var data_size: usize = 0;
    const status = proxy_get_buffer_bytes(
        buffer_type_http_request_body,
        0,
        cap,
        &data,
        &data_size,
    );
    if (status != status_ok) return error.BodyUnavailable;
    if (data_size == 0) return &[_]u8{};
    const ptr = data orelse return error.BodyUnavailable;
    defer memory.hostFree(ptr);
    return try allocator.dupe(u8, ptr[0..data_size]);
}

/// Read one header value. `null` for missing keys (distinct from
/// present-but-empty).
fn readSingleHeader(
    allocator: std.mem.Allocator,
    map_type: i32,
    key: []const u8,
) !?[]const u8 {
    var data: ?[*]u8 = null;
    var data_size: usize = 0;
    const status = proxy_get_header_map_value(
        map_type,
        key.ptr,
        key.len,
        &data,
        &data_size,
    );
    if (status != status_ok) return null;
    // Hosts may signal "missing" with null + 0; do not free in that case.
    if (data_size == 0) return null;
    const ptr = data orelse return null;
    defer memory.hostFree(ptr);
    return try allocator.dupe(u8, ptr[0..data_size]);
}

/// Read and decode the whole header map. A host error or a malformed
/// buffer yields no headers: the pseudo-headers a policy usually keys
/// on are fetched separately, and an unreadable map should not by
/// itself decide the request. The rules still have to hold.
fn readAllHeaders(allocator: std.mem.Allocator, map_type: i32) []const wire.HeaderPair {
    var data: ?[*]u8 = null;
    var data_size: usize = 0;
    const status = proxy_get_header_map_pairs(map_type, &data, &data_size);
    if (status != status_ok) return &[_]wire.HeaderPair{};
    if (data_size == 0) return &[_]wire.HeaderPair{};
    const ptr = data orelse return &[_]wire.HeaderPair{};
    defer memory.hostFree(ptr);

    return wire.decodeHeaderMap(allocator, ptr[0..data_size]) catch &[_]wire.HeaderPair{};
}

// ---------------------------------------------------------------------------
// Host writes.
// ---------------------------------------------------------------------------

fn denyWithStatus(status: i32) void {
    _ = proxy_send_local_response(
        status,
        empty_ptr,
        0,
        empty_ptr,
        0,
        empty_ptr,
        0,
        -1,
    );
}

fn logMsg(level: i32, msg: []const u8) void {
    _ = proxy_log(level, msg.ptr, msg.len);
}
