//! Compiled policies held across calls, addressed by opaque handle.
//!
//! The generic `evaluate` export receives the AST bytes on every call
//! and cannot know they are the ones it parsed last time, so it pays a
//! JSON parse and an AST build per request. On a realistic RBAC policy
//! that is most of the cost -- `bench/README.md` has the measurement,
//! and it is the row where OPA's WASM build beats zopa. The proxy-wasm
//! shim never had this problem: `proxy_on_configure` builds the policy
//! once onto a long-lived arena and keeps it. This module gives plain
//! `WebAssembly.Module` hosts the same arrangement.
//!
//! Lifetimes: each compiled policy owns a private arena, holding both a
//! copy of the policy bytes and the AST built from them. The AST
//! aliases those bytes for every string, so the two cannot be
//! separated. The arena is freed only by `release`, which is the
//! host's job -- nothing here can know when a host is done with a
//! policy, so one that forgets leaks it for the life of the module.
//! That is the same contract as `malloc`.
//!
//! Handles are table indices, never pointers. A host that passes a
//! stale or forged handle gets `error.InvalidHandle`, which the export
//! layer turns into `-1` and every caller denies on. Handing out raw
//! pointers would turn the same mistake into a read of arbitrary linear
//! memory, which in an authorization engine is a bypass primitive
//! rather than a crash.
//!
//! The allocator is a field rather than `memory.host_allocator` so this
//! module can be tested natively: `std.heap.wasm_allocator` does not
//! compile off wasm, and a registry is exactly the kind of code whose
//! tests want `testing.allocator`'s leak checking. `main.zig` holds the
//! one instance the exports use and gives it the host allocator.

const std = @import("std");

const ast = @import("ast.zig");
const eval = @import("eval.zig");
const json = @import("json.zig");

/// Opaque policy identifier. Zero is never issued, so a zeroed
/// variable on the host side cannot name a live policy.
pub const Handle = u32;

pub const Error = error{InvalidHandle};

const Entry = struct {
    arena: std.heap.ArenaAllocator,
    bundle: ast.Modules,
};

pub const Registry = struct {
    gpa: std.mem.Allocator,

    /// Slot table. A released slot is nulled and reused, so a host that
    /// churns policies does not grow this without bound. Entries are
    /// heap-allocated so a table resize never moves an arena that live
    /// AST nodes were allocated from.
    slots: std.ArrayList(?*Entry) = .empty,

    /// Parse and build `policy_bytes` onto a private arena and return
    /// the handle addressing it. The caller keeps ownership of
    /// `policy_bytes`; this copies what it needs.
    pub fn compile(self: *Registry, policy_bytes: []const u8) !Handle {
        const entry = try self.gpa.create(Entry);
        errdefer self.gpa.destroy(entry);

        entry.arena = std.heap.ArenaAllocator.init(self.gpa);
        errdefer entry.arena.deinit();

        const allocator = entry.arena.allocator();
        const policy = try allocator.dupe(u8, policy_bytes);
        const ast_value = try json.parse(allocator, policy);
        entry.bundle = try ast.buildModulesBundle(allocator, ast_value);

        return try self.install(entry);
    }

    /// Place `entry` in the table and return its handle. Split out so
    /// the failure path in `compile` stays a plain `errdefer` chain.
    fn install(self: *Registry, entry: *Entry) !Handle {
        for (self.slots.items, 0..) |slot, i| {
            if (slot == null) {
                self.slots.items[i] = entry;
                return @intCast(i + 1);
            }
        }
        try self.slots.append(self.gpa, entry);
        return @intCast(self.slots.items.len);
    }

    fn lookup(self: *Registry, handle: Handle) Error!*Entry {
        if (handle == 0 or handle > self.slots.items.len) return Error.InvalidHandle;
        return self.slots.items[handle - 1] orelse Error.InvalidHandle;
    }

    /// Evaluate `target_package.target_rule` against a held policy.
    /// Only the input parse and the rule walk happen here; the policy
    /// is already built.
    pub fn evaluateAddressed(
        self: *Registry,
        arena: *std.heap.ArenaAllocator,
        handle: Handle,
        input_json: []const u8,
        target_package: []const u8,
        target_rule: []const u8,
    ) !bool {
        const entry = try self.lookup(handle);
        return eval.evaluateCompiled(arena, input_json, entry.bundle, target_package, target_rule);
    }

    /// Free a compiled policy. Returns false for a handle that was
    /// never issued or has already been released, so a double release
    /// is a reported no-op rather than a second `deinit` of a dead
    /// arena.
    pub fn release(self: *Registry, handle: Handle) bool {
        const entry = self.lookup(handle) catch return false;
        entry.arena.deinit();
        self.gpa.destroy(entry);
        self.slots.items[handle - 1] = null;
        return true;
    }

    /// Number of live policies. For tests, and for a host that wants to
    /// assert it is not leaking.
    pub fn liveCount(self: *const Registry) usize {
        var n: usize = 0;
        for (self.slots.items) |slot| {
            if (slot != null) n += 1;
        }
        return n;
    }

    /// Release everything and drop the table. The wasm module never
    /// calls this -- it has no shutdown -- but a native embedder and
    /// every test does.
    pub fn deinit(self: *Registry) void {
        for (self.slots.items) |slot| {
            if (slot) |entry| {
                entry.arena.deinit();
                self.gpa.destroy(entry);
            }
        }
        self.slots.deinit(self.gpa);
        self.slots = .empty;
    }
};

// -------------------------------------------------------------- tests

const testing = std.testing;

const rbac_policy =
    \\{"type":"modules","modules":[{"type":"module","package":"authz","rules":[
    \\  {"type":"rule","name":"allow","default":true,"value":{"type":"value","value":false}},
    \\  {"type":"rule","name":"allow","body":[
    \\    {"type":"compare","op":"eq",
    \\     "left":{"type":"ref","path":["input","user","role"]},
    \\     "right":{"type":"value","value":"admin"}}]}]}]}
;

test "a held policy answers the same as the parse-every-call path" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    const handle = try registry.compile(rbac_policy);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const admin = "{\"user\":{\"role\":\"admin\"}}";
    const guest = "{\"user\":{\"role\":\"guest\"}}";

    try testing.expect(try registry.evaluateAddressed(&arena, handle, admin, "authz", "allow"));
    try testing.expect(!try registry.evaluateAddressed(&arena, handle, guest, "authz", "allow"));

    // The same inputs through the one-shot export have to agree. If
    // holding a policy could change a decision, this would be a bypass
    // rather than an optimisation.
    try testing.expect(try eval.evaluateAddressed(&arena, admin, rbac_policy, "authz", "allow"));
    try testing.expect(!try eval.evaluateAddressed(&arena, guest, rbac_policy, "authz", "allow"));
}

test "a held policy survives the request arena being reset under it" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    const handle = try registry.compile(rbac_policy);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // The whole point of the handle is that the AST outlives the reset.
    // If the two lifetimes were ever confused, the policy would be read
    // after free somewhere in this loop.
    for (0..64) |_| {
        try testing.expect(try registry.evaluateAddressed(&arena, handle, "{\"user\":{\"role\":\"admin\"}}", "authz", "allow"));
        _ = arena.reset(.retain_capacity);
    }
}

test "handles are independent of each other" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    const a = try registry.compile(rbac_policy);
    const b = try registry.compile(
        \\{"type":"module","rules":[{"type":"rule","name":"allow","value":{"type":"value","value":true}}]}
    );
    try testing.expect(a != b);
    try testing.expectEqual(@as(usize, 2), registry.liveCount());

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expect(!try registry.evaluateAddressed(&arena, a, "{}", "authz", "allow"));
    try testing.expect(try registry.evaluateAddressed(&arena, b, "{}", "", "allow"));

    // Releasing one must not disturb the other.
    try testing.expect(registry.release(a));
    try testing.expectEqual(@as(usize, 1), registry.liveCount());
    try testing.expect(try registry.evaluateAddressed(&arena, b, "{}", "", "allow"));
}

test "released, doubled, zero and out-of-range handles are rejected, not followed" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const handle = try registry.compile(rbac_policy);
    try testing.expect(registry.release(handle));

    // Any of these reaching a dereference would be reading whatever the
    // allocator put in that memory next, which is why handles are table
    // indices and not pointers.
    try testing.expectError(Error.InvalidHandle, registry.evaluateAddressed(&arena, handle, "{}", "authz", "allow"));
    try testing.expect(!registry.release(handle));
    try testing.expectError(Error.InvalidHandle, registry.evaluateAddressed(&arena, 0, "{}", "authz", "allow"));
    try testing.expectError(Error.InvalidHandle, registry.evaluateAddressed(&arena, 9999, "{}", "authz", "allow"));
    try testing.expect(!registry.release(9999));
}

test "a released slot is reused rather than growing the table" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    const first = try registry.compile(rbac_policy);
    try testing.expect(registry.release(first));
    const second = try registry.compile(rbac_policy);

    try testing.expectEqual(first, second);
    try testing.expectEqual(@as(usize, 1), registry.slots.items.len);
}

test "a policy that will not build leaves no handle and no leak" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    // Two failure points that unwind different amounts of arena: the
    // JSON parse, and the AST build behind it.
    try testing.expectError(error.UnexpectedToken, registry.compile("{ not json"));
    try testing.expectError(error.DuplicateDefaultRule, registry.compile(
        \\{"type":"module","rules":[
        \\  {"type":"rule","name":"allow","default":true,"value":{"type":"value","value":false}},
        \\  {"type":"rule","name":"allow","default":true,"value":{"type":"value","value":true}}]}
    ));

    try testing.expectEqual(@as(usize, 0), registry.liveCount());
    try testing.expectEqual(@as(usize, 0), registry.slots.items.len);
}
