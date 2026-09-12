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
//! Handles are not pointers. A host that passes a stale or forged
//! handle gets `error.InvalidHandle`, which the export layer turns into
//! `-1` and every caller denies on. Handing out raw pointers would turn
//! the same mistake into a read of arbitrary linear memory, which in an
//! authorization engine is a bypass primitive rather than a crash.
//!
//! A bare table index is not enough for that, though. Slots are reused,
//! so `release(h)` followed by another `compile` would reissue `h` for a
//! different policy, and a caller still holding the old `h` -- a cached
//! variable, a request in flight while the host reconfigures -- would
//! get an authoritative-looking decision from the wrong policy instead
//! of a denial. That is the same class of bug as the dangling pointer,
//! just bounded to "wrong policy" rather than "wrong memory". So a
//! handle carries a generation alongside the index, `lookup` checks it,
//! and a slot whose generation is exhausted is retired rather than
//! reused. Stale handles therefore always deny, which is what the docs
//! promise.
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

/// Opaque policy identifier: a slot index in the low bits and the
/// generation that slot was on when the handle was issued in the high
/// bits. Zero is never issued, so a zeroed variable on the host side
/// cannot name a live policy.
///
/// The layout stays inside 31 bits because the export signature is
/// `i32` and negative values are reserved for errors.
pub const Handle = u32;

const index_bits: u5 = 16;
const index_mask: u32 = (1 << index_bits) - 1;

/// Slots and generations are both capped by the split above. A host
/// that exhausts either is doing something no deployment does; both
/// limits fail the allocation rather than wrapping, because wrapping is
/// exactly the reuse this scheme exists to prevent.
const max_slots: usize = index_mask; // index 0..=65534, +1 when encoded
const max_generation: u32 = (1 << (31 - @as(u6, index_bits))) - 1;

pub const Error = error{ InvalidHandle, TooManyPolicies };

const Entry = struct {
    arena: std.heap.ArenaAllocator,
    bundle: ast.Modules,
};

const Slot = struct {
    entry: ?*Entry,
    /// Bumped every time this slot is filled. A handle issued at an
    /// earlier generation no longer resolves.
    generation: u32,
};

fn encode(index: usize, generation: u32) Handle {
    return (generation << index_bits) | @as(u32, @intCast(index + 1));
}

pub const Registry = struct {
    gpa: std.mem.Allocator,

    /// Slot table. A released slot is emptied and reused at a bumped
    /// generation, so a host that churns policies does not grow this
    /// without bound while old handles still stop resolving. Entries are
    /// heap-allocated so a table resize never moves an arena that live
    /// AST nodes were allocated from.
    slots: std.ArrayList(Slot) = .empty,

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
    ///
    /// A free slot is only reused if its generation can still advance.
    /// One that has run out is left empty forever: retiring a slot costs
    /// a table entry, while wrapping its generation would silently start
    /// handing out handles that collide with ones a host may still hold.
    fn install(self: *Registry, entry: *Entry) !Handle {
        for (self.slots.items, 0..) |*slot, i| {
            if (slot.entry == null and slot.generation < max_generation) {
                slot.entry = entry;
                slot.generation += 1;
                return encode(i, slot.generation);
            }
        }
        if (self.slots.items.len >= max_slots) return Error.TooManyPolicies;
        try self.slots.append(self.gpa, .{ .entry = entry, .generation = 1 });
        return encode(self.slots.items.len - 1, 1);
    }

    /// Resolve a handle, rejecting anything that does not name the exact
    /// policy the handle was issued for. The generation check is what
    /// makes a handle whose slot has since been reused fail rather than
    /// silently resolve to whatever policy now lives there.
    fn lookup(self: *Registry, handle: Handle) Error!*Entry {
        const index = @as(usize, handle & index_mask);
        if (index == 0 or index > self.slots.items.len) return Error.InvalidHandle;
        const slot = self.slots.items[index - 1];
        if (slot.generation != handle >> index_bits) return Error.InvalidHandle;
        return slot.entry orelse Error.InvalidHandle;
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
        // The generation is left where it is and bumped on the next
        // install, so this handle stops resolving immediately and the
        // next occupant gets a different one.
        self.slots.items[(handle & index_mask) - 1].entry = null;
        return true;
    }

    /// Number of live policies. For tests, and for a host that wants to
    /// assert it is not leaking.
    pub fn liveCount(self: *const Registry) usize {
        var n: usize = 0;
        for (self.slots.items) |slot| {
            if (slot.entry != null) n += 1;
        }
        return n;
    }

    /// Release everything and drop the table. The wasm module never
    /// calls this -- it has no shutdown -- but a native embedder and
    /// every test does.
    pub fn deinit(self: *Registry) void {
        for (self.slots.items) |slot| {
            if (slot.entry) |entry| {
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

test "a released slot is reused, but never under the old handle" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    const first = try registry.compile(rbac_policy);
    try testing.expect(registry.release(first));
    const second = try registry.compile(rbac_policy);

    // Same storage, so the table does not grow...
    try testing.expectEqual(@as(usize, 1), registry.slots.items.len);
    try testing.expectEqual(first & index_mask, second & index_mask);
    // ...but a different handle, so the old one cannot name the new
    // policy.
    try testing.expect(first != second);
}

test "a stale handle whose slot was reused denies, it does not resolve" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // `deny_all` and `allow_all` disagree on every input, so if the
    // stale handle resolved to the slot's new occupant this would come
    // back 1 rather than -1 -- an authoritative decision from the wrong
    // policy, which is the bug this generation counter exists to stop.
    const deny_all = try registry.compile(
        \\{"type":"module","rules":[{"type":"rule","name":"allow","default":true,"value":{"type":"value","value":false}}]}
    );
    try testing.expect(!try registry.evaluateAddressed(&arena, deny_all, "{}", "", "allow"));
    try testing.expect(registry.release(deny_all));

    const allow_all = try registry.compile(
        \\{"type":"module","rules":[{"type":"rule","name":"allow","value":{"type":"value","value":true}}]}
    );
    // The new policy took the freed slot.
    try testing.expectEqual(deny_all & index_mask, allow_all & index_mask);
    try testing.expect(try registry.evaluateAddressed(&arena, allow_all, "{}", "", "allow"));

    // The old handle still refuses.
    try testing.expectError(Error.InvalidHandle, registry.evaluateAddressed(&arena, deny_all, "{}", "", "allow"));
    try testing.expect(!registry.release(deny_all));
}

test "a slot whose generation is exhausted is retired, not wrapped" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    const first = try registry.compile(rbac_policy);
    try testing.expect(registry.release(first));

    // Fast-forward the slot to its last usable generation rather than
    // compiling 32767 times.
    registry.slots.items[0].generation = max_generation - 1;
    const last = try registry.compile(rbac_policy);
    try testing.expectEqual(max_generation, last >> index_bits);
    try testing.expect(registry.release(last));

    // The slot can no longer advance, so it is left alone and the next
    // policy goes somewhere new. Wrapping instead would reissue handles
    // that an unlucky host might still be holding.
    const next = try registry.compile(rbac_policy);
    try testing.expect((next & index_mask) != (last & index_mask));
    try testing.expectEqual(@as(usize, 2), registry.slots.items.len);
}

test "the table refuses to grow past what the index field can address" {
    var registry: Registry = .{ .gpa = testing.allocator };
    defer registry.deinit();

    // Fill the table with retired slots -- empty, so `deinit` has
    // nothing to free, and at max generation, so `install` will not
    // reuse them and has to fall through to appending. Compiling 65535
    // real policies to reach this path is not necessary.
    try registry.slots.appendNTimes(
        testing.allocator,
        .{ .entry = null, .generation = max_generation },
        max_slots,
    );
    try testing.expectError(Error.TooManyPolicies, registry.compile(rbac_policy));

    // The reason the cap is where it is: one slot lower still encodes
    // inside the index field, and one higher would spill into the
    // generation bits and manufacture exactly the handle collision the
    // generation counter exists to prevent.
    const last = encode(max_slots - 1, 1);
    try testing.expectEqual(@as(u32, index_mask), last & index_mask);
    try testing.expectEqual(@as(u32, 1), last >> index_bits);
    try testing.expectEqual(max_slots, @as(usize, encode(max_slots - 1, 1) & index_mask));
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
