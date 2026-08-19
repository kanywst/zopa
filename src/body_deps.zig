//! Static analysis of body dependencies in a compiled policy.
//!
//! Walks the AST once, classifying how the policy references the
//! request body. `proxy_wasm.zig` runs `analyzeTarget` over the
//! `allow_body` rules at configure time and keeps the class around for
//! two decisions on the hot path:
//!
//! - `.no_body_refs`: the body rule never reads the body, so a body
//!   that got truncated at the buffer cap changes nothing.
//! - `.prefix_only` / `.full_tree`: the decision depends on bytes we
//!   may not have. A truncated body is refused rather than evaluated
//!   against a prefix, because "the parse failed so the deny rule
//!   didn't fire" is a bypass, not a decision.
//!
//! Streaming evaluation itself (per `docs/proposals/streaming-evaluation.md`)
//! depends on the body-aware callback path landing first; this
//! analyser is the configure-time piece that ships independently.

const std = @import("std");
const ast = @import("ast.zig");

pub const Class = enum {
    /// Policy does not reference `input.body` anywhere.
    no_body_refs,
    /// Policy references body sub-paths (e.g. `input.body.amount`).
    /// A streaming evaluator can decide as soon as those resolve.
    prefix_only,
    /// Policy references `input.body` as a whole or iterates over
    /// the body's contents. The full body must be buffered.
    full_tree,
};

pub const BodyDeps = struct {
    class: Class,
    /// Number of distinct body sub-paths referenced when
    /// `class == .prefix_only`. Always 0 for the other classes.
    prefix_count: usize,
};

/// Classify body usage of every rule reachable in `module`.
/// Conservative: when in doubt, returns `.full_tree`.
pub fn analyze(module: ast.Module) BodyDeps {
    var st = State{};
    visitModule(&st, module, null);
    return st.finalize();
}

/// Classify body usage of the rules named `target_rule` across every
/// module in `bundle`. This is the question the shim actually has:
/// "does the rule I am about to run for this phase read the body?".
/// Rules for other phases are irrelevant and would only push the
/// class up.
pub fn analyzeTarget(bundle: ast.Modules, target_rule: []const u8) BodyDeps {
    var st = State{};
    for (bundle.modules) |module| visitModule(&st, module, target_rule);
    return st.finalize();
}

fn visitModule(st: *State, module: ast.Module, target_rule: ?[]const u8) void {
    for (module.rules) |rule| {
        if (target_rule) |want| {
            if (!std.mem.eql(u8, rule.name, want)) continue;
        }
        for (rule.body) |expr| visit(st, expr);
        if (rule.value) |v| visit(st, v);
    }
}

const State = struct {
    refs_whole: bool = false,
    prefix_count: usize = 0,

    fn finalize(self: State) BodyDeps {
        if (self.refs_whole) return .{ .class = .full_tree, .prefix_count = 0 };
        if (self.prefix_count == 0) return .{ .class = .no_body_refs, .prefix_count = 0 };
        return .{ .class = .prefix_only, .prefix_count = self.prefix_count };
    }
};

fn visit(st: *State, expr: *const ast.Expr) void {
    switch (expr.*) {
        .value => {},
        .ref => |path| visitRef(st, path),
        .compare => |c| {
            visit(st, c.left);
            visit(st, c.right);
        },
        .not => |inner| visit(st, inner),
        .some, .every => |it| {
            visit(st, it.source);
            visit(st, it.body);
            // Iterating over a ref into the body is full-tree:
            // the iterator needs the entire collection. The source
            // visit above marks the path; we promote to whole if
            // the source is itself an `input.body...` ref.
            if (it.source.* == .ref) {
                if (refTouchesBody(it.source.ref)) st.refs_whole = true;
            }
        },
        .call => |c| for (c.args) |arg| visit(st, arg),
    }
}

fn visitRef(st: *State, path: []const []const u8) void {
    if (!refTouchesBody(path)) return;

    // `input.body` (or just `body`) by itself = whole-tree dependency.
    // Body sub-paths (input.body.amount, body.user) = prefix-only.
    const body_index = bodySegmentIndex(path) orelse return;
    if (body_index + 1 >= path.len) {
        st.refs_whole = true;
    } else {
        st.prefix_count += 1;
    }
}

fn refTouchesBody(path: []const []const u8) bool {
    return bodySegmentIndex(path) != null;
}

/// Locate the `body` segment inside an input ref. Accepts both
/// `["input", "body", ...]` and the shorthand `["body", ...]`.
fn bodySegmentIndex(path: []const []const u8) ?usize {
    if (path.len == 0) return null;
    if (std.mem.eql(u8, path[0], "body")) return 0;
    if (path.len >= 2 and std.mem.eql(u8, path[0], "input") and std.mem.eql(u8, path[1], "body")) {
        return 1;
    }
    return null;
}

const testing = std.testing;
const json = @import("json.zig");

fn classify(src: []const u8) !Class {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const node = try json.parse(arena.allocator(), src);
    const module = try ast.buildModule(arena.allocator(), node);
    return analyze(module).class;
}

test "analyze: no body refs -> no_body_refs" {
    const policy =
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"method\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"GET\"}}";
    try testing.expectEqual(Class.no_body_refs, try classify(policy));
}

test "analyze: input.body.amount -> prefix_only" {
    const policy =
        "{\"type\":\"gt\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body\",\"amount\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":100}}";
    try testing.expectEqual(Class.prefix_only, try classify(policy));
}

test "analyze: bare input.body -> full_tree" {
    const policy =
        "{\"type\":\"neq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":null}}";
    try testing.expectEqual(Class.full_tree, try classify(policy));
}

test "analyze: iterate input.body.items -> full_tree" {
    const policy =
        "{\"type\":\"every\",\"var\":\"item\"," ++
        "\"source\":{\"type\":\"ref\",\"path\":[\"input\",\"body\",\"items\"]}," ++
        "\"body\":{\"type\":\"value\",\"value\":true}}";
    try testing.expectEqual(Class.full_tree, try classify(policy));
}

test "analyze: prefix_count counts distinct body refs" {
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body\",\"action\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"submit\"}}," ++
        "{\"type\":\"gt\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body\",\"amount\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":0}}]}]}";
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const node = try json.parse(arena.allocator(), policy);
    const module = try ast.buildModule(arena.allocator(), node);
    const deps = analyze(module);
    try testing.expectEqual(Class.prefix_only, deps.class);
    try testing.expectEqual(@as(usize, 2), deps.prefix_count);
}

test "analyze: body shorthand path (no input prefix) detected" {
    const policy =
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"body\",\"x\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":1}}";
    try testing.expectEqual(Class.prefix_only, try classify(policy));
}

test "analyzeTarget: only the named rule's body refs count" {
    // `allow` reads the body; `allow_body` doesn't. Asking about
    // `allow_body` must not inherit `allow`'s dependency, or every
    // body would be treated as decision-relevant.
    const policy =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body\",\"x\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":1}}]}," ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"method\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"POST\"}}]}]}" ++
        "]}";

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const node = try json.parse(arena.allocator(), policy);
    const bundle = try ast.buildModulesBundle(arena.allocator(), node);

    try testing.expectEqual(Class.no_body_refs, analyzeTarget(bundle, "allow_body").class);
    try testing.expectEqual(Class.prefix_only, analyzeTarget(bundle, "allow").class);
    try testing.expectEqual(Class.no_body_refs, analyzeTarget(bundle, "absent").class);
}

test "analyzeTarget: refs spread across modules in a bundle are combined" {
    const policy =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"method\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"POST\"}}]}]}," ++
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"body\":[" ++
        "{\"type\":\"neq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":null}}]}]}" ++
        "]}";

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const node = try json.parse(arena.allocator(), policy);
    const bundle = try ast.buildModulesBundle(arena.allocator(), node);
    try testing.expectEqual(Class.full_tree, analyzeTarget(bundle, "allow_body").class);
}

test "analyze: call with body arg -> prefix_only" {
    const policy =
        "{\"type\":\"call\",\"name\":\"startswith\",\"args\":[" ++
        "{\"type\":\"ref\",\"path\":[\"input\",\"body\",\"action\"]}," ++
        "{\"type\":\"value\",\"value\":\"approve_\"}]}";
    try testing.expectEqual(Class.prefix_only, try classify(policy));
}
