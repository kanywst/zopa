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
    /// Policy does not reference the request body anywhere.
    no_body_refs,
    /// Policy references body sub-paths (e.g. `input.body.amount`).
    /// A streaming evaluator can decide as soon as those resolve.
    prefix_only,
    /// Policy references `input.body` or `input.body_raw` as a whole,
    /// or iterates over the body's contents. The full body must be
    /// buffered.
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

/// Classify body usage of the rules named `target_rule` in
/// `target_package`. This is the question the shim actually has: "does
/// the rule I am about to run for this phase read the body?".
///
/// Scoped to the package because that is what gets evaluated -- the
/// shim dispatches into `""`. A bundle that also carries packages for
/// `evaluate_addressed` callers would otherwise let an unrelated
/// `allow_body` rule inflate the class for the one that actually runs.
/// The error direction is safe either way (a too-high class only costs
/// spurious refusals of oversized bodies, never a bypass), but an
/// analysis that answers a different question than the one asked drifts
/// wrong later.
pub fn analyzeTarget(
    bundle: ast.Modules,
    target_package: []const u8,
    target_rule: []const u8,
) BodyDeps {
    var st = State{};
    for (bundle.modules) |module| {
        if (!std.mem.eql(u8, module.package, target_package)) continue;
        visitModule(&st, module, target_rule);
    }
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
                if (classifyRef(it.source.ref) != .none) st.refs_whole = true;
            }
        },
        .call => |c| for (c.args) |arg| visit(st, arg),
    }
}

fn visitRef(st: *State, path: []const []const u8) void {
    switch (classifyRef(path)) {
        .none => {},
        .whole => st.refs_whole = true,
        .prefix => st.prefix_count += 1,
    }
}

const RefKind = enum {
    /// Does not reach the request body.
    none,
    /// Needs the body in full: `input.body`, or `input.body_raw`, which
    /// is the entire body as one string.
    whole,
    /// Needs a sub-path of the parsed body, e.g. `input.body.amount`.
    prefix,
};

/// Classify an input ref by how much of the request body it needs.
/// Accepts the `input`-prefixed spelling and the shorthand alike, since
/// `json.lookupPath` strips one leading `input` segment.
///
/// `body_raw` counts. It is a sibling key rather than a sub-path of
/// `body`, so a walk that only looks for the segment `body` classifies
/// a policy like `contains(input.body_raw, "...")` as touching nothing
/// -- and the shim then evaluates it against a truncated prefix, which
/// is the fail-open this analyser exists to prevent, reached through
/// the other field.
///
/// `body_truncated` deliberately does not count. It is a flag *about*
/// the body rather than content from it, and a policy reading it is
/// asking to handle truncation itself; classifying it as a body
/// reference would make the shim refuse the request before the policy
/// ever saw the flag.
fn classifyRef(path: []const []const u8) RefKind {
    var p = path;
    if (p.len > 0 and std.mem.eql(u8, p[0], "input")) p = p[1..];
    if (p.len == 0) return .none;

    if (std.mem.eql(u8, p[0], "body_raw")) return .whole;
    if (!std.mem.eql(u8, p[0], "body")) return .none;
    return if (p.len == 1) .whole else .prefix;
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

test "analyze: body_raw is a whole-body reference" {
    // A policy whose only body dependency is the raw string still needs
    // every byte. Classifying it as no_body_refs let the shim evaluate
    // it against a truncated prefix: `contains(input.body_raw, "X")`
    // simply returns false when X sat past the buffer cap, and the
    // request was allowed.
    const raw =
        "{\"type\":\"call\",\"name\":\"contains\",\"args\":[" ++
        "{\"type\":\"ref\",\"path\":[\"input\",\"body_raw\"]}," ++
        "{\"type\":\"value\",\"value\":\"BLOCKED\"}]}";
    try testing.expectEqual(Class.full_tree, try classify(raw));

    const shorthand =
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"body_raw\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"x\"}}";
    try testing.expectEqual(Class.full_tree, try classify(shorthand));
}

test "analyze: body_truncated alone is not a body reference" {
    // The flag is about the body, not from it. Treating it as a body
    // ref would make the shim refuse an oversized request before the
    // policy that wanted to handle truncation itself ever ran.
    const policy = "{\"type\":\"ref\",\"path\":[\"input\",\"body_truncated\"]}";
    try testing.expectEqual(Class.no_body_refs, try classify(policy));
}

test "analyze: keys that merely start with `body` are not body refs" {
    const policy =
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"bodyguard\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":1}}";
    try testing.expectEqual(Class.no_body_refs, try classify(policy));
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

    try testing.expectEqual(Class.no_body_refs, analyzeTarget(bundle, "", "allow_body").class);
    try testing.expectEqual(Class.prefix_only, analyzeTarget(bundle, "", "allow").class);
    try testing.expectEqual(Class.no_body_refs, analyzeTarget(bundle, "", "absent").class);
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
    try testing.expectEqual(Class.full_tree, analyzeTarget(bundle, "", "allow_body").class);
}

test "analyze: call with body arg -> prefix_only" {
    const policy =
        "{\"type\":\"call\",\"name\":\"startswith\",\"args\":[" ++
        "{\"type\":\"ref\",\"path\":[\"input\",\"body\",\"action\"]}," ++
        "{\"type\":\"value\",\"value\":\"approve_\"}]}";
    try testing.expectEqual(Class.prefix_only, try classify(policy));
}

test "analyzeTarget: rules in other packages don't inflate the class" {
    // The shim dispatches into the implicit `""` package, so a bundle
    // that also carries packages for `evaluate_addressed` callers must
    // not have their body refs counted against it.
    const policy =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"method\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"POST\"}}]}]}," ++
        "{\"type\":\"module\",\"package\":\"audit\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"body\":[" ++
        "{\"type\":\"neq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":null}}]}]}" ++
        "]}";

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const node = try json.parse(arena.allocator(), policy);
    const bundle = try ast.buildModulesBundle(arena.allocator(), node);

    try testing.expectEqual(Class.no_body_refs, analyzeTarget(bundle, "", "allow_body").class);
    try testing.expectEqual(Class.full_tree, analyzeTarget(bundle, "audit", "allow_body").class);
}
