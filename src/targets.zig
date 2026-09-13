//! Which `(package, rule)` pairs each proxy-wasm phase evaluates.
//!
//! Split out of `proxy_wasm.zig` for the reason that file's own header
//! gives: it is pure logic over `ast.Modules` and `json.Value`, no host
//! imports anywhere near it, so unit tests can reach it. The
//! fail-closed guarantees here -- refusing an unknown phase, an unknown
//! `on_deny`, a rule the policy does not define, and a block that would
//! leave the request phase unguarded -- were reachable only through a
//! real Envoy before, which needs the binary on PATH and cannot be run
//! from `zig build test-unit`.
//!
//! The composition rule lives here too. Enforcing targets are ANDed;
//! ORing would let an added rule widen access, so adding one can only
//! ever narrow it. An advisory target is evaluated and never blocks,
//! and neither does its failure to evaluate: a broken audit rule is a
//! broken audit trail, not a reason to reject traffic.

const std = @import("std");

const ast = @import("ast.zig");
const json = @import("json.zig");

/// Rule names the phases use when no `targets` block is given.
pub const default_request_rule: []const u8 = "allow";
pub const default_body_rule: []const u8 = "allow_body";
pub const default_response_rule: []const u8 = "allow_response";

/// Which of the two configuration shapes a document is.
///
/// Historically the whole plugin configuration *is* the policy AST. A
/// document carrying a `policy` member is the wrapper that can also
/// name targets. No AST node has a top-level `policy`, so the two
/// cannot be confused.
///
/// A bare AST carrying a top-level `targets` is refused rather than
/// treated as either. `ast.buildModulesBundle` ignores members it does
/// not know, so such a document would otherwise parse fine, take the
/// defaults, and never read the targets the author wrote -- a
/// misconfiguration that changes what the filter enforces and says
/// nothing.
pub fn shapeOf(config: json.Value) Error!?json.Value {
    if (config != .object) return null;
    if (json.lookupMember(config.object, "policy")) |policy| return policy;
    if (json.lookupMember(config.object, "targets") != null) return error.TargetsWithoutPolicyWrapper;
    return null;
}

/// One `(package, rule)` pair a phase evaluates, and what a deny does.
///
/// Without a `targets` block the shim evaluates exactly one rule per
/// phase in the implicit `""` package, which is what every release
/// before this did and remains the default. A deployment that wants an
/// audit rule alongside the enforcing one -- decided, logged, but not
/// blocking -- names both here.
pub const Target = struct {
    package: []const u8,
    rule: []const u8,
    /// `false` for an audit target: the decision is logged and the
    /// request proceeds. Enforcing is the default, so a typo in the
    /// field name cannot silently turn a blocking rule advisory.
    enforce: bool = true,
};

pub const Set = struct {
    request: []const Target,
    body: []const Target,
    response: []const Target,
};

pub const Error = error{
    NoEnforcingRequestTarget,
    PhaseRuleOutsideDefaultPackage,
    TargetsWithoutPolicyWrapper,
    UnknownPhase,
    UnknownOnDeny,
    TargetRuleMissing,
    MalformedTargets,
    OutOfMemory,
};

/// Build the per-phase target lists.
///
/// `config` is null for the historical shape, where the configuration
/// is the bare policy: one enforcing rule per phase in the implicit
/// package, and the body and response phases only if the policy defines
/// their rule. That arrangement is what every release before this one
/// did, and staying byte-identical to it matters more than tidiness.
///
/// Everything the block can get wrong fails configure rather than
/// degrading: an unknown phase, an unknown `on_deny`, a rule the policy
/// does not define. A target that never fires is worse than a filter
/// that refuses to start, because nothing surfaces it.
pub fn build(
    allocator: std.mem.Allocator,
    bundle: ast.Modules,
    config: ?json.Value,
) Error!Set {
    const cfg = config orelse return defaults(allocator, bundle);

    const targets_v = json.lookupMember(cfg.object, "targets") orelse
        return defaults(allocator, bundle);
    if (targets_v != .array) return error.MalformedTargets;

    var request: std.ArrayList(Target) = .empty;
    var body: std.ArrayList(Target) = .empty;
    var response: std.ArrayList(Target) = .empty;

    for (targets_v.array) |entry| {
        if (entry != .object) return error.MalformedTargets;
        const obj = entry.object;

        const phase_v = json.lookupMember(obj, "phase") orelse return error.MalformedTargets;
        const rule_v = json.lookupMember(obj, "rule") orelse return error.MalformedTargets;
        if (phase_v != .string or rule_v != .string) return error.MalformedTargets;

        const package = if (json.lookupMember(obj, "package")) |p| blk: {
            if (p != .string) return error.MalformedTargets;
            break :blk p.string;
        } else "";

        // Enforcing unless the deployment says otherwise, so a
        // misspelled field cannot quietly make a blocking rule
        // advisory.
        const enforce = if (json.lookupMember(obj, "on_deny")) |od| blk: {
            if (od != .string) return error.MalformedTargets;
            if (std.mem.eql(u8, od.string, "deny")) break :blk true;
            if (std.mem.eql(u8, od.string, "log")) break :blk false;
            return error.UnknownOnDeny;
        } else true;

        if (!ruleExists(bundle, package, rule_v.string)) return error.TargetRuleMissing;

        const target = Target{ .package = package, .rule = rule_v.string, .enforce = enforce };
        const list = if (std.mem.eql(u8, phase_v.string, "request"))
            &request
        else if (std.mem.eql(u8, phase_v.string, "body"))
            &body
        else if (std.mem.eql(u8, phase_v.string, "response"))
            &response
        else
            return error.UnknownPhase;
        try list.append(allocator, target);
    }

    // The request phase has no `has_allow_*` gate -- it always runs --
    // so an empty list here would make `decideTargets` return allow
    // from an empty loop and let every request through, with no
    // configure error and no log line. `{"targets": []}` alone would
    // have disabled authorization while looking configured.
    //
    // A filter that only inspects bodies is a real thing to want, but
    // it has to say so: name a request rule that allows, rather than
    // getting the same effect by omission.
    var enforcing_request = false;
    for (request.items) |t| {
        if (t.enforce) enforcing_request = true;
    }
    if (!enforcing_request) return error.NoEnforcingRequestTarget;

    return .{
        .request = try request.toOwnedSlice(allocator),
        .body = try body.toOwnedSlice(allocator),
        .response = try response.toOwnedSlice(allocator),
    };
}

/// The arrangement every release before targets used.
fn defaults(allocator: std.mem.Allocator, bundle: ast.Modules) Error!Set {
    const request = try allocator.alloc(Target, 1);
    request[0] = .{ .package = "", .rule = default_request_rule };

    const body = try defaultPhase(allocator, bundle, default_body_rule);
    const response = try defaultPhase(allocator, bundle, default_response_rule);

    return .{ .request = request, .body = body, .response = response };
}

/// One phase's default target, or none.
///
/// The bare configuration only ever dispatches into the implicit `""`
/// package. A policy that defines `allow_body` in some *other* package
/// without one in `""` is therefore a rule that can never fire, and
/// this refuses rather than guessing: taking the rule would silently
/// start enforcing something the shim never used to reach, and ignoring
/// it would leave the phase unguarded while the policy looks like it
/// covers the body. Name it in a `targets` block instead.
fn defaultPhase(
    allocator: std.mem.Allocator,
    bundle: ast.Modules,
    rule: []const u8,
) Error![]Target {
    if (ruleExists(bundle, "", rule)) {
        const buf = try allocator.alloc(Target, 1);
        buf[0] = .{ .package = "", .rule = rule };
        return buf;
    }
    for (bundle.modules) |module| {
        for (module.rules) |r| {
            if (std.mem.eql(u8, r.name, rule)) return error.PhaseRuleOutsideDefaultPackage;
        }
    }
    return &.{};
}

fn ruleExists(bundle: ast.Modules, package: []const u8, rule: []const u8) bool {
    for (bundle.modules) |module| {
        if (!std.mem.eql(u8, module.package, package)) continue;
        for (module.rules) |r| {
            if (std.mem.eql(u8, r.name, rule)) return true;
        }
    }
    return false;
}

// -------------------------------------------------------------- tests

const testing = std.testing;

/// Build a bundle and a config document on one arena, the way
/// `proxy_on_configure` does.
fn parse(arena: *std.heap.ArenaAllocator, src: []const u8) !struct { bundle: ast.Modules, config: json.Value } {
    const allocator = arena.allocator();
    const doc = try json.parse(allocator, src);
    const policy = json.lookupMember(doc.object, "policy") orelse doc;
    return .{ .bundle = try ast.buildModulesBundle(allocator, policy), .config = doc };
}

const two_packages =
    \\{"policy":{"type":"modules","modules":[
    \\  {"type":"module","package":"authz","rules":[
    \\    {"type":"rule","name":"allow","value":{"type":"value","value":true}}]},
    \\  {"type":"module","package":"audit","rules":[
    \\    {"type":"rule","name":"ok","value":{"type":"value","value":true}}]}]},
    \\ "targets":[TARGETS]}
;

fn withTargets(arena: *std.heap.ArenaAllocator, targets_json: []const u8) !Set {
    const buf = try std.mem.replaceOwned(u8, arena.allocator(), two_packages, "TARGETS", targets_json);
    const parsed = try parse(arena, buf);
    return build(arena.allocator(), parsed.bundle, parsed.config);
}

test "targets: a block names the pairs each phase evaluates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const set = try withTargets(&arena,
        \\{"phase":"request","package":"authz","rule":"allow"},
        \\{"phase":"request","package":"audit","rule":"ok","on_deny":"log"}
    );
    try testing.expectEqual(@as(usize, 2), set.request.len);
    try testing.expectEqualStrings("authz", set.request[0].package);
    try testing.expect(set.request[0].enforce);
    try testing.expectEqualStrings("audit", set.request[1].package);
    try testing.expect(!set.request[1].enforce);
    try testing.expectEqual(@as(usize, 0), set.body.len);
}

test "targets: enforcing is the default so a typo cannot make a rule advisory" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const set = try withTargets(&arena,
        \\{"phase":"request","package":"authz","rule":"allow","on_dney":"log"}
    );
    try testing.expect(set.request[0].enforce);
}

test "targets: a block that would leave the request phase unguarded is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // The request phase always runs and has no existence gate, so an
    // empty or all-advisory list would allow every request from an
    // empty loop -- configured-looking and silent.
    try testing.expectError(Error.NoEnforcingRequestTarget, withTargets(&arena, ""));
    try testing.expectError(Error.NoEnforcingRequestTarget, withTargets(&arena,
        \\{"phase":"body","package":"authz","rule":"allow"}
    ));
    try testing.expectError(Error.NoEnforcingRequestTarget, withTargets(&arena,
        \\{"phase":"request","package":"authz","rule":"allow","on_deny":"log"}
    ));
}

test "targets: everything malformed is refused rather than skipped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    try testing.expectError(Error.UnknownPhase, withTargets(&arena,
        \\{"phase":"trailers","package":"authz","rule":"allow"}
    ));
    try testing.expectError(Error.UnknownOnDeny, withTargets(&arena,
        \\{"phase":"request","package":"authz","rule":"allow","on_deny":"warn"}
    ));
    // A target naming a rule the policy does not define would never
    // fire, which is worse than refusing to start because nothing
    // surfaces it.
    try testing.expectError(Error.TargetRuleMissing, withTargets(&arena,
        \\{"phase":"request","package":"authz","rule":"nope"}
    ));
    // Right rule, wrong package.
    try testing.expectError(Error.TargetRuleMissing, withTargets(&arena,
        \\{"phase":"request","package":"audit","rule":"allow"}
    ));
    try testing.expectError(Error.MalformedTargets, withTargets(&arena,
        \\{"phase":"request","rule":42}
    ));
    try testing.expectError(Error.MalformedTargets, withTargets(&arena, "\"not an object\""));
}

test "targets: no block reproduces the pre-targets arrangement" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Request only: the policy defines no body or response rule, so
    // those phases stay off, exactly as before targets existed.
    const request_only = try parse(&arena,
        \\{"type":"module","rules":[
        \\  {"type":"rule","name":"allow","value":{"type":"value","value":true}}]}
    );
    const a = try build(arena.allocator(), request_only.bundle, null);
    try testing.expectEqual(@as(usize, 1), a.request.len);
    try testing.expectEqualStrings("", a.request[0].package);
    try testing.expectEqualStrings(default_request_rule, a.request[0].rule);
    try testing.expect(a.request[0].enforce);
    try testing.expectEqual(@as(usize, 0), a.body.len);
    try testing.expectEqual(@as(usize, 0), a.response.len);

    // With the phase rules present, those phases turn on.
    const all_phases = try parse(&arena,
        \\{"type":"module","rules":[
        \\  {"type":"rule","name":"allow","value":{"type":"value","value":true}},
        \\  {"type":"rule","name":"allow_body","value":{"type":"value","value":true}},
        \\  {"type":"rule","name":"allow_response","value":{"type":"value","value":true}}]}
    );
    const b = try build(arena.allocator(), all_phases.bundle, null);
    try testing.expectEqual(@as(usize, 1), b.body.len);
    try testing.expectEqualStrings(default_body_rule, b.body[0].rule);
    try testing.expectEqual(@as(usize, 1), b.response.len);
}

test "targets: a bare AST carrying `targets` is refused, not silently ignored" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // `ast.buildModulesBundle` ignores members it does not know, so
    // without this the document parses, takes the defaults, and never
    // reads the targets the author wrote -- a misconfiguration that
    // changes what the filter enforces and says nothing.
    const bare_with_targets = try json.parse(allocator,
        \\{"type":"module","rules":[{"type":"rule","name":"allow","value":{"type":"value","value":true}}],
        \\ "targets":[{"phase":"request","package":"","rule":"allow"}]}
    );
    try testing.expectError(Error.TargetsWithoutPolicyWrapper, shapeOf(bare_with_targets));

    // A plain AST is the historical shape and stays one.
    const bare = try json.parse(allocator,
        \\{"type":"module","rules":[{"type":"rule","name":"allow","value":{"type":"value","value":true}}]}
    );
    try testing.expectEqual(@as(?json.Value, null), try shapeOf(bare));

    // The wrapper hands back the policy it carries.
    const wrapped = try json.parse(allocator,
        \\{"policy":{"type":"module","rules":[]},"targets":[]}
    );
    const policy = try shapeOf(wrapped);
    try testing.expect(policy != null);
    try testing.expect(policy.? == .object);

    // A non-object configuration is not a wrapper; the AST builder
    // rejects it on its own terms.
    try testing.expectEqual(@as(?json.Value, null), try shapeOf(try json.parse(allocator, "[]")));
}

test "targets: a phase rule outside the default package is refused, not half-enabled" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // The bare shape only dispatches into the implicit package, so
    // `authz.allow_body` can never fire. Before the phase gate and the
    // target list shared one source of truth, this turned the body
    // phase *on* with no target to evaluate -- and an empty target list
    // allows from an empty loop, so every body was permitted.
    const parsed = try parse(&arena,
        \\{"type":"modules","modules":[
        \\  {"type":"module","package":"","rules":[
        \\    {"type":"rule","name":"allow","value":{"type":"value","value":true}}]},
        \\  {"type":"module","package":"authz","rules":[
        \\    {"type":"rule","name":"allow_body","value":{"type":"value","value":true}}]}]}
    );
    try testing.expectError(
        Error.PhaseRuleOutsideDefaultPackage,
        build(arena.allocator(), parsed.bundle, null),
    );
}
