//! Policy AST: `Module` -> `Rule` -> `Expr`. The `Value` type comes
//! from `json.zig`, so parsed inputs and AST literals share one
//! representation.
//!
//! Builders allocate everything on the caller-supplied allocator
//! (the request arena, in zopa). `Value.string` payloads can alias
//! the source JSON buffer; the host must keep that buffer alive
//! through the call.

const std = @import("std");
const json = @import("json.zig");

pub const Value = json.Value;

/// Comparison operator used by `Expr.compare`.
pub const CompareOp = enum {
    eq,
    neq,
    lt,
    lte,
    gt,
    gte,

    fn fromString(s: []const u8) ?CompareOp {
        if (std.mem.eql(u8, s, "eq")) return .eq;
        if (std.mem.eql(u8, s, "neq")) return .neq;
        if (std.mem.eql(u8, s, "lt")) return .lt;
        if (std.mem.eql(u8, s, "lte")) return .lte;
        if (std.mem.eql(u8, s, "gt")) return .gt;
        if (std.mem.eql(u8, s, "gte")) return .gte;
        return null;
    }
};

/// Expression node.
pub const Expr = union(enum) {
    value: Value,
    ref: []const []const u8,
    compare: Compare,
    not: *const Expr,
    some: Iter,
    every: Iter,
    call: Call,

    pub const Compare = struct {
        op: CompareOp,
        left: *const Expr,
        right: *const Expr,
    };

    /// Iteration over an array, set, or object. The evaluator binds
    /// each element under `var_name` and runs `body`. `some` and
    /// `every` share this shape; only the body combination differs.
    ///
    /// `kind` only matters when the source resolves to a JSON object;
    /// for arrays and sets it is ignored.
    pub const Iter = struct {
        var_name: []const u8,
        source: *const Expr,
        body: *const Expr,
        kind: IterKind = .keys,
    };

    pub const IterKind = enum {
        keys,
        values,

        fn fromString(s: []const u8) ?IterKind {
            if (std.mem.eql(u8, s, "keys")) return .keys;
            if (std.mem.eql(u8, s, "values")) return .values;
            return null;
        }
    };

    /// Call to a builtin function. The evaluator looks `name` up in
    /// `builtins.zig`; unknown names error out (treated as deny).
    pub const Call = struct {
        name: []const u8,
        args: []const *const Expr,
    };
};

/// `body` is an implicit AND. `value` is the expression returned
/// when the body holds; `null` means boolean `true`. `is_default`
/// is set by the Rego `default` keyword.
pub const Rule = struct {
    name: []const u8,
    body: []const *const Expr,
    value: ?*const Expr,
    is_default: bool,
};

/// A compiled policy module. Rules with the same name OR-combine.
/// `package` is optional ("" means the implicit single-module case);
/// see `Modules` for how multi-package bundles are addressed.
pub const Module = struct {
    rules: []const Rule,
    package: []const u8 = "",
};

/// A bundle of modules. Allows the proxy-wasm shim to load multiple
/// independently authored policies into a single VM and dispatch
/// per request to a specific `(package, rule)` target.
///
/// Bare `{"type":"module",...}` and bare expressions still work via
/// `buildModule`; `buildModulesBundle` wraps either form into a
/// single-element bundle with `package=""` for backwards compat.
pub const Modules = struct {
    modules: []const Module,
};

// Builders. Consume a `json.Value`, return arena-allocated nodes.

/// Build a `Module`. Accepts either the canonical
/// `{"type":"module","rules":[...]}` shape or a bare expression,
/// which is wrapped into a synthetic `allow` rule. `package` is
/// read from the canonical shape if present.
pub fn buildModule(allocator: std.mem.Allocator, node: Value) !Module {
    if (node != .object) return error.InvalidAst;

    const t = try requireString(node.object, "type");

    if (std.mem.eql(u8, t, "module")) {
        const rules_v = try requireField(node.object, "rules");
        if (rules_v != .array) return error.InvalidRules;
        const rules = try allocator.alloc(Rule, rules_v.array.len);
        for (rules_v.array, 0..) |item, i| {
            rules[i] = try buildRule(allocator, item);
        }
        const pkg: []const u8 = if (json.lookupMember(node.object, "package")) |p_v| pkg_blk: {
            if (p_v != .string) return error.InvalidPackage;
            break :pkg_blk p_v.string;
        } else "";
        return .{ .rules = rules, .package = pkg };
    }

    // Legacy: bare expression -> single synthetic `allow` rule.
    const expr = try buildExpr(allocator, node);
    const body = try allocator.alloc(*const Expr, 1);
    body[0] = expr;
    const rules = try allocator.alloc(Rule, 1);
    rules[0] = .{
        .name = "allow",
        .body = body,
        .value = null,
        .is_default = false,
    };
    return .{ .rules = rules, .package = "" };
}

/// Build a `Modules` bundle. Accepts:
///   `{"type":"modules","modules":[<module>, ...]}` -> multi-package
///   `{"type":"module", ...}`                       -> single module
///   bare expression                                -> synthetic allow
pub fn buildModulesBundle(allocator: std.mem.Allocator, node: Value) !Modules {
    if (node == .object) {
        if (json.lookupMember(node.object, "type")) |t_v| {
            if (t_v == .string and std.mem.eql(u8, t_v.string, "modules")) {
                const list_v = try requireField(node.object, "modules");
                if (list_v != .array) return error.InvalidModules;
                const mods = try allocator.alloc(Module, list_v.array.len);
                for (list_v.array, 0..) |item, i| {
                    mods[i] = try buildModule(allocator, item);
                }
                const bundle = Modules{ .modules = mods };
                try validateDefaults(bundle);
                return bundle;
            }
        }
    }
    // Single-module / bare-expression form: wrap into a 1-element bundle.
    const single = try buildModule(allocator, node);
    const mods = try allocator.alloc(Module, 1);
    mods[0] = single;
    const bundle = Modules{ .modules = mods };
    try validateDefaults(bundle);
    return bundle;
}

/// Reject a package that declares `default` twice for the same rule.
///
/// OPA rejects this when it compiles the policy -- `rego_type_error:
/// multiple default rules data.authz.allow found` -- and does not pick
/// one. Accepting it here and letting the last declaration win would
/// make the fallback depend on bundle ordering, which is the same
/// order-dependence the evaluator refuses for conflicting non-default
/// rules; it would just be quieter, because a fallback only shows up on
/// the requests where nothing else matched.
///
/// Checked at build time rather than during evaluation because it is a
/// property of the policy, not of any request. On the proxy-wasm path
/// that means a bad policy fails `proxy_on_configure` instead of
/// denying every request; on the generic path it is `-1`.
///
/// Quadratic in the number of `default` rules, which is one per rule
/// name in every policy that isn't already broken.
fn validateDefaults(bundle: Modules) !void {
    for (bundle.modules, 0..) |mod_a, i| {
        for (mod_a.rules, 0..) |rule_a, ri| {
            if (!rule_a.is_default) continue;

            for (bundle.modules[i..], i..) |mod_b, j| {
                if (!std.mem.eql(u8, mod_a.package, mod_b.package)) continue;
                const start: usize = if (j == i) ri + 1 else 0;
                for (mod_b.rules[start..]) |rule_b| {
                    if (!rule_b.is_default) continue;
                    if (std.mem.eql(u8, rule_a.name, rule_b.name)) {
                        return error.DuplicateDefaultRule;
                    }
                }
            }
        }
    }
}

fn buildRule(allocator: std.mem.Allocator, node: Value) !Rule {
    if (node != .object) return error.InvalidRule;
    const obj = node.object;

    const t = try requireString(obj, "type");
    if (!std.mem.eql(u8, t, "rule")) return error.InvalidRule;

    const name = try requireString(obj, "name");
    const is_default = if (json.lookupMember(obj, "default")) |d|
        (d == .boolean and d.boolean)
    else
        false;

    const body_slice: []const *const Expr = if (json.lookupMember(obj, "body")) |b_v| body: {
        if (b_v != .array) return error.InvalidRuleBody;
        const buf = try allocator.alloc(*const Expr, b_v.array.len);
        for (b_v.array, 0..) |item, i| {
            buf[i] = try buildExpr(allocator, item);
        }
        break :body buf;
    } else try allocator.alloc(*const Expr, 0);

    const value_expr: ?*const Expr = if (json.lookupMember(obj, "value")) |v_v|
        try buildExpr(allocator, v_v)
    else
        null;

    return .{
        .name = name,
        .body = body_slice,
        .value = value_expr,
        .is_default = is_default,
    };
}

/// Build a single expression. See `docs/ast.md` for the accepted JSON
/// shapes; the compare operator names (`eq`, `neq`, `lt`, ...) are
/// recognised as shorthand for `{"type":"compare","op":...}`.
pub fn buildExpr(allocator: std.mem.Allocator, node: Value) !*Expr {
    if (node != .object) return error.InvalidAst;
    const obj = node.object;

    const t = try requireString(obj, "type");
    const expr = try allocator.create(Expr);

    if (std.mem.eql(u8, t, "value")) {
        const v = try requireField(obj, "value");
        expr.* = .{ .value = v };
    } else if (std.mem.eql(u8, t, "ref")) {
        const path_v = try requireField(obj, "path");
        if (path_v != .array) return error.InvalidPath;
        const parts = try allocator.alloc([]const u8, path_v.array.len);
        for (path_v.array, 0..) |part, i| {
            if (part != .string) return error.InvalidPath;
            parts[i] = part.string;
        }
        expr.* = .{ .ref = parts };
    } else if (std.mem.eql(u8, t, "compare") or CompareOp.fromString(t) != null) {
        const op = if (std.mem.eql(u8, t, "compare")) op_blk: {
            const op_v = try requireField(obj, "op");
            if (op_v != .string) return error.InvalidOp;
            break :op_blk CompareOp.fromString(op_v.string) orelse return error.UnknownOp;
        } else CompareOp.fromString(t).?;

        const left_v = try requireField(obj, "left");
        const right_v = try requireField(obj, "right");
        expr.* = .{ .compare = .{
            .op = op,
            .left = try buildExpr(allocator, left_v),
            .right = try buildExpr(allocator, right_v),
        } };
    } else if (std.mem.eql(u8, t, "not")) {
        const inner = try requireField(obj, "expr");
        expr.* = .{ .not = try buildExpr(allocator, inner) };
    } else if (std.mem.eql(u8, t, "set")) {
        const items_v = try requireField(obj, "items");
        if (items_v != .array) return error.InvalidItems;
        const items = try allocator.alloc(Value, items_v.array.len);
        for (items_v.array, 0..) |item, i| {
            items[i] = item;
        }
        expr.* = .{ .value = .{ .set = items } };
    } else if (std.mem.eql(u8, t, "some") or std.mem.eql(u8, t, "every")) {
        const var_name = try requireString(obj, "var");
        const source_v = try requireField(obj, "source");
        const body_v = try requireField(obj, "body");
        const kind: Expr.IterKind = if (json.lookupMember(obj, "kind")) |k_v| blk: {
            if (k_v != .string) return error.InvalidKind;
            break :blk Expr.IterKind.fromString(k_v.string) orelse return error.UnknownKind;
        } else .keys;
        const iter = Expr.Iter{
            .var_name = var_name,
            .source = try buildExpr(allocator, source_v),
            .body = try buildExpr(allocator, body_v),
            .kind = kind,
        };
        expr.* = if (std.mem.eql(u8, t, "some"))
            .{ .some = iter }
        else
            .{ .every = iter };
    } else if (std.mem.eql(u8, t, "call")) {
        const name = try requireString(obj, "name");
        const args_v = try requireField(obj, "args");
        if (args_v != .array) return error.InvalidArgs;
        const args = try allocator.alloc(*const Expr, args_v.array.len);
        for (args_v.array, 0..) |item, i| {
            args[i] = try buildExpr(allocator, item);
        }
        expr.* = .{ .call = .{ .name = name, .args = args } };
    } else {
        return error.UnknownExprType;
    }

    return expr;
}

// Object lookup helpers used by the builders. `lookupMember` lives
// in json.zig; these wrappers add the "must be present" / "must be
// a string" shorthands the builders need.

fn requireField(members: []const Value.Member, key: []const u8) !Value {
    return json.lookupMember(members, key) orelse error.MissingField;
}

fn requireString(members: []const Value.Member, key: []const u8) ![]const u8 {
    const v = try requireField(members, key);
    if (v != .string) return error.InvalidType;
    return v.string;
}

// Tests.

const testing = std.testing;

fn buildExprFromJson(arena: *std.heap.ArenaAllocator, src: []const u8) !*Expr {
    const node = try json.parse(arena.allocator(), src);
    return buildExpr(arena.allocator(), node);
}

test "buildExpr: value literal" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const e = try buildExprFromJson(&arena, "{\"type\":\"value\",\"value\":42}");
    try testing.expect(e.* == .value);
    try testing.expectEqual(@as(f64, 42), e.value.number);
}

test "buildExpr: ref" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const e = try buildExprFromJson(&arena, "{\"type\":\"ref\",\"path\":[\"input\",\"x\"]}");
    try testing.expect(e.* == .ref);
    try testing.expectEqual(@as(usize, 2), e.ref.len);
    try testing.expectEqualStrings("input", e.ref[0]);
}

test "buildExpr: compare canonical and shorthand are equivalent" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const canonical = try buildExprFromJson(&arena, "{\"type\":\"compare\",\"op\":\"eq\"," ++
        "\"left\":{\"type\":\"value\",\"value\":1}," ++
        "\"right\":{\"type\":\"value\",\"value\":1}}");
    const shorthand = try buildExprFromJson(&arena, "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"value\",\"value\":1}," ++
        "\"right\":{\"type\":\"value\",\"value\":1}}");
    try testing.expectEqual(CompareOp.eq, canonical.compare.op);
    try testing.expectEqual(CompareOp.eq, shorthand.compare.op);
}

test "buildExpr: rejects unknown type" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.UnknownExprType, buildExprFromJson(&arena, "{\"type\":\"bogus\"}"));
}

test "buildModule: canonical" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const node = try json.parse(arena.allocator(), "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}" ++
        "]}");
    const m = try buildModule(arena.allocator(), node);
    try testing.expectEqual(@as(usize, 1), m.rules.len);
    try testing.expect(m.rules[0].is_default);
}

fn buildBundleFromJson(arena: *std.heap.ArenaAllocator, src: []const u8) !Modules {
    const node = try json.parse(arena.allocator(), src);
    return buildModulesBundle(arena.allocator(), node);
}

test "buildModulesBundle: two defaults for one rule are rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // Same package, two `default allow` declarations. OPA reports
    // `multiple default rules data.authz.allow found` at compile time;
    // silently keeping the last would make the fallback depend on which
    // module came first in the bundle.
    const across_modules =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}]}," ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}]}" ++
        "]}";
    try testing.expectError(
        error.DuplicateDefaultRule,
        buildBundleFromJson(&arena, across_modules),
    );

    // Also within one module.
    const within_module =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}," ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}" ++
        "]}";
    try testing.expectError(
        error.DuplicateDefaultRule,
        buildBundleFromJson(&arena, within_module),
    );
}

test "buildModulesBundle: defaults for different rules or packages are fine" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // One default per rule name is the normal shape, and the same rule
    // name in a *different* package is a different rule.
    const ok =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}," ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}]}," ++
        "{\"type\":\"module\",\"package\":\"audit\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}]}" ++
        "]}";
    const bundle = try buildBundleFromJson(&arena, ok);
    try testing.expectEqual(@as(usize, 2), bundle.modules.len);
}

test "buildModule: bare expression wraps into allow rule" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const node = try json.parse(arena.allocator(), "{\"type\":\"value\",\"value\":true}");
    const m = try buildModule(arena.allocator(), node);
    try testing.expectEqual(@as(usize, 1), m.rules.len);
    try testing.expectEqualStrings("allow", m.rules[0].name);
    try testing.expectEqual(@as(usize, 1), m.rules[0].body.len);
}
