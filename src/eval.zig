//! Evaluator. Parses the input and AST onto the request arena,
//! projects the AST into `Module`, then walks the rules.
//!
//! Every recursive helper bumps a depth counter capped at
//! `max_eval_depth`. Hitting the cap is reported as
//! `error.EvalTooDeep`; the export wrapper turns that into `-1` and
//! the proxy-wasm shim treats it as deny.
//!
//! `some` and `every` push a `Scope` frame on the C stack while
//! their body runs. Refs check the scope chain before falling back
//! to the input root, so no heap traffic is needed for bindings.

const std = @import("std");
const ast = @import("ast.zig");
const builtins = @import("builtins.zig");
const json = @import("json.zig");

/// Default rule name when the caller doesn't override it.
pub const default_target_rule: []const u8 = "allow";

/// Recursion cap. See `docs/ast.md` for context.
const max_eval_depth: u32 = 32;

/// Stack-allocated buffer for builtin args. Larger calls fall back to
/// `nil` (deny in body position). Bump if a future builtin needs more.
const max_builtin_args: usize = 8;

/// Explicit error set; needed because the recursive helpers form a
/// cycle that the compiler can't infer through.
const HelperError = error{
    EvalTooDeep,
    PathNotObject,
    PathNotFound,
};

/// Rego truthiness: only `false` and undefined (`nil`) are falsy.
/// Every other value -- including `0`, `""`, and `[]` -- is truthy,
/// because in Rego those are *defined* and definedness is what a rule
/// body tests.
fn truthy(v: json.Value) bool {
    return switch (v) {
        .boolean => |b| b,
        .nil => false,
        else => true,
    };
}

/// Scope frame for variables introduced by `some` / `every`.
const Scope = struct {
    parent: ?*const Scope = null,
    name: []const u8,
    bound: json.Value,
};

/// Run a single evaluation. `arena` must already be initialised; this
/// function neither inits nor resets it -- that is the caller's job.
///
/// Targets the default package ("") and the default rule ("allow").
/// Use `evaluateWithTarget` to pick a non-default rule (e.g.
/// "allow_response" or "allow_body"), or `evaluateAddressed` to
/// dispatch into a specific `package.rule` pair within a
/// `{"type":"modules", ...}` bundle.
pub fn evaluate(
    arena: *std.heap.ArenaAllocator,
    input_json: []const u8,
    ast_json: []const u8,
) !bool {
    return evaluateAddressed(arena, input_json, ast_json, "", default_target_rule);
}

/// Run a single evaluation against `target_rule` in the default
/// package (""). Used by the proxy-wasm shim to route phase-specific
/// callbacks: `allow_response` for the response phase and
/// `allow_body` for the body phase, while the request-headers phase
/// stays on `allow`.
pub fn evaluateWithTarget(
    arena: *std.heap.ArenaAllocator,
    input_json: []const u8,
    ast_json: []const u8,
    target_rule: []const u8,
) !bool {
    return evaluateAddressed(arena, input_json, ast_json, "", target_rule);
}

/// Run a single evaluation against `target_package.target_rule`. The
/// AST source can be either a single module or a `Modules` bundle;
/// the legacy single-module form is treated as `package = ""`.
///
/// This parses and builds the policy on every call, which is what the
/// generic `evaluate` export has to do -- it receives the AST bytes
/// per request and can't know they're the same ones as last time.
/// Hosts that hold a policy across requests should build it once and
/// call `evaluateCompiled`.
pub fn evaluateAddressed(
    arena: *std.heap.ArenaAllocator,
    input_json: []const u8,
    ast_json: []const u8,
    target_package: []const u8,
    target_rule: []const u8,
) !bool {
    const allocator = arena.allocator();

    const ast_value = try json.parse(allocator, ast_json);
    const bundle = try ast.buildModulesBundle(allocator, ast_value);

    return evaluateCompiled(arena, input_json, bundle, target_package, target_rule);
}

/// Run a single evaluation against a bundle that was already built.
///
/// `bundle` must outlive the call and must NOT live on `arena` -- the
/// arena is per-request and the whole point here is that the policy
/// isn't. The proxy-wasm shim builds it once at configure time on a
/// long-lived arena, which takes the JSON parse and the AST
/// construction off the per-request path entirely; on a non-trivial
/// policy that is the majority of the work.
pub fn evaluateCompiled(
    arena: *std.heap.ArenaAllocator,
    input_json: []const u8,
    bundle: ast.Modules,
    target_package: []const u8,
    target_rule: []const u8,
) !bool {
    const input_value = try json.parse(arena.allocator(), input_json);
    return evalBundle(bundle, target_package, target_rule, input_value);
}

/// Evaluate `target_rule` over every rule contributed to
/// `target_package`. A `default` rule anywhere in the package supplies
/// the fallback; nothing matching at all denies.
///
/// The scan is package-wide rather than module-by-module on purpose.
/// In Rego a package split across several files is one rule set, so
/// `default allow = false` in one file governs `allow if ...` in
/// another. Evaluating each module in isolation and OR-ing the results
/// got that wrong twice over: the default only covered its own file,
/// and an early module returning `true` short-circuited past a later
/// module's explicit `value: false` deny.
///
/// Every satisfied rule is evaluated, not just the first. `allow` is a
/// *complete* rule: OPA raises `eval_conflict_error` ("complete rules
/// must not produce multiple outputs") when two definitions hold at
/// once with different values, and it does not resolve that by source
/// order. Returning the first match would make zopa answer `allow`
/// where OPA errors, and would make the answer depend on bundle
/// ordering -- which carries no meaning in Rego and shifts when files
/// are split or renamed. `error.RuleConflict` surfaces as `-1`, which
/// every caller treats as deny.
///
/// Two definitions agreeing on a value is not a conflict, matching
/// Rego. The cost of not short-circuiting is that a satisfied policy
/// evaluates all of its `allow` rules rather than stopping at the
/// first; OPA pays the same cost for the same reason.
fn evalBundle(
    bundle: ast.Modules,
    target_package: []const u8,
    target_rule: []const u8,
    input: json.Value,
) !bool {
    var fallback: bool = false;
    var have_fallback: bool = false;
    var decision: ?json.Value = null;

    for (bundle.modules) |module| {
        if (!std.mem.eql(u8, module.package, target_package)) continue;

        for (module.rules) |rule| {
            if (!std.mem.eql(u8, rule.name, target_rule)) continue;

            if (rule.is_default) {
                // A `default` rule with no value is meaningless; skip
                // it rather than letting it mask a real one. Defaults
                // never conflict -- they only apply when nothing else
                // produced a value.
                if (rule.value) |vex| {
                    fallback = truthy(try resolveValue(vex, input, null, 0));
                    have_fallback = true;
                }
                continue;
            }

            if (!try evalBody(rule.body, input)) continue;

            const value = if (rule.value) |vex|
                try resolveValue(vex, input, null, 0)
            else
                json.Value{ .boolean = true };

            if (decision) |already| {
                if (!json.valueEquals(already, value)) return error.RuleConflict;
            } else {
                decision = value;
            }
        }
    }

    if (decision) |v| return truthy(v);
    return if (have_fallback) fallback else false;
}

/// Bodies are an implicit AND of expressions.
fn evalBody(body: []const *const ast.Expr, input: json.Value) !bool {
    for (body) |expr| {
        if (!try evalExprBool(expr, input, null, 0)) return false;
    }
    return true;
}

fn evalExprBool(
    expr: *const ast.Expr,
    input: json.Value,
    scope: ?*const Scope,
    depth: u32,
) HelperError!bool {
    if (depth >= max_eval_depth) return error.EvalTooDeep;
    return switch (expr.*) {
        .value => |v| truthy(v),
        .ref => |path| blk: {
            // Missing paths are undefined in Rego; we treat that as
            // `false` so incomplete input falls through to deny. Only
            // the two "not there" errors fold into false -- anything
            // else (today just the depth guard) has to keep
            // propagating, or a resource limit would read as a policy
            // decision.
            const v = resolveRef(input, scope, path) catch |err| switch (err) {
                error.PathNotFound, error.PathNotObject => break :blk false,
                else => return err,
            };
            break :blk truthy(v);
        },
        .compare => |c| try evalCompare(c, input, scope, depth + 1),
        .not => |inner| !(try evalExprBool(inner, input, scope, depth + 1)),
        .some => |it| try evalSome(it, input, scope, depth + 1),
        .every => |it| try evalEvery(it, input, scope, depth + 1),
        .call => |c| truthy(try evalCall(c, input, scope, depth + 1)),
    };
}

fn evalCompare(
    c: ast.Expr.Compare,
    input: json.Value,
    scope: ?*const Scope,
    depth: u32,
) HelperError!bool {
    if (depth >= max_eval_depth) return error.EvalTooDeep;
    const lhs = try resolveValue(c.left, input, scope, depth + 1);
    const rhs = try resolveValue(c.right, input, scope, depth + 1);
    return switch (c.op) {
        .eq => json.valueEquals(lhs, rhs),
        .neq => !json.valueEquals(lhs, rhs),
        .lt, .lte, .gt, .gte => blk: {
            const ord = json.valueCompare(lhs, rhs) orelse break :blk false;
            break :blk switch (c.op) {
                .lt => ord == .lt,
                .lte => ord != .gt,
                .gt => ord == .gt,
                .gte => ord != .lt,
                else => unreachable,
            };
        },
    };
}

/// Iterator handle returned by `iterItems`. Avoids allocating a
/// projected `Value` slice for object iteration; the consumer reads
/// elements through `len()` and `at()`.
const ItemIter = union(enum) {
    none,
    flat: []const json.Value,
    object_keys: []const json.Value.Member,
    object_values: []const json.Value.Member,

    fn len(self: ItemIter) usize {
        return switch (self) {
            .none => 0,
            .flat => |xs| xs.len,
            .object_keys, .object_values => |members| members.len,
        };
    }

    fn at(self: ItemIter, i: usize) json.Value {
        return switch (self) {
            .none => unreachable,
            .flat => |xs| xs[i],
            .object_keys => |members| .{ .string = members[i].key },
            .object_values => |members| members[i].value,
        };
    }
};

/// `some x in source: body`. True if the body holds for at least
/// one binding. A non-iterable source yields `false`.
fn evalSome(
    it: ast.Expr.Iter,
    input: json.Value,
    scope: ?*const Scope,
    depth: u32,
) HelperError!bool {
    if (depth >= max_eval_depth) return error.EvalTooDeep;
    const items = try iterItems(it.source, it.kind, input, scope, depth + 1);
    if (items == .none) return false;
    var i: usize = 0;
    while (i < items.len()) : (i += 1) {
        const child = Scope{ .parent = scope, .name = it.var_name, .bound = items.at(i) };
        if (try evalExprBool(it.body, input, &child, depth + 1)) return true;
    }
    return false;
}

/// `every x in source: body`. Vacuously true on an empty or
/// non-iterable source.
fn evalEvery(
    it: ast.Expr.Iter,
    input: json.Value,
    scope: ?*const Scope,
    depth: u32,
) HelperError!bool {
    if (depth >= max_eval_depth) return error.EvalTooDeep;
    const items = try iterItems(it.source, it.kind, input, scope, depth + 1);
    if (items == .none) return true;
    var i: usize = 0;
    while (i < items.len()) : (i += 1) {
        const child = Scope{ .parent = scope, .name = it.var_name, .bound = items.at(i) };
        if (!try evalExprBool(it.body, input, &child, depth + 1)) return false;
    }
    return true;
}

/// Resolve `source` to an iterable view. Returns `.none` for
/// non-iterable values; the caller decides the default.
fn iterItems(
    source: *const ast.Expr,
    kind: ast.Expr.IterKind,
    input: json.Value,
    scope: ?*const Scope,
    depth: u32,
) HelperError!ItemIter {
    const v = try resolveValue(source, input, scope, depth);
    return switch (v) {
        .array => |xs| .{ .flat = xs },
        .set => |xs| .{ .flat = xs },
        .object => |members| switch (kind) {
            .keys => .{ .object_keys = members },
            .values => .{ .object_values = members },
        },
        else => .none,
    };
}

/// Resolve an expression to a `Value`. Boolean operators fold into
/// `Value.boolean` so they're usable in value position (rule values,
/// compare operands).
fn resolveValue(
    expr: *const ast.Expr,
    input: json.Value,
    scope: ?*const Scope,
    depth: u32,
) HelperError!json.Value {
    if (depth >= max_eval_depth) return error.EvalTooDeep;
    return switch (expr.*) {
        .value => |v| v,
        // Missing paths in Rego are *undefined*. We surface that as
        // `Value.nil` so callers (compare, call, iterators) see a
        // type-mismatched value rather than an error -- a missing
        // ref inside `eq` should produce false, not -1. EvalTooDeep
        // and RefYieldsComposite still propagate.
        .ref => |path| resolveRef(input, scope, path) catch |err| switch (err) {
            error.PathNotFound, error.PathNotObject => json.Value.nil,
            else => return err,
        },
        .compare => |c| .{ .boolean = try evalCompare(c, input, scope, depth + 1) },
        .not => |inner| .{ .boolean = !(try evalExprBool(inner, input, scope, depth + 1)) },
        .some => |it| .{ .boolean = try evalSome(it, input, scope, depth + 1) },
        .every => |it| .{ .boolean = try evalEvery(it, input, scope, depth + 1) },
        .call => |c| try evalCall(c, input, scope, depth + 1),
    };
}

fn evalCall(
    c: ast.Expr.Call,
    input: json.Value,
    scope: ?*const Scope,
    depth: u32,
) HelperError!json.Value {
    if (depth >= max_eval_depth) return error.EvalTooDeep;
    if (c.args.len > max_builtin_args) return .nil;
    const b = builtins.lookup(c.name) orelse return .nil;
    var resolved: [max_builtin_args]json.Value = undefined;
    for (c.args, 0..) |arg, i| {
        resolved[i] = try resolveValue(arg, input, scope, depth + 1);
    }
    return builtins.dispatch(b, resolved[0..c.args.len]);
}

/// Resolve a ref. The first segment is matched against the scope
/// chain; the rest walk the bound value. A leading `"input"` segment
/// skips the chain and goes straight to the input root.
fn resolveRef(
    input: json.Value,
    scope: ?*const Scope,
    path: []const []const u8,
) HelperError!json.Value {
    if (path.len == 0) return error.PathNotFound;

    if (std.mem.eql(u8, path[0], "input")) {
        return json.lookupPath(input, path);
    }

    var cursor = scope;
    while (cursor) |frame| : (cursor = frame.parent) {
        if (std.mem.eql(u8, frame.name, path[0])) {
            return walkValue(frame.bound, path[1..]);
        }
    }

    // No matching binding -- treat as a plain input ref.
    return json.lookupPath(input, path);
}

/// Walk `path` through `value`. Returns the leaf as-is; the only
/// failure modes are "non-object on the way down" and "key missing".
///
/// Member lookup goes through `json.lookupMember` so a bound variable
/// resolves duplicate keys the same last-wins way `json.lookupPath`
/// does for the input root.
fn walkValue(value: json.Value, path: []const []const u8) HelperError!json.Value {
    var cur = value;
    for (path) |segment| {
        if (cur != .object) return error.PathNotObject;
        cur = json.lookupMember(cur.object, segment) orelse return error.PathNotFound;
    }
    return cur;
}

// Tests.

const testing = std.testing;

fn run(input: []const u8, ast_src: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    return evaluate(&arena, input, ast_src);
}

test "evaluate: literal true allows" {
    try testing.expect(try run("{}", "{\"type\":\"value\",\"value\":true}"));
}

test "evaluate: literal false denies" {
    try testing.expect(!(try run("{}", "{\"type\":\"value\",\"value\":false}")));
}

test "evaluate: ref equality" {
    const policy =
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"admin\"}}";
    try testing.expect(try run("{\"role\":\"admin\"}", policy));
    try testing.expect(!(try run("{\"role\":\"guest\"}", policy)));
}

test "evaluate: missing ref denies" {
    try testing.expect(!(try run("{}", "{\"type\":\"ref\",\"path\":[\"input\",\"missing\"]}")));
}

test "evaluate: missing ref inside compare denies (Rego undefined semantics)" {
    // `input.user.role == "admin"` against `{}` -- the ref resolves
    // to undefined; comparing undefined with a string is false, which
    // means deny in body position. zopa used to surface this as -1
    // (error) which diverged from Rego.
    const policy =
        "{\"type\":\"compare\",\"op\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"user\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"admin\"}}";
    try testing.expect(!(try run("{}", policy)));
    // Sanity: present + matching -> allow, present + mismatch -> deny.
    try testing.expect(try run("{\"user\":{\"role\":\"admin\"}}", policy));
    try testing.expect(!(try run("{\"user\":{\"role\":\"guest\"}}", policy)));
}

test "evaluate: default rule when no other rule matches" {
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}," ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"admin\"}}]}" ++
        "]}";
    try testing.expect(!(try run("{\"role\":\"guest\"}", policy)));
    try testing.expect(try run("{\"role\":\"admin\"}", policy));
}

test "evaluate: call startswith on input.path" {
    const policy =
        "{\"type\":\"call\",\"name\":\"startswith\",\"args\":[" ++
        "{\"type\":\"ref\",\"path\":[\"input\",\"path\"]}," ++
        "{\"type\":\"value\",\"value\":\"/admin/\"}]}";
    try testing.expect(try run("{\"path\":\"/admin/users\"}", policy));
    try testing.expect(!(try run("{\"path\":\"/users\"}", policy)));
}

test "evaluate: call count compared with gt" {
    const policy =
        "{\"type\":\"gt\"," ++
        "\"left\":{\"type\":\"call\",\"name\":\"count\",\"args\":[" ++
        "{\"type\":\"ref\",\"path\":[\"input\",\"perms\"]}]}," ++
        "\"right\":{\"type\":\"value\",\"value\":2}}";
    try testing.expect(try run("{\"perms\":[\"r\",\"w\",\"x\"]}", policy));
    try testing.expect(!(try run("{\"perms\":[\"r\"]}", policy)));
}

test "evaluate: unknown builtin denies" {
    const policy =
        "{\"type\":\"call\",\"name\":\"made_up_fn\",\"args\":[" ++
        "{\"type\":\"value\",\"value\":1}]}";
    try testing.expect(!(try run("{}", policy)));
}

test "evaluate: every over object keys" {
    const policy =
        "{\"type\":\"every\",\"var\":\"k\",\"kind\":\"keys\"," ++
        "\"source\":{\"type\":\"ref\",\"path\":[\"input\",\"attrs\"]}," ++
        "\"body\":{\"type\":\"neq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"k\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"internal\"}}}";
    try testing.expect(try run(
        "{\"attrs\":{\"team\":\"sre\",\"region\":\"us-east\"}}",
        policy,
    ));
    try testing.expect(!(try run(
        "{\"attrs\":{\"team\":\"sre\",\"internal\":\"yes\"}}",
        policy,
    )));
}

test "evaluate: some over object values" {
    const policy =
        "{\"type\":\"some\",\"var\":\"v\",\"kind\":\"values\"," ++
        "\"source\":{\"type\":\"ref\",\"path\":[\"input\",\"flags\"]}," ++
        "\"body\":{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"v\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":true}}}";
    try testing.expect(try run(
        "{\"flags\":{\"a\":false,\"b\":true,\"c\":false}}",
        policy,
    ));
    try testing.expect(!(try run(
        "{\"flags\":{\"a\":false,\"b\":false}}",
        policy,
    )));
}

test "evaluate: every over object defaults to keys" {
    const policy =
        "{\"type\":\"every\",\"var\":\"k\"," ++
        "\"source\":{\"type\":\"ref\",\"path\":[\"input\",\"m\"]}," ++
        "\"body\":{\"type\":\"neq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"k\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"banned\"}}}";
    try testing.expect(try run("{\"m\":{\"x\":1,\"y\":2}}", policy));
    try testing.expect(!(try run("{\"m\":{\"x\":1,\"banned\":2}}", policy)));
}

fn runAddressed(input: []const u8, ast_src: []const u8, pkg: []const u8, rule: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    return evaluateAddressed(&arena, input, ast_src, pkg, rule);
}

test "modules bundle: address authz.allow vs audit.allow" {
    const policy =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"admin\"}}]}]}," ++
        "{\"type\":\"module\",\"package\":\"audit\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"value\",\"value\":true}]}]}" ++
        "]}";

    // authz.allow fires only on admin.
    try testing.expect(try runAddressed("{\"role\":\"admin\"}", policy, "authz", "allow"));
    try testing.expect(!(try runAddressed("{\"role\":\"guest\"}", policy, "authz", "allow")));

    // audit.allow always fires regardless of role.
    try testing.expect(try runAddressed("{\"role\":\"guest\"}", policy, "audit", "allow"));
}

test "modules bundle: missing package -> deny" {
    const policy =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"value\",\"value\":true}]}]}" ++
        "]}";
    try testing.expect(!(try runAddressed("{}", policy, "missing", "allow")));
}

test "modules bundle: bare module wraps as package='' (backwards compat)" {
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"value\",\"value\":true}]}]}";
    try testing.expect(try runAddressed("{}", policy, "", "allow"));
    // Same module via the default `evaluate` entry must still allow.
    try testing.expect(try run("{}", policy));
}

test "modules bundle: OR across two modules in same package" {
    const policy =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"admin\"}}]}]}," ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"editor\"}}]}]}" ++
        "]}";
    try testing.expect(try runAddressed("{\"role\":\"admin\"}", policy, "authz", "allow"));
    try testing.expect(try runAddressed("{\"role\":\"editor\"}", policy, "authz", "allow"));
    try testing.expect(!(try runAddressed("{\"role\":\"guest\"}", policy, "authz", "allow")));
}

test "modules bundle: a package-level default covers sibling modules" {
    // In Rego a package split across files is one rule set, so the
    // `default allow = true` declared in the first module governs the
    // second module's rules too.
    const policy =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}]}," ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"banned\"}}]," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}]}" ++
        "]}";

    // Nothing matches -> the sibling module's default decides.
    try testing.expect(try runAddressed("{\"role\":\"viewer\"}", policy, "authz", "allow"));
    // The deny rule in module 2 overrides module 1's default.
    try testing.expect(!(try runAddressed("{\"role\":\"banned\"}", policy, "authz", "allow")));
}

test "modules bundle: two definitions holding at once is a conflict" {
    // Module 1 allows tenant acme; module 2 denies banned roles. Both
    // are definitions of the same complete rule `authz.allow`, so an
    // input satisfying both asks for two different outputs. OPA reports
    // that as eval_conflict_error rather than picking one by source
    // order, and so do we -- the caller turns the error into a deny.
    const policy =
        "{\"type\":\"modules\",\"modules\":[" ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"tenant\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"acme\"}}]}]}," ++
        "{\"type\":\"module\",\"package\":\"authz\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"banned\"}}]," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}]}" ++
        "]}";

    try testing.expect(try runAddressed(
        "{\"tenant\":\"acme\",\"role\":\"viewer\"}",
        policy,
        "authz",
        "allow",
    ));
    // Both hold: true from module 1, false from module 2. Answering
    // `allow` here would diverge from OPA and would make the decision
    // depend on which module happens to come first in the bundle.
    try testing.expectError(error.RuleConflict, runAddressed(
        "{\"tenant\":\"acme\",\"role\":\"banned\"}",
        policy,
        "authz",
        "allow",
    ));
    // With module 1 not matching, evaluation carries on into module 2
    // and its `value: false` deny is reached. The old module-at-a-time
    // implementation returned module 1's "no match" as a plain false
    // and never got here.
    try testing.expect(!(try runAddressed(
        "{\"tenant\":\"other\",\"role\":\"banned\"}",
        policy,
        "authz",
        "allow",
    )));
}

test "modules bundle: definitions agreeing on a value are not a conflict" {
    // Two rules that both hold and both yield `true` are fine in Rego:
    // a complete rule may have any number of definitions as long as
    // they produce the same output. This is the ordinary `allow if A`
    // / `allow if B` shape, so treating it as a conflict would break
    // almost every real policy.
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}," ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"admin\"}}]}," ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"tenant\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"acme\"}}]}" ++
        "]}";

    try testing.expect(try run("{\"role\":\"admin\",\"tenant\":\"acme\"}", policy));
    try testing.expect(try run("{\"role\":\"admin\",\"tenant\":\"other\"}", policy));
    try testing.expect(try run("{\"role\":\"guest\",\"tenant\":\"acme\"}", policy));
    try testing.expect(!(try run("{\"role\":\"guest\",\"tenant\":\"other\"}", policy)));
}

test "modules bundle: a default never conflicts with a rule that fires" {
    // `default allow = true` plus a rule yielding false is the
    // deny-override shape the response and body phases use. The default
    // is a fallback, not a competing definition, so it must not trip
    // the conflict check.
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}," ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"banned\"}}]," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}" ++
        "]}";
    try testing.expect(try run("{\"role\":\"viewer\"}", policy));
    try testing.expect(!(try run("{\"role\":\"banned\"}", policy)));
}

test "evaluate: input key literally named `input` is still reachable" {
    // `lookupPath` strips one leading "input" segment, so addressing a
    // real member called `input` needs the prefix spelled twice.
    const policy =
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"input\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"x\"}}";
    try testing.expect(try run("{\"input\":\"x\"}", policy));
}

test "evaluate: duplicate keys in input resolve last-wins" {
    const policy =
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"user\",\"role\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"admin\"}}";
    // The backend (Go/JS) reads "guest"; zopa must agree, i.e. deny.
    try testing.expect(!(try run(
        "{\"user\":{\"role\":\"admin\",\"role\":\"guest\"}}",
        policy,
    )));
}

test "evaluate: falsy-but-defined values stay truthy in body position" {
    // Rego tests definedness, not JS truthiness: `0`, `""` and `[]`
    // are all defined, so a bare ref to them holds.
    try testing.expect(try run("{\"x\":0}", "{\"type\":\"ref\",\"path\":[\"input\",\"x\"]}"));
    try testing.expect(try run("{\"x\":\"\"}", "{\"type\":\"ref\",\"path\":[\"input\",\"x\"]}"));
    try testing.expect(try run("{\"x\":[]}", "{\"type\":\"ref\",\"path\":[\"input\",\"x\"]}"));
    // `null` and `false` are the only falsy ones.
    try testing.expect(!(try run("{\"x\":null}", "{\"type\":\"ref\",\"path\":[\"input\",\"x\"]}")));
    try testing.expect(!(try run("{\"x\":false}", "{\"type\":\"ref\",\"path\":[\"input\",\"x\"]}")));
}

fn runWithTarget(input: []const u8, ast_src: []const u8, target: []const u8) !bool {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    return evaluateWithTarget(&arena, input, ast_src, target);
}

test "evaluateWithTarget: allow_response fires on 5xx" {
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow_response\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}," ++
        "{\"type\":\"rule\",\"name\":\"allow_response\",\"body\":[" ++
        "{\"type\":\"gte\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"response\",\"status\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":500}}]," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}" ++
        "]}";

    // 5xx responses fail the allow_response rule -> deny -> 503 replacement.
    try testing.expect(!(try runWithTarget(
        "{\"response\":{\"status\":500,\"headers\":{}}}",
        policy,
        "allow_response",
    )));

    // Non-5xx responses go through default (allow).
    try testing.expect(try runWithTarget(
        "{\"response\":{\"status\":200,\"headers\":{}}}",
        policy,
        "allow_response",
    ));
}

test "evaluateWithTarget: missing target rule -> deny" {
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow\",\"body\":[" ++
        "{\"type\":\"value\",\"value\":true}]}]}";
    // Policy only has `allow`; `allow_response` doesn't exist.
    try testing.expect(!(try runWithTarget("{}", policy, "allow_response")));
}

test "evaluateWithTarget: allow target preserves default behaviour" {
    const policy = "{\"type\":\"value\",\"value\":true}";
    try testing.expect(try runWithTarget("{}", policy, "allow"));
}

test "evaluateWithTarget: allow_body fires on amount > limit" {
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}," ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"body\":[" ++
        "{\"type\":\"gt\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body\",\"amount\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":1000}}]," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}" ++
        "]}";

    // Body amount over limit -> rule fires returning false -> deny.
    try testing.expect(!(try runWithTarget(
        "{\"body\":{\"amount\":5000},\"body_raw\":\"...\"}",
        policy,
        "allow_body",
    )));

    // Body amount under limit -> default rule wins -> allow.
    try testing.expect(try runWithTarget(
        "{\"body\":{\"amount\":50},\"body_raw\":\"...\"}",
        policy,
        "allow_body",
    ));
}

test "evaluateWithTarget: body_raw fallback when body parse fails" {
    // Policy targets body_raw directly so a non-JSON body is still
    // policy-checkable.
    const policy =
        "{\"type\":\"module\",\"rules\":[" ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"body\":[" ++
        "{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"input\",\"body_raw\"]}," ++
        "\"right\":{\"type\":\"value\",\"value\":\"BLOCKED\"}}]," ++
        "\"value\":{\"type\":\"value\",\"value\":false}}," ++
        "{\"type\":\"rule\",\"name\":\"allow_body\",\"default\":true," ++
        "\"value\":{\"type\":\"value\",\"value\":true}}" ++
        "]}";
    try testing.expect(!(try runWithTarget(
        "{\"body\":null,\"body_raw\":\"BLOCKED\"}",
        policy,
        "allow_body",
    )));
    try testing.expect(try runWithTarget(
        "{\"body\":null,\"body_raw\":\"ok\"}",
        policy,
        "allow_body",
    ));
}

test "evaluate: every+some over arrays" {
    const policy =
        "{\"type\":\"every\",\"var\":\"req\"," ++
        "\"source\":{\"type\":\"ref\",\"path\":[\"input\",\"required\"]}," ++
        "\"body\":{\"type\":\"some\",\"var\":\"have\"," ++
        "\"source\":{\"type\":\"ref\",\"path\":[\"input\",\"granted\"]}," ++
        "\"body\":{\"type\":\"eq\"," ++
        "\"left\":{\"type\":\"ref\",\"path\":[\"have\"]}," ++
        "\"right\":{\"type\":\"ref\",\"path\":[\"req\"]}}}}";
    try testing.expect(try run(
        "{\"required\":[\"r\",\"w\"],\"granted\":[\"r\",\"w\",\"x\"]}",
        policy,
    ));
    try testing.expect(!(try run(
        "{\"required\":[\"r\",\"d\"],\"granted\":[\"r\",\"w\"]}",
        policy,
    )));
}

test "fuzz: an arbitrary AST either decides or errors, never crashes" {
    try testing.fuzz({}, fuzzEvaluate, .{});
}

fn fuzzEvaluate(_: void, smith: *std.testing.Smith) !void {
    @disableInstrumentation();
    var ast_buf: [512]u8 = undefined;
    const ast_len = smith.sliceWeightedBytes(&ast_buf, &.{
        .rangeAtMost(u8, 0x20, 0x7e, 1),
        .value(u8, '{', 6),
        .value(u8, '}', 6),
        .value(u8, '[', 6),
        .value(u8, ']', 6),
        .value(u8, '"', 8),
        .value(u8, ':', 4),
        .value(u8, ',', 4),
        .rangeAtMost(u8, 'a', 'z', 6),
        .rangeAtMost(u8, '0', '9', 3),
    });

    var input_buf: [128]u8 = undefined;
    const input_len = smith.sliceWeightedBytes(&input_buf, &.{
        .rangeAtMost(u8, 0x20, 0x7e, 1),
        .value(u8, '{', 4),
        .value(u8, '}', 4),
        .value(u8, '"', 6),
        .value(u8, ':', 3),
        .rangeAtMost(u8, 'a', 'z', 4),
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    // The contract the wasm exports depend on: every outcome is either
    // a boolean decision or an error. A hostile policy must not be
    // able to reach unreachable code, blow the stack, or leave the
    // arena in a state the next request inherits.
    const decision = evaluate(&arena, input_buf[0..input_len], ast_buf[0..ast_len]) catch return;
    std.mem.doNotOptimizeAway(decision);
}

test "evaluate: depth guard fires" {
    var policy: std.ArrayList(u8) = .empty;
    defer policy.deinit(testing.allocator);
    var i: u32 = 0;
    while (i < max_eval_depth + 4) : (i += 1) {
        try policy.appendSlice(testing.allocator, "{\"type\":\"not\",\"expr\":");
    }
    try policy.appendSlice(testing.allocator, "{\"type\":\"value\",\"value\":true}");
    i = 0;
    while (i < max_eval_depth + 4) : (i += 1) {
        try policy.append(testing.allocator, '}');
    }
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.EvalTooDeep, evaluate(&arena, "{}", policy.items));
}
