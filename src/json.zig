//! Recursive-descent JSON parser. Smaller than `std.json` and shares
//! its `Value` tree with `ast.zig` and `eval.zig`, so the evaluator
//! never has to re-project between formats.
//!
//! Strings without escape sequences alias the source buffer directly;
//! only escaped strings allocate. All allocations go on the
//! caller-supplied allocator (the request arena, in zopa).
//!
//! `Value.string` payloads can alias the source buffer the host owns,
//! so the host must keep the JSON bytes alive until evaluation
//! finishes.
//!
//! Covers the full JSON grammar: objects, arrays, strings (including
//! `\uXXXX` and surrogate-pair escapes), numbers (parsed as `f64`),
//! and the three literals.
//!
//! Strictness matters here for a reason that isn't obvious: zopa sees
//! the same request as the service behind it. If the two parsers
//! disagree about a document, a policy can be made to read one value
//! while the backend reads another. So the number grammar is the
//! RFC 8259 one (no `01`, no `1.`, no `.5`, no `+1`) rather than
//! whatever `parseFloat` happens to accept, and duplicate object keys
//! resolve last-wins, matching Go's `encoding/json` (hence OPA/Rego)
//! and JavaScript's `JSON.parse`.

const std = @import("std");

/// Tagged value tree shared by the parser, the AST, and the
/// evaluator. `set` does not appear in pure JSON; the AST builder
/// produces it from `{"type":"set", ...}` literals.
pub const Value = union(enum) {
    nil,
    boolean: bool,
    number: f64,
    string: []const u8,
    array: []const Value,
    object: []const Member,
    set: []const Value,

    pub const Member = struct {
        key: []const u8,
        value: Value,
    };
};

pub const ParseError = error{
    UnexpectedToken,
    UnexpectedEof,
    InvalidNumber,
    InvalidString,
    InvalidEscape,
    InvalidUnicode,
    InvalidLiteral,
    NestingTooDeep,
    OutOfMemory,
};

/// Maximum nesting depth. Bump if you have a documented need.
const max_depth: u32 = 64;

/// Member count past which `parseObject` stops deduping keys with a
/// scan per insert and sorts once at the end instead.
const object_scan_max: usize = 16;

/// Collapse duplicate keys last-wins, each surviving key keeping the
/// position it first appeared at (what `JSON.parse` does). Returns the
/// surviving prefix of `members`.
///
/// Sorts rather than hashes. An unseeded hash -- and a freestanding
/// module has nothing to seed one with -- lets a request body made of
/// colliding keys turn the parse quadratic. A heap sort is O(n log n)
/// for every input, so no choice of keys is worse than any other.
fn dedupeWide(allocator: std.mem.Allocator, members: []Value.Member) error{OutOfMemory}![]Value.Member {
    // One scratch allocation: on the request arena a free only returns
    // the most recent block, so every extra buffer here would stay
    // allocated until the reset.
    const Slot = struct { hash: u32, pos: u32 };
    const order = try allocator.alloc(Slot, members.len);
    defer allocator.free(order);
    for (order, members, 0..) |*o, m, i| o.* = .{ .hash = std.hash.Fnv1a_32.hash(m.key), .pos = @intCast(i) };

    // By hash, then key, then position, so each run of one key ends at
    // its last occurrence and starts at its first. The hash only makes
    // the common comparison an integer one; keys crafted to collide fall
    // through to comparing bytes, still within the sort's bound.
    std.sort.heap(Slot, order, members, struct {
        fn lessThan(ms: []Value.Member, a: Slot, b: Slot) bool {
            if (a.hash != b.hash) return a.hash < b.hash;
            return switch (std.mem.order(u8, ms[a.pos].key, ms[b.pos].key)) {
                .lt => true,
                .gt => false,
                .eq => a.pos < b.pos,
            };
        }
    }.lessThan);

    var run: usize = 0;
    while (run < order.len) {
        var end = run + 1;
        while (end < order.len and order[end].hash == order[run].hash and
            std.mem.eql(u8, members[order[end].pos].key, members[order[run].pos].key)) end += 1;
        members[order[run].pos].value = members[order[end - 1].pos].value;
        // Later runs never look at these positions again, so the key
        // itself can carry the mark.
        for (order[run + 1 .. end]) |o| members[o.pos].key = shadowed_key;
        run = end;
    }

    var w: usize = 0;
    for (members) |m| {
        if (m.key.ptr == shadowed_key.ptr) continue;
        members[w] = m;
        w += 1;
    }
    return members[0..w];
}

/// Marks a member `dedupeWide` drops. Compared by address, so no key
/// read from a document can be mistaken for it.
const shadowed_key: []const u8 = "\x00shadowed";

/// Parse `source` into a `Value`, allocating on `allocator`.
pub fn parse(allocator: std.mem.Allocator, source: []const u8) ParseError!Value {
    var p = Parser{ .src = source, .i = 0, .allocator = allocator, .depth = 0 };
    p.skipWs();
    const v = try p.parseValue();
    p.skipWs();
    if (p.i != p.src.len) return error.UnexpectedToken;
    return v;
}

const Parser = struct {
    src: []const u8,
    i: usize,
    depth: u32,
    allocator: std.mem.Allocator,

    fn peek(self: *Parser) ?u8 {
        return if (self.i < self.src.len) self.src[self.i] else null;
    }

    fn advance(self: *Parser) ?u8 {
        if (self.i >= self.src.len) return null;
        const c = self.src[self.i];
        self.i += 1;
        return c;
    }

    fn expect(self: *Parser, c: u8) ParseError!void {
        const got = self.advance() orelse return error.UnexpectedEof;
        if (got != c) return error.UnexpectedToken;
    }

    fn skipWs(self: *Parser) void {
        while (self.i < self.src.len) {
            switch (self.src[self.i]) {
                ' ', '\t', '\n', '\r' => self.i += 1,
                else => break,
            }
        }
    }

    fn parseValue(self: *Parser) ParseError!Value {
        self.skipWs();
        const c = self.peek() orelse return error.UnexpectedEof;
        return switch (c) {
            '{' => self.parseObject(),
            '[' => self.parseArray(),
            '"' => .{ .string = try self.parseString() },
            't', 'f' => self.parseBool(),
            'n' => self.parseNull(),
            '-', '0'...'9' => self.parseNumber(),
            else => error.UnexpectedToken,
        };
    }

    fn enter(self: *Parser) ParseError!void {
        if (self.depth >= max_depth) return error.NestingTooDeep;
        self.depth += 1;
    }

    fn leave(self: *Parser) void {
        self.depth -= 1;
    }

    fn parseObject(self: *Parser) ParseError!Value {
        try self.enter();
        defer self.leave();

        try self.expect('{');
        // Accumulate into a list, then dupe into a fixed slice. The
        // list's deinit is a no-op when allocator is an arena.
        var entries: std.ArrayList(Value.Member) = .empty;
        defer entries.deinit(self.allocator);

        self.skipWs();
        if (self.peek() == @as(u8, '}')) {
            _ = self.advance();
            return .{ .object = try self.allocator.dupe(Value.Member, entries.items) };
        }

        // A repeated key overwrites the earlier member instead of
        // appending, so the object holds what Go/JS/OPA hold.
        // `lookupMember` alone is not enough: iteration, `count`, and
        // object equality read the whole member list, and a shadowed
        // value left in it is one the backend never sees -- `some v in
        // obj` matching it is a bypass. A small object is deduped as it
        // is read; a wide one once, at the end, so a body of thousands of
        // keys costs a sort rather than a scan per key.
        while (true) {
            self.skipWs();
            const key = try self.parseString();
            self.skipWs();
            try self.expect(':');
            const v = try self.parseValue();
            const existing: ?usize = if (entries.items.len < object_scan_max) blk: {
                for (entries.items, 0..) |e, i| {
                    if (std.mem.eql(u8, e.key, key)) break :blk i;
                }
                break :blk null;
            } else null;
            if (existing) |i| {
                entries.items[i].value = v;
            } else {
                try entries.append(self.allocator, .{ .key = key, .value = v });
            }

            self.skipWs();
            const sep = self.advance() orelse return error.UnexpectedEof;
            if (sep == ',') continue;
            if (sep == '}') break;
            return error.UnexpectedToken;
        }

        const members = if (entries.items.len > object_scan_max)
            try dedupeWide(self.allocator, entries.items)
        else
            entries.items;
        return .{ .object = try self.allocator.dupe(Value.Member, members) };
    }

    fn parseArray(self: *Parser) ParseError!Value {
        try self.enter();
        defer self.leave();

        try self.expect('[');
        var items: std.ArrayList(Value) = .empty;
        defer items.deinit(self.allocator);

        self.skipWs();
        if (self.peek() == @as(u8, ']')) {
            _ = self.advance();
            return .{ .array = try self.allocator.dupe(Value, items.items) };
        }

        while (true) {
            const v = try self.parseValue();
            try items.append(self.allocator, v);

            self.skipWs();
            const sep = self.advance() orelse return error.UnexpectedEof;
            if (sep == ',') continue;
            if (sep == ']') break;
            return error.UnexpectedToken;
        }

        return .{ .array = try self.allocator.dupe(Value, items.items) };
    }

    /// Returns a slice aliasing the source buffer when the string has
    /// no escapes; otherwise allocates a decoded copy.
    fn parseString(self: *Parser) ParseError![]const u8 {
        try self.expect('"');
        const start = self.i;
        var saw_escape = false;

        while (self.i < self.src.len) : (self.i += 1) {
            const c = self.src[self.i];
            if (c == '"') {
                const raw = self.src[start..self.i];
                self.i += 1;
                if (!saw_escape) return raw;
                return try decodeEscapes(self.allocator, raw);
            }
            if (c == '\\') {
                saw_escape = true;
                self.i += 1;
                if (self.i >= self.src.len) return error.UnexpectedEof;
                continue;
            }
            if (c < 0x20) return error.InvalidString;
        }
        return error.UnexpectedEof;
    }

    fn parseBool(self: *Parser) ParseError!Value {
        if (self.matchLiteral("true")) return .{ .boolean = true };
        if (self.matchLiteral("false")) return .{ .boolean = false };
        return error.InvalidLiteral;
    }

    fn parseNull(self: *Parser) ParseError!Value {
        if (self.matchLiteral("null")) return .nil;
        return error.InvalidLiteral;
    }

    fn matchLiteral(self: *Parser, lit: []const u8) bool {
        if (self.src.len - self.i < lit.len) return false;
        if (!std.mem.eql(u8, self.src[self.i .. self.i + lit.len], lit)) return false;
        self.i += lit.len;
        return true;
    }

    /// Scan exactly the RFC 8259 number grammar:
    ///
    /// ```text
    ///   number = [ "-" ] int [ frac ] [ exp ]
    ///   int    = "0" / ( digit1-9 *DIGIT )
    ///   frac   = "." 1*DIGIT
    ///   exp    = ( "e" / "E" ) [ "+" / "-" ] 1*DIGIT
    /// ```
    ///
    /// Handing the slice straight to `parseFloat` would also accept
    /// `01`, `1.`, `1e`, and `-.5`; a host that rejects those sees a
    /// different document than we do, which is exactly the kind of
    /// disagreement a policy bypass is built on.
    fn parseNumber(self: *Parser) ParseError!Value {
        const start = self.i;

        if (self.peek() == @as(u8, '-')) self.i += 1;

        // int: a lone `0`, or a non-zero digit followed by digits.
        const lead = self.peek() orelse return error.InvalidNumber;
        if (lead == '0') {
            self.i += 1;
            // `01` would otherwise scan as `0` and leave `1` behind as
            // a trailing token. Rejecting it here names the actual
            // problem instead of blaming the next character.
            if (self.hasDigit()) return error.InvalidNumber;
        } else if (lead >= '1' and lead <= '9') {
            self.skipDigits();
        } else {
            return error.InvalidNumber;
        }

        // frac
        if (self.peek() == @as(u8, '.')) {
            self.i += 1;
            if (!self.hasDigit()) return error.InvalidNumber;
            self.skipDigits();
        }

        // exp
        if (self.peek()) |c| {
            if (c == 'e' or c == 'E') {
                self.i += 1;
                if (self.peek()) |sign| {
                    if (sign == '+' or sign == '-') self.i += 1;
                }
                if (!self.hasDigit()) return error.InvalidNumber;
                self.skipDigits();
            }
        }

        const text = self.src[start..self.i];
        const f = std.fmt.parseFloat(f64, text) catch return error.InvalidNumber;
        return .{ .number = f };
    }

    fn hasDigit(self: *Parser) bool {
        const c = self.peek() orelse return false;
        return c >= '0' and c <= '9';
    }

    fn skipDigits(self: *Parser) void {
        while (self.hasDigit()) self.i += 1;
    }
};

/// Decode the escape sequences inside a JSON string. Output length
/// is bounded by input length, so a single up-front allocation is
/// always enough.
fn decodeEscapes(allocator: std.mem.Allocator, raw: []const u8) ParseError![]u8 {
    var out = try allocator.alloc(u8, raw.len);
    var oi: usize = 0;
    var i: usize = 0;

    while (i < raw.len) {
        const c = raw[i];
        if (c != '\\') {
            out[oi] = c;
            oi += 1;
            i += 1;
            continue;
        }
        i += 1;
        if (i >= raw.len) return error.UnexpectedEof;

        const esc = raw[i];
        i += 1;
        switch (esc) {
            '"' => {
                out[oi] = '"';
                oi += 1;
            },
            '\\' => {
                out[oi] = '\\';
                oi += 1;
            },
            '/' => {
                out[oi] = '/';
                oi += 1;
            },
            'b' => {
                out[oi] = 0x08;
                oi += 1;
            },
            'f' => {
                out[oi] = 0x0c;
                oi += 1;
            },
            'n' => {
                out[oi] = '\n';
                oi += 1;
            },
            'r' => {
                out[oi] = '\r';
                oi += 1;
            },
            't' => {
                out[oi] = '\t';
                oi += 1;
            },
            'u' => {
                if (i + 4 > raw.len) return error.InvalidUnicode;
                const cu1 = std.fmt.parseInt(u16, raw[i .. i + 4], 16) catch return error.InvalidUnicode;
                i += 4;

                var cp: u21 = undefined;
                if (cu1 >= 0xD800 and cu1 <= 0xDBFF) {
                    // High surrogate -- must be followed by `\uYYYY`
                    // low surrogate to form a non-BMP code point.
                    if (i + 6 > raw.len or raw[i] != '\\' or raw[i + 1] != 'u') {
                        return error.InvalidUnicode;
                    }
                    const cu2 = std.fmt.parseInt(u16, raw[i + 2 .. i + 6], 16) catch return error.InvalidUnicode;
                    if (cu2 < 0xDC00 or cu2 > 0xDFFF) return error.InvalidUnicode;
                    i += 6;
                    const high: u21 = cu1 - 0xD800;
                    const low: u21 = cu2 - 0xDC00;
                    cp = 0x10000 + (high << 10) + low;
                } else if (cu1 >= 0xDC00 and cu1 <= 0xDFFF) {
                    // Lone low surrogate -- invalid in any UTF.
                    return error.InvalidUnicode;
                } else {
                    cp = cu1;
                }

                // UTF-8 length is always <= the source escape length,
                // so `out` (sized to the input) is wide enough.
                const n = std.unicode.utf8Encode(cp, out[oi..]) catch return error.InvalidUnicode;
                oi += n;
            },
            else => return error.InvalidEscape,
        }
    }
    return out[0..oi];
}

// Helpers shared with the evaluator.

/// Walk a path of member names through nested objects (Rego ref
/// semantics). A leading `"input"` segment is stripped if present.
///
/// Member names only. The evaluator walks paths that may carry array
/// indices itself, over `ast.Expr.PathSegment`, so this form stays for
/// the call sites that only ever have names -- and `json.zig` goes on
/// not importing the AST.
pub fn lookupPath(root: Value, path: []const []const u8) !Value {
    var start: usize = 0;
    if (path.len > 0 and std.mem.eql(u8, path[0], "input")) start = 1;

    var cur = root;
    var i: usize = start;
    while (i < path.len) : (i += 1) {
        if (cur != .object) return error.PathNotObject;
        cur = lookupMember(cur.object, path[i]) orelse return error.PathNotFound;
    }
    return cur;
}

/// Value bound to `key`, or `null` if the object has no such member.
/// Public so the AST builder and the evaluator both reuse it instead
/// of open-coding the scan.
///
/// Scans backwards so a duplicated key resolves to the *last*
/// occurrence. That is what Go's `encoding/json` and JavaScript's
/// `JSON.parse` do, so a request body carrying `{"role":"admin",
/// "role":"guest"}` means the same thing to zopa as it does to the
/// service behind the proxy.
pub fn lookupMember(members: []const Value.Member, key: []const u8) ?Value {
    var i = members.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, members[i].key, key)) return members[i].value;
    }
    return null;
}

/// Strict structural equality. Different kinds compare unequal.
/// Object and set comparison ignores member order.
pub fn valueEquals(a: Value, b: Value) bool {
    return switch (a) {
        .nil => b == .nil,
        .boolean => |ba| switch (b) {
            .boolean => |bb| ba == bb,
            else => false,
        },
        .number => |na| switch (b) {
            .number => |nb| na == nb,
            else => false,
        },
        .string => |sa| switch (b) {
            .string => |sb| std.mem.eql(u8, sa, sb),
            else => false,
        },
        .array => |xa| switch (b) {
            .array => |xb| arrayEqual(xa, xb),
            else => false,
        },
        .object => |oa| switch (b) {
            .object => |ob| objectEqual(oa, ob),
            else => false,
        },
        .set => |sa| switch (b) {
            .set => |sb| setEqual(sa, sb),
            else => false,
        },
    };
}

fn arrayEqual(a: []const Value, b: []const Value) bool {
    if (a.len != b.len) return false;
    for (a, 0..) |x, i| if (!valueEquals(x, b[i])) return false;
    return true;
}

// Maximum object width we can match without duplicate-key risk.
// Real policy objects are tiny; widening just bumps the on-stack
// bitmap size.
const object_match_max: usize = 64;

fn objectEqual(a: []const Value.Member, b: []const Value.Member) bool {
    if (a.len != b.len) return false;
    if (b.len > object_match_max) return objectEqualLinear(a, b);

    // Match each entry of `a` against an unconsumed entry of `b`.
    // A consumed-bitmap stops a duplicate key in `a` from matching
    // the same `b` entry twice.
    var consumed = [_]bool{false} ** object_match_max;
    outer: for (a) |ea| {
        for (b, 0..) |eb, i| {
            if (consumed[i]) continue;
            if (std.mem.eql(u8, ea.key, eb.key) and valueEquals(ea.value, eb.value)) {
                consumed[i] = true;
                continue :outer;
            }
        }
        return false;
    }
    return true;
}

// Fallback for objects wider than `object_match_max`. Cannot
// distinguish duplicate keys, but never allocates from inside the
// equality helper.
fn objectEqualLinear(a: []const Value.Member, b: []const Value.Member) bool {
    if (a.len != b.len) return false;
    outer: for (a) |ea| {
        for (b) |eb| {
            if (std.mem.eql(u8, ea.key, eb.key) and valueEquals(ea.value, eb.value))
                continue :outer;
        }
        return false;
    }
    return true;
}

// Set equality is order- and multiplicity-insensitive: a ⊆ b ∧ b ⊆ a.
// `[1] == [1, 1]` evaluates true, matching the contract in
// `docs/ast.md`.
fn setEqual(a: []const Value, b: []const Value) bool {
    return setSubsetOf(a, b) and setSubsetOf(b, a);
}

fn setSubsetOf(needle: []const Value, haystack: []const Value) bool {
    outer: for (needle) |x| {
        for (haystack) |y| if (valueEquals(x, y)) continue :outer;
        return false;
    }
    return true;
}

/// Rego's ordering, as `<` / `>` see it. OPA orders every pair of
/// values, across types too: null < boolean < number < string < array <
/// object < set, so `"abc" > 5` holds. Arrays compare element by element,
/// then by length. Returns `null` only for two objects or two sets, which
/// OPA orders by their sorted contents; that needs an allocation this
/// helper does not make, so the caller reports it rather than guessing.
pub fn valueCompare(a: Value, b: Value) ?std.math.Order {
    const ra = typeRank(a);
    const rb = typeRank(b);
    if (ra != rb) return std.math.order(ra, rb);
    return switch (a) {
        .nil => .eq,
        .boolean => |ba| std.math.order(@intFromBool(ba), @intFromBool(b.boolean)),
        .number => |na| std.math.order(na, b.number),
        .string => |sa| std.mem.order(u8, sa, b.string),
        .array => |xa| {
            const xb = b.array;
            for (xa[0..@min(xa.len, xb.len)], xb[0..@min(xa.len, xb.len)]) |x, y| {
                const o = valueCompare(x, y) orelse return null;
                if (o != .eq) return o;
            }
            return std.math.order(xa.len, xb.len);
        },
        .object, .set => null,
    };
}

fn typeRank(v: Value) u8 {
    return switch (v) {
        .nil => 0,
        .boolean => 1,
        .number => 2,
        .string => 3,
        .array => 4,
        .object => 5,
        .set => 6,
    };
}

// Tests.

const testing = std.testing;

test "parse: scalars" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expect((try parse(a, "true")) == .boolean);
    try testing.expect((try parse(a, "null")) == .nil);
    try testing.expectEqual(@as(f64, 42), (try parse(a, "42")).number);
    try testing.expectEqual(@as(f64, -3.5), (try parse(a, "-3.5")).number);
}

test "fuzz: parse never crashes and never over-reads" {
    try testing.fuzz({}, fuzzParse, .{});
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    @disableInstrumentation();
    var buf: [512]u8 = undefined;
    // Weighted towards JSON punctuation and escape starters so the
    // fuzzer spends its budget inside the grammar rather than on
    // documents that die at the first byte.
    const len = smith.sliceWeightedBytes(&buf, &.{
        .rangeAtMost(u8, 0x00, 0xff, 1),
        .rangeAtMost(u8, 0x20, 0x7e, 3),
        .value(u8, '{', 6),
        .value(u8, '}', 6),
        .value(u8, '[', 6),
        .value(u8, ']', 6),
        .value(u8, '"', 8),
        .value(u8, '\\', 8),
        .value(u8, ':', 4),
        .value(u8, ',', 4),
        .rangeAtMost(u8, '0', '9', 4),
        .value(u8, 'u', 4),
        .value(u8, '-', 2),
        .value(u8, '.', 2),
        .value(u8, 'e', 2),
    });
    const src = buf[0..len];

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const v = parse(arena.allocator(), src) catch return;

    // Anything that parsed has to be walkable: strings either alias
    // `src` or live in the arena, and every child is reachable.
    walk(v);
}

fn walk(v: Value) void {
    @disableInstrumentation();
    switch (v) {
        .nil, .boolean, .number => {},
        .string => |s| for (s) |c| std.mem.doNotOptimizeAway(c),
        .array, .set => |xs| for (xs) |x| walk(x),
        .object => |members| for (members) |m| {
            for (m.key) |c| std.mem.doNotOptimizeAway(c);
            walk(m.value);
        },
    }
}

test "parse: RFC 8259 number grammar is enforced" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Accepted forms.
    try testing.expectEqual(@as(f64, 0), (try parse(a, "0")).number);
    try testing.expectEqual(@as(f64, -0.5), (try parse(a, "-0.5")).number);
    try testing.expectEqual(@as(f64, 1200), (try parse(a, "1.2e3")).number);
    try testing.expectEqual(@as(f64, 0.012), (try parse(a, "1.2E-2")).number);
    try testing.expectEqual(@as(f64, 120), (try parse(a, "1.2e+2")).number);

    // Rejected forms. Every one of these is accepted by a bare
    // `parseFloat` call, and rejected by Go / JavaScript / OPA. Which
    // error comes back depends on whether the scanner stops inside the
    // number or leaves a trailing token; the contract is only that the
    // document does not parse.
    const bad = [_][]const u8{
        "01", // leading zero
        "-01", // leading zero after sign
        "1.", // trailing decimal point
        ".5", // no integer part
        "-.5",
        "+1", // explicit plus
        "1e", // empty exponent
        "1e+", // sign but no exponent digits
        "1.2.3", // two decimal points
        "-", // sign only
        "1_000", // separators are not JSON
    };
    for (bad) |src| {
        if (parse(a, src)) |_| {
            std.debug.print("expected \"{s}\" to be rejected\n", .{src});
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "parse: number rejection also fires nested in a document" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(
        error.InvalidNumber,
        parse(arena.allocator(), "{\"amount\":007}"),
    );
}

test "lookupMember: duplicate keys resolve last-wins" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    // Go, JavaScript, and OPA all read "guest" here. If zopa read
    // "admin" a request could satisfy an admin-only policy while the
    // backend saw a guest.
    const v = try parse(arena.allocator(), "{\"role\":\"admin\",\"role\":\"guest\"}");
    try testing.expectEqualStrings("guest", lookupMember(v.object, "role").?.string);
    try testing.expect(lookupMember(v.object, "absent") == null);
}

test "lookupPath: duplicate keys resolve last-wins through nesting" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = try parse(arena.allocator(), "{\"u\":{\"r\":1},\"u\":{\"r\":2}}");
    const got = try lookupPath(root, &.{ "input", "u", "r" });
    try testing.expectEqual(@as(f64, 2), got.number);
}

test "parse: a duplicated key leaves one member holding the last value" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const v = try parse(arena.allocator(), "{\"r\":\"admin\",\"x\":1,\"r\":\"guest\"}");
    try testing.expectEqual(@as(usize, 2), v.object.len);
    try testing.expectEqualStrings("r", v.object[0].key);
    try testing.expectEqualStrings("guest", v.object[0].value.string);

    // An escaped spelling is the same key once decoded.
    const e = try parse(arena.allocator(), "{\"a\":1,\"\\u0061\":2}");
    try testing.expectEqual(@as(usize, 1), e.object.len);
    try testing.expectEqual(@as(f64, 2), e.object[0].value.number);

    // What the backend calls equal, zopa does too.
    const want = try parse(arena.allocator(), "{\"r\":\"guest\",\"x\":1}");
    try testing.expect(valueEquals(v, want));
}

test "parse: duplicate keys collapse past the scan threshold too" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var src: std.ArrayList(u8) = .empty;
    try src.append(arena.allocator(), '{');
    const n = object_scan_max * 3;
    for (0..n) |i| {
        if (i > 0) try src.append(arena.allocator(), ',');
        // Every key appears twice: k0..k(n/2-1), then again with i.
        try src.print(arena.allocator(), "\"k{d}\":{d}", .{ i % (n / 2), i });
    }
    try src.append(arena.allocator(), '}');
    const v = try parse(arena.allocator(), src.items);
    try testing.expectEqual(n / 2, v.object.len);
    for (v.object, 0..) |m, i| {
        try testing.expectEqual(@as(f64, @floatFromInt(i + n / 2)), m.value.number);
    }
}

test "parse: a wide object treats an escaped spelling as the same key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var src: std.ArrayList(u8) = .empty;
    try src.appendSlice(arena.allocator(), "{\"a\":0");
    for (0..object_scan_max + 4) |i| try src.print(arena.allocator(), ",\"f{d}\":0", .{i});
    // Past the scan threshold, so this goes through `dedupeWide`, which
    // compares keys after `parseString` has decoded them.
    try src.appendSlice(arena.allocator(), ",\"\\u0061\":1}");
    const v = try parse(arena.allocator(), src.items);
    try testing.expectEqual(object_scan_max + 5, v.object.len);
    try testing.expectEqualStrings("a", v.object[0].key);
    try testing.expectEqual(@as(f64, 1), v.object[0].value.number);
}

test "parse: running out of memory while deduping a wide object is an error" {
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(testing.allocator);
    try src.append(testing.allocator, '{');
    for (0..object_scan_max * 2) |i| {
        if (i > 0) try src.append(testing.allocator, ',');
        try src.print(testing.allocator, "\"k{d}\":0", .{i % object_scan_max});
    }
    try src.append(testing.allocator, '}');

    // Fail every allocation from the first one onward until the parse
    // gets through, so the dedupe's own allocations are among those hit.
    var fail_index: usize = 0;
    while (true) : (fail_index += 1) {
        var arena = std.heap.ArenaAllocator.init(testing.allocator);
        defer arena.deinit();
        var failing = std.testing.FailingAllocator.init(arena.allocator(), .{ .fail_index = fail_index });
        if (parse(failing.allocator(), src.items)) |v| {
            try testing.expectEqual(object_scan_max, v.object.len);
            break;
        } else |err| try testing.expectEqual(error.OutOfMemory, err);
    }
}

test "parse: object and nested array" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const v = try parse(arena.allocator(), "{\"a\":[1,2,{\"b\":\"x\"}]}");
    try testing.expect(v == .object);
    try testing.expectEqual(@as(usize, 1), v.object.len);
    const inner = v.object[0].value;
    try testing.expect(inner == .array);
    try testing.expectEqual(@as(usize, 3), inner.array.len);
    try testing.expectEqual(@as(f64, 1), inner.array[0].number);
    try testing.expect(inner.array[2] == .object);
}

test "parse: string without escapes aliases source" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const src: []const u8 = "\"hello\"";
    const v = try parse(arena.allocator(), src);
    try testing.expect(v == .string);
    try testing.expectEqualStrings("hello", v.string);
    // Aliasing: the returned slice points into src + 1.
    try testing.expectEqual(@intFromPtr(src.ptr) + 1, @intFromPtr(v.string.ptr));
}

test "parse: string with escapes decodes" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const v = try parse(arena.allocator(), "\"a\\nb\\t\\\"c\"");
    try testing.expectEqualStrings("a\nb\t\"c", v.string);
}

test "parse: surrogate pair becomes non-BMP code point" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const v = try parse(arena.allocator(), "\"\\uD834\\uDD1E\"");
    try testing.expectEqualStrings("\u{1D11E}", v.string);
}

test "parse: lone surrogate is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(error.InvalidUnicode, parse(arena.allocator(), "\"\\uDC00\""));
}

test "parse: nesting cap" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var src: std.ArrayList(u8) = .empty;
    defer src.deinit(testing.allocator);
    try src.appendNTimes(testing.allocator, '[', max_depth + 1);
    try src.append(testing.allocator, '0');
    try src.appendNTimes(testing.allocator, ']', max_depth + 1);
    try testing.expectError(error.NestingTooDeep, parse(arena.allocator(), src.items));
}

test "lookupPath: input prefix is optional" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = try parse(arena.allocator(), "{\"user\":{\"role\":\"admin\"}}");
    const a = try lookupPath(root, &.{ "input", "user", "role" });
    const b = try lookupPath(root, &.{ "user", "role" });
    try testing.expectEqualStrings("admin", a.string);
    try testing.expectEqualStrings("admin", b.string);
}

test "lookupPath: missing key" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const root = try parse(arena.allocator(), "{\"a\":1}");
    try testing.expectError(error.PathNotFound, lookupPath(root, &.{"missing"}));
}

test "valueEquals" {
    try testing.expect(valueEquals(.{ .number = 1.0 }, .{ .number = 1.0 }));
    try testing.expect(!valueEquals(.{ .number = 1.0 }, .{ .number = 2.0 }));
    try testing.expect(!valueEquals(.{ .number = 1.0 }, .{ .string = "1" }));
    try testing.expect(valueEquals(.nil, .nil));
}

test "valueCompare" {
    try testing.expectEqual(std.math.Order.lt, valueCompare(.{ .number = 1 }, .{ .number = 2 }).?);
    try testing.expectEqual(std.math.Order.eq, valueCompare(.{ .string = "a" }, .{ .string = "a" }).?);
    // Across types, OPA's rank order: number < string.
    try testing.expectEqual(std.math.Order.lt, valueCompare(.{ .number = 1 }, .{ .string = "1" }).?);
    try testing.expectEqual(std.math.Order.lt, valueCompare(.nil, .{ .boolean = false }).?);
    try testing.expectEqual(std.math.Order.lt, valueCompare(.{ .boolean = true }, .{ .number = 1 }).?);
    const a12 = [_]Value{ .{ .number = 1 }, .{ .number = 2 } };
    const a13 = [_]Value{ .{ .number = 1 }, .{ .number = 3 } };
    const a1 = [_]Value{.{ .number = 1 }};
    try testing.expectEqual(std.math.Order.lt, valueCompare(.{ .array = &a12 }, .{ .array = &a13 }).?);
    try testing.expectEqual(std.math.Order.lt, valueCompare(.{ .array = &a1 }, .{ .array = &a12 }).?);
    try testing.expectEqual(std.math.Order.gt, valueCompare(.{ .array = &a1 }, .{ .string = "z" }).?);
    // Two objects are ordered by OPA, but not here.
    try testing.expect(valueCompare(.{ .object = &.{} }, .{ .object = &.{} }) == null);
}
