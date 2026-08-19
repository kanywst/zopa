//! Everything the proxy-wasm shim does between "bytes from the host"
//! and "JSON for the evaluator": decoding the header-map
//! serialisation, and synthesising the per-phase input documents.
//!
//! It lives apart from `proxy_wasm.zig` because that file's
//! `extern "env"` declarations only resolve inside a wasm host, which
//! makes it unlinkable -- and therefore untestable -- on the host.
//! The code here has no imports from the ABI, so `zig build test-unit`
//! can hammer it directly. That matters more than the tidiness: the
//! header-map decoder parses a length-prefixed binary buffer, which is
//! the single most malformed-input-exposed surface in the module.
//!
//! Every function allocates on the caller-supplied allocator (the
//! request arena, in zopa) and borrows its inputs.

const std = @import("std");
const json = @import("json.zig");

pub const HeaderPair = struct { key: []const u8, value: []const u8 };

pub const DecodeError = error{
    InvalidHeaderMap,
    OutOfMemory,
};

/// Decode the proxy-wasm header-map serialisation:
///
/// ```text
///   u32_le N
///   (u32_le key_size, u32_le value_size) * N
///   (key, NUL, value, NUL) * N
/// ```
///
/// `buf` comes straight from the host, so every length in it is
/// treated as hostile. On wasm32 `usize` is 32 bits and the sizes are
/// u32, so each offset is built with checked arithmetic -- an
/// unchecked `p + key_size + 1` wraps to a small number and sails
/// through a naive bounds check.
pub fn decodeHeaderMap(
    allocator: std.mem.Allocator,
    buf: []const u8,
) DecodeError![]HeaderPair {
    if (buf.len == 0) return &[_]HeaderPair{};
    if (buf.len < 4) return error.InvalidHeaderMap;

    const num = std.mem.readInt(u32, buf[0..4], .little);
    if (num == 0) return &[_]HeaderPair{};

    const sizes_off: usize = 4;
    const sizes_len = std.math.mul(usize, num, 8) catch return error.InvalidHeaderMap;
    const sizes_end = std.math.add(usize, sizes_off, sizes_len) catch return error.InvalidHeaderMap;
    if (buf.len < sizes_end) return error.InvalidHeaderMap;

    const headers = try allocator.alloc(HeaderPair, num);
    var p: usize = sizes_end;
    var i: usize = 0;
    while (i < num) : (i += 1) {
        const so = sizes_off + i * 8;
        const key_size = std.mem.readInt(u32, buf[so..][0..4], .little);
        const value_size = std.mem.readInt(u32, buf[so + 4 ..][0..4], .little);

        // (key_size + 1) + (value_size + 1), guarded end-to-end.
        const kv = std.math.add(usize, key_size, value_size) catch return error.InvalidHeaderMap;
        const need = std.math.add(usize, kv, 2) catch return error.InvalidHeaderMap;
        const end = std.math.add(usize, p, need) catch return error.InvalidHeaderMap;
        if (end > buf.len) return error.InvalidHeaderMap;

        const key = try allocator.dupe(u8, buf[p .. p + key_size]);
        p += @as(usize, key_size) + 1; // skip NUL terminator
        const value = try allocator.dupe(u8, buf[p .. p + value_size]);
        p += @as(usize, value_size) + 1;
        headers[i] = .{ .key = key, .value = value };
    }

    return headers;
}

/// Build the request-phase input:
/// `{"method":..., "path":..., "headers":{...}}`.
///
/// `method` and `path` are passed in separately because Envoy on the
/// wamr runtime omits pseudo-headers from the header-map dump, so the
/// shim fetches them by name.
pub fn buildRequestInput(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    headers: []const HeaderPair,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"method\":");
    try appendJsonString(allocator, &buf, method);
    try buf.appendSlice(allocator, ",\"path\":");
    try appendJsonString(allocator, &buf, path);
    try buf.appendSlice(allocator, ",\"headers\":");
    try appendHeaderObject(allocator, &buf, headers);
    try buf.append(allocator, '}');

    return try allocator.dupe(u8, buf.items);
}

/// Build the response-phase input:
/// `{"response":{"status":<int|null>,"headers":{...}}}`.
///
/// `status_text` is the raw `:status` header. Anything that isn't a
/// plain non-negative integer becomes `null` so a policy comparing
/// against a number sees undefined rather than a coerced value.
pub fn buildResponseInput(
    allocator: std.mem.Allocator,
    status_text: []const u8,
    headers: []const HeaderPair,
) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"response\":{\"status\":");
    if (std.fmt.parseInt(u16, status_text, 10)) |status| {
        var num_buf: [8]u8 = undefined;
        try buf.appendSlice(allocator, std.fmt.bufPrint(&num_buf, "{d}", .{status}) catch unreachable);
    } else |_| {
        try buf.appendSlice(allocator, "null");
    }

    try buf.appendSlice(allocator, ",\"headers\":");
    try appendHeaderObject(allocator, &buf, headers);
    try buf.appendSlice(allocator, "}}");

    return try allocator.dupe(u8, buf.items);
}

/// Build the body-phase input:
/// `{"body":<parsed|null>,"body_raw":"...","body_truncated":<bool>}`.
///
/// The body is inlined verbatim when it parses as JSON; otherwise
/// `body` is null and the policy can still match on `body_raw` (e.g.
/// with `contains`). `body_truncated` tells a policy that the bytes it
/// is looking at are a prefix -- the shim also refuses the request
/// outright in that case when the policy reads the body, but exposing
/// the flag lets a policy make its own call.
pub fn buildBodyInput(
    allocator: std.mem.Allocator,
    body: []const u8,
    truncated: bool,
) ![]u8 {
    const parses_as_json = body.len > 0 and blk: {
        _ = json.parse(allocator, body) catch break :blk false;
        break :blk true;
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{\"body\":");
    try buf.appendSlice(allocator, if (parses_as_json) body else "null");
    try buf.appendSlice(allocator, ",\"body_raw\":");
    try appendJsonString(allocator, &buf, body);
    try buf.appendSlice(allocator, ",\"body_truncated\":");
    try buf.appendSlice(allocator, if (truncated) "true" else "false");
    try buf.append(allocator, '}');

    return try allocator.dupe(u8, buf.items);
}

/// Serialise headers as a JSON object, dropping pseudo-headers --
/// `:method`, `:path`, and `:status` are promoted to named fields by
/// the callers above, and leaving the colon-prefixed copies in would
/// give a policy two spellings of the same fact.
fn appendHeaderObject(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    headers: []const HeaderPair,
) !void {
    try buf.append(allocator, '{');
    var first = true;
    for (headers) |h| {
        if (h.key.len > 0 and h.key[0] == ':') continue;
        if (!first) try buf.append(allocator, ',');
        first = false;
        try appendJsonString(allocator, buf, h.key);
        try buf.append(allocator, ':');
        try appendJsonString(allocator, buf, h.value);
    }
    try buf.append(allocator, '}');
}

/// Append `s` as a JSON string literal. RFC 8259 requires every byte
/// below 0x20 to be escaped, so the ones without a short form get
/// `\u00XX`; without that a header carrying a raw control byte would
/// produce a document zopa itself refuses to parse.
pub fn appendJsonString(
    allocator: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    s: []const u8,
) !void {
    try buf.append(allocator, '"');
    for (s) |c| {
        switch (c) {
            '"' => try buf.appendSlice(allocator, "\\\""),
            '\\' => try buf.appendSlice(allocator, "\\\\"),
            '\n' => try buf.appendSlice(allocator, "\\n"),
            '\r' => try buf.appendSlice(allocator, "\\r"),
            '\t' => try buf.appendSlice(allocator, "\\t"),
            0x08 => try buf.appendSlice(allocator, "\\b"),
            0x0c => try buf.appendSlice(allocator, "\\f"),
            else => {
                if (c < 0x20) {
                    var hex_buf: [6]u8 = undefined;
                    const hex = std.fmt.bufPrint(&hex_buf, "\\u{x:0>4}", .{c}) catch unreachable;
                    try buf.appendSlice(allocator, hex);
                } else {
                    try buf.append(allocator, c);
                }
            },
        }
    }
    try buf.append(allocator, '"');
}

// Tests.

const testing = std.testing;

/// Encode a header map the way a proxy-wasm host would, so the
/// decoder can be exercised against well-formed input before the
/// malformed cases below start bending it.
fn encodeHeaderMap(allocator: std.mem.Allocator, pairs: []const HeaderPair) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendNTimes(allocator, 0, 4);
    std.mem.writeInt(u32, buf.items[0..4], @intCast(pairs.len), .little);

    for (pairs) |p| {
        var sizes: [8]u8 = undefined;
        std.mem.writeInt(u32, sizes[0..4], @intCast(p.key.len), .little);
        std.mem.writeInt(u32, sizes[4..8], @intCast(p.value.len), .little);
        try buf.appendSlice(allocator, &sizes);
    }
    for (pairs) |p| {
        try buf.appendSlice(allocator, p.key);
        try buf.append(allocator, 0);
        try buf.appendSlice(allocator, p.value);
        try buf.append(allocator, 0);
    }

    return buf.toOwnedSlice(allocator);
}

test "decodeHeaderMap: round-trips a well-formed map" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const want = [_]HeaderPair{
        .{ .key = ":method", .value = "GET" },
        .{ .key = "x-user", .value = "kt" },
        .{ .key = "empty", .value = "" },
    };
    const encoded = try encodeHeaderMap(a, &want);
    const got = try decodeHeaderMap(a, encoded);

    try testing.expectEqual(want.len, got.len);
    for (want, got) |w, g| {
        try testing.expectEqualStrings(w.key, g.key);
        try testing.expectEqualStrings(w.value, g.value);
    }
}

test "decodeHeaderMap: empty and zero-count buffers yield no headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    try testing.expectEqual(@as(usize, 0), (try decodeHeaderMap(a, &[_]u8{})).len);
    try testing.expectEqual(@as(usize, 0), (try decodeHeaderMap(a, &[_]u8{ 0, 0, 0, 0 })).len);
}

test "decodeHeaderMap: malformed buffers are rejected, never read past the end" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const cases = [_][]const u8{
        // Truncated count.
        &[_]u8{ 1, 0 },
        // Claims one entry, no size table.
        &[_]u8{ 1, 0, 0, 0 },
        // Claims one entry, size table present, payload missing.
        &[_]u8{ 1, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0 },
        // key_size = 0xFFFFFFFF: `p + key_size + 1` wraps on wasm32.
        &[_]u8{ 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 'a', 0, 'b', 0 },
        // value_size = 0xFFFFFFFF, same wrap from the other side.
        &[_]u8{ 1, 0, 0, 0, 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 'a', 0, 'b', 0 },
        // Both maxed: key_size + value_size itself overflows.
        &[_]u8{ 1, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 'a', 0 },
        // Count huge enough that count * 8 overflows a 32-bit usize.
        &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0 },
    };

    for (cases, 0..) |buf, i| {
        _ = decodeHeaderMap(a, buf) catch continue;
        std.debug.print("case {d} should have been rejected\n", .{i});
        return error.TestUnexpectedResult;
    }
}

test "decodeHeaderMap: last entry's trailing NUL may be the final byte" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Exactly sized: 4 + 8 + ("a" NUL "b" NUL) = 16 bytes.
    const buf = [_]u8{ 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 'a', 0, 'b', 0 };
    const got = try decodeHeaderMap(a, &buf);
    try testing.expectEqual(@as(usize, 1), got.len);
    try testing.expectEqualStrings("a", got[0].key);
    try testing.expectEqualStrings("b", got[0].value);
}

test "fuzz: decodeHeaderMap survives arbitrary host buffers" {
    try testing.fuzz({}, fuzzDecodeHeaderMap, .{});
}

fn fuzzDecodeHeaderMap(_: void, smith: *std.testing.Smith) !void {
    @disableInstrumentation();
    var buf: [1024]u8 = undefined;
    // Bias towards small integers and 0xFF runs: the interesting
    // inputs are length fields that are either just past the end of
    // the buffer or large enough to wrap 32-bit arithmetic.
    const len = smith.sliceWeightedBytes(&buf, &.{
        .rangeAtMost(u8, 0x00, 0xff, 1),
        .value(u8, 0x00, 8),
        .value(u8, 0xff, 8),
        .rangeAtMost(u8, 0x01, 0x10, 4),
    });

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const headers = decodeHeaderMap(arena.allocator(), buf[0..len]) catch return;

    // Anything that decoded must be internally consistent: every slice
    // has to point inside the arena and be readable end to end.
    for (headers) |h| {
        std.mem.doNotOptimizeAway(h.key.len);
        std.mem.doNotOptimizeAway(h.value.len);
        for (h.key) |c| std.mem.doNotOptimizeAway(c);
        for (h.value) |c| std.mem.doNotOptimizeAway(c);
    }
}

test "fuzz: header values always round-trip through the synthesised JSON" {
    try testing.fuzz({}, fuzzHeaderRoundTrip, .{});
}

fn fuzzHeaderRoundTrip(_: void, smith: *std.testing.Smith) !void {
    @disableInstrumentation();
    var value_buf: [256]u8 = undefined;
    const len = smith.sliceWeightedBytes(&value_buf, &.{
        .rangeAtMost(u8, 0x00, 0xff, 1),
        .rangeAtMost(u8, 0x20, 0x7e, 4),
        .value(u8, '"', 6),
        .value(u8, '\\', 6),
        .rangeAtMost(u8, 0x00, 0x1f, 4),
    });
    const value = value_buf[0..len];

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const headers = [_]HeaderPair{.{ .key = "x-fuzz", .value = value }};
    const doc = try buildRequestInput(a, "GET", "/", &headers);

    // Property: whatever bytes went in, the document parses and the
    // header comes back byte-identical. A header that could break out
    // of its string literal is a policy-input injection.
    const parsed = try json.parse(a, doc);
    const hs = json.lookupMember(parsed.object, "headers").?;
    try testing.expectEqual(@as(usize, 1), hs.object.len);
    try testing.expectEqualStrings(value, json.lookupMember(hs.object, "x-fuzz").?.string);
}

test "buildRequestInput: output parses and drops pseudo-headers" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const headers = [_]HeaderPair{
        .{ .key = ":method", .value = "GET" },
        .{ .key = "x-user", .value = "kt" },
    };
    const doc = try buildRequestInput(a, "GET", "/admin", &headers);
    const v = try json.parse(a, doc);

    try testing.expectEqualStrings("GET", json.lookupMember(v.object, "method").?.string);
    try testing.expectEqualStrings("/admin", json.lookupMember(v.object, "path").?.string);
    const hs = json.lookupMember(v.object, "headers").?;
    try testing.expectEqual(@as(usize, 1), hs.object.len);
    try testing.expectEqualStrings("kt", json.lookupMember(hs.object, "x-user").?.string);
}

test "buildRequestInput: header bytes that would break the JSON are escaped" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A header value that tries to close the string and inject a
    // sibling key, plus a raw control byte and a backslash.
    const hostile = "\",\"role\":\"admin\x01\\";
    const headers = [_]HeaderPair{.{ .key = "x-evil", .value = hostile }};
    const doc = try buildRequestInput(a, "GET", "/", &headers);
    const v = try json.parse(a, doc);

    const hs = json.lookupMember(v.object, "headers").?;
    try testing.expectEqual(@as(usize, 1), hs.object.len);
    try testing.expectEqualStrings(hostile, json.lookupMember(hs.object, "x-evil").?.string);
    // The injected key must not exist as a real member anywhere.
    try testing.expect(json.lookupMember(hs.object, "role") == null);
    try testing.expect(json.lookupMember(v.object, "role") == null);
}

test "buildRequestInput: an empty header map still produces a valid document" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const doc = try buildRequestInput(a, "", "", &[_]HeaderPair{});
    const v = try json.parse(a, doc);
    try testing.expectEqual(@as(usize, 0), json.lookupMember(v.object, "headers").?.object.len);
}

test "buildResponseInput: status parses as a number, junk becomes null" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const ok = try json.parse(a, try buildResponseInput(a, "503", &[_]HeaderPair{}));
    const resp = json.lookupMember(ok.object, "response").?;
    try testing.expectEqual(@as(f64, 503), json.lookupMember(resp.object, "status").?.number);

    for ([_][]const u8{ "", "abc", "-1", "99999", "20 0" }) |junk| {
        const v = try json.parse(a, try buildResponseInput(a, junk, &[_]HeaderPair{}));
        const r = json.lookupMember(v.object, "response").?;
        try testing.expect(json.lookupMember(r.object, "status").? == .nil);
    }
}

test "buildBodyInput: JSON body is inlined, garbage falls back to body_raw" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const good = try json.parse(a, try buildBodyInput(a, "{\"amount\":5000}", false));
    const body = json.lookupMember(good.object, "body").?;
    try testing.expectEqual(@as(f64, 5000), json.lookupMember(body.object, "amount").?.number);
    try testing.expect(!json.lookupMember(good.object, "body_truncated").?.boolean);

    const bad = try json.parse(a, try buildBodyInput(a, "not json\"", false));
    try testing.expect(json.lookupMember(bad.object, "body").? == .nil);
    try testing.expectEqualStrings("not json\"", json.lookupMember(bad.object, "body_raw").?.string);
}

test "buildBodyInput: an empty body is null, not a parse attempt" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const v = try json.parse(a, try buildBodyInput(a, "", false));
    try testing.expect(json.lookupMember(v.object, "body").? == .nil);
    try testing.expectEqualStrings("", json.lookupMember(v.object, "body_raw").?.string);
}

test "buildBodyInput: truncation is reported to the policy" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const v = try json.parse(a, try buildBodyInput(a, "{\"a\":1", true));
    try testing.expect(json.lookupMember(v.object, "body_truncated").?.boolean);
    // A truncated JSON body doesn't parse, so `body` is null rather
    // than a half-built object.
    try testing.expect(json.lookupMember(v.object, "body").? == .nil);
}
