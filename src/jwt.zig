const std = @import("std");

const meta = @import("meta.zig");

const Allocator = std.mem.Allocator;

const Base64URL = std.base64.url_safe_no_pad;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;

pub const Key = union(enum) {
    hs256: []const u8,
    hs384: []const u8,
    hs512: []const u8,
    none,

    fn algString(key: *const Key) []const u8 {
        return switch (key.*) {
            .hs256 => "HS256",
            .hs384 => "HS384",
            .hs512 => "HS512",
            .none => "none",
        };
    }
};

pub const Header = struct {
    typ: []const u8,
    alg: []const u8,
};

pub fn TokenData(comptime T: type) type {
    return struct {
        claims: T,
        arena: *std.heap.ArenaAllocator,

        const Self = @This();

        fn deinit(self: *Self) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }
    };
}

fn signMessage(allocator: Allocator, message: []const u8, key: Key) ![]u8 {
    switch (key) {
        .hs256 => |k| {
            var digest: [HmacSha256.mac_length]u8 = undefined;
            HmacSha256.create(&digest, message, k);
            return allocator.dupe(u8, &digest);
        },
        .hs384 => |k| {
            var digest: [HmacSha384.mac_length]u8 = undefined;
            HmacSha384.create(&digest, message, k);
            return allocator.dupe(u8, &digest);
        },
        .hs512 => |k| {
            var digest: [HmacSha512.mac_length]u8 = undefined;
            HmacSha512.create(&digest, message, k);
            return allocator.dupe(u8, &digest);
        },
        .none => return allocator.dupe(u8, ""),
    }
}

fn base64URLEncode(allocator: Allocator, source: []const u8) ![]u8 {
    var base64 = std.ArrayList(u8).init(allocator);
    try Base64URL.Encoder.encodeWriter(base64.writer(), source);
    return base64.toOwnedSlice();
}

fn base64URLDecode(allocator: Allocator, base64: []const u8) ![]u8 {
    const size = try Base64URL.Decoder.calcSizeForSlice(base64);
    var decoded = try std.ArrayList(u8).initCapacity(allocator, size);
    decoded.expandToCapacity();

    try Base64URL.Decoder.decode(decoded.items, base64);
    return decoded.toOwnedSlice();
}

pub fn encode(allocator: Allocator, claims: anytype, key: Key) ![]u8 {
    comptime meta.validateClaimTypes(@TypeOf(claims)) catch |e| {
        meta.claimCompileError(e);
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const aa = arena.allocator();

    const claims_json = try std.json.stringifyAlloc(aa, claims, .{});
    const claims_base64 = try base64URLEncode(aa, claims_json);

    const header = .{
        .alg = key.algString(),
        .typ = "JWT",
    };

    const header_json = try std.json.stringifyAlloc(aa, header, .{});
    const header_base64 = try base64URLEncode(aa, header_json);

    const message = try std.fmt.allocPrint(aa, "{s}.{s}", .{
        header_base64,
        claims_base64,
    });

    const sig = try signMessage(aa, message, key);
    const sig_base64 = try base64URLEncode(aa, sig);

    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ message, sig_base64 });
}

pub fn decode(comptime T: type, allocator: Allocator, token: []const u8, key: Key) !TokenData(T) {
    const header_end = std.mem.indexOfScalar(
        u8,
        token,
        '.',
    ) orelse return error.InvalidFormat;
    const signature_start = std.mem.indexOfScalarPos(
        u8,
        token,
        header_end + 1,
        '.',
    ) orelse return error.InvalidFormat;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const aa = arena.allocator();

    const header_segment = token[0..header_end];
    const claims_segment = token[header_end + 1 .. signature_start];
    const sig_segment = token[signature_start + 1 ..];
    _ = sig_segment;

    const header = try std.json.parseFromSlice(
        Header,
        allocator,
        try base64URLDecode(aa, header_segment),
        .{},
    );
    defer header.deinit();

    var data_arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(data_arena);

    data_arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer data_arena.deinit();

    const data: TokenData(T) = .{
        .arena = data_arena,
        .claims = try std.json.parseFromSliceLeaky(
            T,
            data_arena.allocator(),
            try base64URLDecode(aa, claims_segment),
            .{ .allocate = .alloc_always },
        ),
    };

    _ = key;
    return data;
}

test "encode: token contains base64url encoded header with alg" {
    const allocator = std.testing.allocator;

    const token = try encode(allocator, .{}, .{ .hs256 = "foobar" });
    defer allocator.free(token);

    const header_end = std.mem.indexOfScalar(u8, token, '.') orelse @panic("no dots");
    const header_segment: []const u8 = token[0..header_end];

    const decoded_header = try base64URLDecode(allocator, header_segment);
    defer allocator.free(decoded_header);

    var parsed_headers = try std.json.parseFromSlice(Header, allocator, decoded_header, .{});
    defer parsed_headers.deinit();

    try std.testing.expectEqualSlices(u8, "JWT", parsed_headers.value.typ);
    try std.testing.expectEqualSlices(u8, "HS256", parsed_headers.value.alg);
}

test "encode: token contains base64url encoded claims" {
    const allocator = std.testing.allocator;

    const iat = std.time.timestamp();
    const exp: i64 = iat + (15 * std.time.s_per_min);

    const Claims = struct {
        iat: i64,
        exp: i64,
        sub: []const u8,
    };

    const claims = .{
        .iat = iat,
        .exp = exp,
        .sub = "1",
    };

    const token = try encode(allocator, claims, .{ .hs256 = "your-256-bit-secret" });
    defer allocator.free(token);

    const claims_start = std.mem.indexOfScalar(u8, token, '.') orelse @panic("no dots");
    const claims_end = std.mem.lastIndexOfScalar(u8, token, '.') orelse @panic("no dots");

    try std.testing.expect(claims_start != claims_end);

    const claim_segment: []const u8 = token[claims_start + 1 .. claims_end];

    const decoded_claims = try base64URLDecode(allocator, claim_segment);
    defer allocator.free(decoded_claims);

    var parsed_claims = try std.json.parseFromSlice(Claims, allocator, decoded_claims, .{});
    defer parsed_claims.deinit();

    try std.testing.expectEqual(claims.iat, parsed_claims.value.iat);
    try std.testing.expectEqual(claims.exp, parsed_claims.value.exp);
    try std.testing.expectEqualSlices(u8, claims.sub, parsed_claims.value.sub);
}

test "encode: token contains base64url encoded signature" {
    const allocator = std.testing.allocator;

    const token = try encode(allocator, .{}, .{ .hs256 = "your-256-bit-secret" });
    defer allocator.free(token);

    const end_idx = std.mem.lastIndexOfScalar(u8, token, '.') orelse @panic("no dots");

    const signature_segment: []const u8 = token[end_idx + 1 ..];

    const signature = try base64URLDecode(allocator, signature_segment);
    defer allocator.free(signature);
}

test "encode: token contains empty signature for none alg" {
    const allocator = std.testing.allocator;

    const token = try encode(allocator, .{}, .none);
    defer allocator.free(token);

    const end_idx = std.mem.lastIndexOfScalar(u8, token, '.') orelse @panic("no dots");

    const signature_segment: []const u8 = token[end_idx + 1 ..];

    try std.testing.expectEqual(0, signature_segment.len);
}

test "decode: returns token of correct type" {
    const allocator = std.testing.allocator;

    const Claims = struct {
        iat: i64,
        exp: i64,
        sub: []const u8,
    };

    const iat = std.time.timestamp();
    const exp: i64 = iat + (15 * std.time.s_per_min);

    const claims = .{
        .iat = iat,
        .exp = exp,
        .sub = "1",
    };

    const token = try encode(allocator, claims, .{
        .hs256 = "your-256-bit-secret",
    });
    defer allocator.free(token);

    var data = try decode(Claims, allocator, token, .{
        .hs256 = "your-256-bit-secret",
    });
    defer data.deinit();

    try std.testing.expectEqual(claims.iat, data.claims.iat);
    try std.testing.expectEqual(claims.exp, data.claims.exp);
    try std.testing.expectEqualSlices(u8, claims.sub, data.claims.sub);
}
