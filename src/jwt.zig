const std = @import("std");

const meta = @import("meta.zig");
const util = @import("util.zig");

const Allocator = std.mem.Allocator;

const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;

pub const EncodingError = util.EncodingError;

/// The signing key for a JSON Web Token.
///
/// NOTE: Currently only supports the three HMAC signing
/// algorithms or `none`.
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

const Header = struct {
    typ: []const u8,
    alg: []const u8,
};

/// A handle for the memory allocated for the claim type `T`.
/// A developer *must* call `deinit()` on the `TokenData`
/// in order to release the memory allocated for the claim.
pub fn TokenData(comptime T: type) type {
    return struct {
        claims: T,
        arena: *std.heap.ArenaAllocator,

        const Self = @This();

        fn init(allocator: Allocator, source: []const u8) DecodingError!Self {
            var arena = try allocator.create(std.heap.ArenaAllocator);
            errdefer allocator.destroy(arena);

            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();

            const decoded_claims = try util.base64URLDecode(allocator, source);
            defer allocator.free(decoded_claims);

            return .{
                .arena = arena,
                .claims = try std.json.parseFromSliceLeaky(
                    T,
                    arena.allocator(),
                    decoded_claims,
                    .{ .allocate = .alloc_always },
                ),
            };
        }

        pub fn deinit(self: *Self) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }
    };
}

fn signMessage(allocator: Allocator, message: []const u8, key: Key) Allocator.Error![]u8 {
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

/// Encodes `claims` into a JWT using the algorithm for the given `key`.
///
/// The following standard claims are supported and checked for type correctness
/// at compile time if present in the type of `claims`:
///
/// * `iss`, `sub`, `jti`: `[]u8`, `[]const u8`, or coercable to one of the former.
/// * `iat`, `exp`, `nbf`: Any integer type that can represent the number of seconds
/// since the unix timestamp (UTC 1970-01-01). Recommended: `i64`.
///
/// Returns an error if `claims` could not be serialized, or if base64 encoding
/// fails.
pub fn encode(allocator: Allocator, claims: anytype, key: Key) EncodingError![]u8 {
    _ = comptime meta.validateClaimTypes(@TypeOf(claims)) catch |e| {
        meta.claimCompileError(e);
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const aa = arena.allocator();

    const claims_json = try std.json.stringifyAlloc(aa, claims, .{});
    const claims_base64 = try util.base64URLEncode(aa, claims_json);

    const header = .{
        .alg = key.algString(),
        .typ = "JWT",
    };

    const header_json = try std.json.stringifyAlloc(aa, header, .{});
    const header_base64 = try util.base64URLEncode(aa, header_json);

    const message = try std.fmt.allocPrint(aa, "{s}.{s}", .{
        header_base64,
        claims_base64,
    });

    const sig = try signMessage(aa, message, key);
    const sig_base64 = try util.base64URLEncode(aa, sig);

    return std.fmt.allocPrint(allocator, "{s}.{s}", .{ message, sig_base64 });
}

pub const ValidationError = error{
    InvalidFormat,
    InvalidSignature,
    Expired,
    TooEarly,
};

pub const DecodingError = ValidationError || EncodingError || std.json.ParseError(std.json.Scanner);

/// Decodes the given `token` into a claims of type `T`, verifying standard claims
/// and ensuring that the `token`'s signature matches the signature we generate
/// with `key`.
///
/// Returns a handle that manages the memory of the parsed `T`.
pub fn decode(comptime T: type, allocator: Allocator, token: []const u8, key: Key) DecodingError!TokenData(T) {
    const claim_info = comptime meta.validateClaimTypes(T) catch |e| {
        meta.claimCompileError(e);
    };

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const aa = arena.allocator();

    const segments = try util.splitToken(token);

    const token_signature = try util.base64URLDecode(aa, segments.signature);
    const our_signature = try signMessage(aa, segments.message, key);

    if (!std.mem.eql(u8, token_signature, our_signature)) {
        return error.InvalidSignature;
    }

    const header = try util.base64URLDecode(aa, segments.header);
    // We want to ensure that the header isn't malformed, but we don't otherwise need it.
    _ = try std.json.parseFromSliceLeaky(Header, aa, header, .{});

    var data = try TokenData(T).init(allocator, segments.claims);
    errdefer data.deinit();

    const now = std.time.timestamp();

    if (claim_info.has_exp and now > data.claims.exp) {
        return error.Expired;
    }

    if (claim_info.has_nbf and now < data.claims.nbf) {
        return error.TooEarly;
    }

    return data;
}

test "encode: token contains base64url encoded header with alg" {
    const allocator = std.testing.allocator;

    const token = try encode(allocator, .{}, .{ .hs256 = "foobar" });
    defer allocator.free(token);

    const header_end = std.mem.indexOfScalar(u8, token, '.') orelse @panic("no dots");
    const header_segment: []const u8 = token[0..header_end];

    const decoded_header = try util.base64URLDecode(allocator, header_segment);
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

    const decoded_claims = try util.base64URLDecode(allocator, claim_segment);
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

    const signature = try util.base64URLDecode(allocator, signature_segment);
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

    const secret = "your-256-bit-secret";
    const token = try encode(allocator, claims, .{ .hs256 = secret });
    defer allocator.free(token);

    var data = try decode(Claims, allocator, token, .{
        .hs256 = secret,
    });
    defer data.deinit();

    try std.testing.expectEqual(claims.iat, data.claims.iat);
    try std.testing.expectEqual(claims.exp, data.claims.exp);
    try std.testing.expectEqualSlices(u8, claims.sub, data.claims.sub);
}

test "decode: returns with non-standard claims" {
    const allocator = std.testing.allocator;

    const Claims = struct {
        name: []const u8,
    };

    const claims = .{ .name = "Foobar" };

    const secret = "my-256-bit-secret";
    const token = try encode(allocator, claims, .{
        .hs256 = secret,
    });
    defer allocator.free(token);

    var data = try decode(Claims, allocator, token, .{
        .hs256 = secret,
    });
    defer data.deinit();

    try std.testing.expectEqualSlices(u8, claims.name, data.claims.name);
}

test "decode: returns error if signature is invalid" {
    const allocator = std.testing.allocator;

    const Claims = struct {
        sub: []const u8,
    };

    const claims = .{ .sub = "foo" };

    const token = try encode(allocator, claims, .{
        .hs256 = "my-256-bit-token",
    });
    defer allocator.free(token);

    try std.testing.expectError(error.InvalidSignature, decode(Claims, allocator, token, .{
        .hs256 = "hackers-256-bit-token",
    }));
}

test "decode: returns error if token is expired" {
    const allocator = std.testing.allocator;

    const Claims = struct {
        iat: i64,
        exp: i64,
    };

    const now = std.time.timestamp();
    const exp = now - (std.time.s_per_min * 15);
    const iat = exp - (std.time.s_per_min * 30);

    const claims = .{
        .iat = iat,
        .exp = exp,
    };

    const secret = "my-256-bit-secret";
    const token = try encode(allocator, claims, .{
        .hs256 = secret,
    });
    defer allocator.free(token);

    try std.testing.expectError(error.Expired, decode(Claims, allocator, token, .{
        .hs256 = secret,
    }));
}

test "decode: returns error if before nbf" {
    const allocator = std.testing.allocator;

    const Claims = struct {
        nbf: i64,
    };

    const now = std.time.timestamp();
    const nbf = now + (std.time.s_per_min * 15);

    const claims = .{
        .nbf = nbf,
    };

    const secret = "my-256-bit-secret";
    const token = try encode(allocator, claims, .{
        .hs256 = secret,
    });
    defer allocator.free(token);

    try std.testing.expectError(error.TooEarly, decode(Claims, allocator, token, .{
        .hs256 = secret,
    }));
}
