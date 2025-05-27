//! Functions for encoding and decoding JSON Web Tokens ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519)).
//!
//! ## Overview
//!
//! `jwt.zig` provides a simple, flexible, and type-safe implementation of the JSON Web Token
//! specification. Developers can create custom claims stucts that `jwt.zig` will encode into
//! and decode from compact JWS tokens.
//!
//! ### Claims
//!
//! To encode or decode a token, you must provide a set of claims. Developers can use
//! any struct that can be serialized and deserialized from JSON for this. Typically
//! a claims struct will provide at least one of the standard claims described in
//! [RFC7519 Section 4.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1), but
//! none of those claims are mandatory.
//!
//! The following standard claims are supported and checked for type correctness
//! at compile time if the provided struct has these fields:
//!
//! * `iss`, `sub`, `jti`: `[]u8`, `[]const u8`, or coercable to one of the former.
//! * `iat`, `exp`, `nbf`: Any integer type that can represent the number of seconds
//! since the unix timestamp (UTC 1970-01-01). Recommended: `i64`.
//!
//! ```zig
//! const Claims = struct {
//!     iat: i64,
//!     exp: i64,
//!     sub: []const u8,
//!     // non-standard claim
//!     name: []const u8,
//! };
//! ```
//!
//! ### Keys
//!
//! `jwt.zig` currently only supports the three HMAC signing algorithms or `none` as signing
//! algorithms. Developers should store their secret keys in a secure location and load them
//! dynamically. Keys should **never** be stored in source code or committed to source control.
//!
//! ```zig
//! const secret = try std.process.getEnvVarOwned(allocator, "JWT_SECRET");
//! defer allocator.free(secret);
//!
//! const key: jwt.Key = .{
//!     .hs256 = secret,
//! };
//! ```
//!
//! ### Encoding
//!
//! Once a developer has claims and a key, they can encode their claims struct into a token
//! with the `encode()` function. It returns an allocated byte string that the caller is
//! responsible for freeing.
//!
//! Calling `encode()` triggers compile-time checks to ensure the given claims have the right
//! structure.
//!
//! ```zig
//! const token = try jwt.encode(allocator, claims, key);
//! ```
//!
//! ### Decoding
//!
//! To validate a token, you call `decode()`, which will return a handle to the
//! decoded claims. The key given to `decode()` must be the same as the key
//! given to `encode()`, otherwise decoding will fail.
//!
//! If the standard claims `exp` and `nbf` are present, they will be checked against
//! the current time for validity.
//!
//! The caller *must* call `deinit()` on the returned item to release
//! the allocated memory.
//!
//! ```zig
//! const data = try jwt.decode(Claims, allocator, token, key);
//! defer data.deinit();
//! ```
//!
//! ## References
//!
//! * JWT Website ([jwt.io](https://jwt.io/))
//! * JSON Web Signatures ([RFC7515](https://www.rfc-editor.org/rfc/rfc7515))
//! * JSON Web Algorithms ([RFC7518](https://www.rfc-editor.org/rfc/rfc7518))
//! * JSON Web Tokens ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519))
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
/// NOTE: Currently only supports the three HMAC signing algorithms or `none`.
pub const Key = union(enum) {
    /// For maximum security this should be a signing key at least 256 bits (32 bytes) long.
    hs256: []const u8,
    /// For maximum security this should be a signing key at least 384 bits (48 bytes) long.
    hs384: []const u8,
    /// For maximum security this should be a signing key at least 512 bits (64 bytes) long.
    hs512: []const u8,
    /// **WARNING**: Using tokens without a signature is not recommended.
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
        /// The decoded claims. Developers may process custom claims with application-specific logic.
        claims: T,
        /// The arena allocator holding the memory for `claims`. **DO NOT USE DIRECTLY**.
        arena: *std.heap.ArenaAllocator,

        const Self = @This();

        fn init(allocator: Allocator, source: []const u8) DecodingError!Self {
            var arena = try allocator.create(std.heap.ArenaAllocator);
            errdefer allocator.destroy(arena);

            arena.* = std.heap.ArenaAllocator.init(allocator);
            errdefer arena.deinit();

            const claims = try std.json.parseFromSliceLeaky(T, arena.allocator(), source, .{
                .allocate = .alloc_always,
            });

            return .{
                .arena = arena,
                .claims = claims,
            };
        }

        /// Releases the memory allocated for `claims`.
        pub fn deinit(self: *Self) void {
            const allocator = self.arena.child_allocator;
            self.arena.deinit();
            allocator.destroy(self.arena);
        }
    };
}

fn hmacSign(
    comptime Method: type,
    allocator: Allocator,
    message: []const u8,
    secret: []const u8,
) Allocator.Error![]u8 {
    var digest: [Method.mac_length]u8 = undefined;
    Method.create(&digest, message, secret);
    return allocator.dupe(u8, &digest);
}

fn signMessage(allocator: Allocator, message: []const u8, key: Key) Allocator.Error![]u8 {
    switch (key) {
        .hs256 => |k| {
            return hmacSign(HmacSha256, allocator, message, k);
        },
        .hs384 => |k| {
            return hmacSign(HmacSha384, allocator, message, k);
        },
        .hs512 => |k| {
            return hmacSign(HmacSha512, allocator, message, k);
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
    TokenFormatInvalid,
    TokenSignatureInvalid,
    TokenExpired,
    TokenTooEarly,
    TokenCustomValidatorFailed,
};

pub const DecodingError = ValidationError || EncodingError || std.json.ParseError(std.json.Scanner);

/// Options for decoding a token.
pub fn DecodeOpts(comptime T: type) type {
    return struct {
        /// A function that the user can use to check their
        /// custom claims after the standard claims are validated.
        validator: ?fn (claims: *T) anyerror!void = null,
        /// The amount of seconds that the current time is allowed
        /// to deviate from the standard claims `nbf` and `exp`.
        leeway_seconds: i64 = 60,
    };
}

/// Decodes the given `token` into a object of type `T`, verifying standard claims
/// and ensuring that the `token`'s signature matches the signature we generate
/// with `key`.
///
/// Returns a handle that manages the memory of the parsed `T`, or an error if…
///
/// * …signature validation fails;
/// * …standard claims `exp` and `nbf` are present and validation fails;
/// * …base64url decoding fails;
/// * …memory allocation fails.
///
/// The caller *must* call `deinit()` on the returned item to release the allocated
/// memory.
pub fn decode(comptime T: type, allocator: Allocator, token: []const u8, key: Key) DecodingError!TokenData(T) {
    return decodeOpts(T, allocator, token, key, .{});
}

/// Same as `decode()` but with the ability to provide specific options
/// such as the leeway for time checks and a custom validation function.
///
/// The caller *must* call `deinit()` on the returned item to release the allocated
/// memory.
pub fn decodeOpts(
    comptime T: type,
    allocator: Allocator,
    token: []const u8,
    key: Key,
    opts: DecodeOpts(T),
) DecodingError!TokenData(T) {
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
        return error.TokenSignatureInvalid;
    }

    const header = try util.base64URLDecode(aa, segments.header);
    // We want to ensure that the header isn't malformed, but we don't otherwise need it.
    _ = try std.json.parseFromSliceLeaky(Header, aa, header, .{});

    const claims = try util.base64URLDecode(aa, segments.claims);
    var data = try TokenData(T).init(allocator, claims);
    errdefer data.deinit();

    const now = std.time.timestamp();

    if (claim_info.has_exp and (now - opts.leeway_seconds) > data.claims.exp) {
        return error.TokenExpired;
    }

    if (claim_info.has_nbf and (now + opts.leeway_seconds) < data.claims.nbf) {
        return error.TokenTooEarly;
    }

    if (opts.validator) |validator| {
        validator(&data.claims) catch return error.TokenCustomValidatorFailed;
    }

    return data;
}

const jwt = @This();

test encode {
    const allocator = std.testing.allocator;

    const Claims = struct {
        iat: i64,
        exp: i64,
        sub: []const u8,
        name: []const u8,
    };

    const now = std.time.timestamp();
    // We want this token to expire in 15 minutes.
    const exp = now + (15 * std.time.s_per_min);

    const claims: Claims = .{
        .iat = now,
        .exp = exp,
        .sub = "1",
        .name = "BrainBlasted",
    };

    // In a real application, this should not be stored in the source
    // code and should instead be loaded from the environment (via an
    // environment variable or some file on the developer's machine).
    const secret = "your-256-bit-secret";
    const token = try jwt.encode(allocator, claims, .{
        .hs256 = secret,
    });
    defer allocator.free(token);

    // Store token or send it to the user
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

test decode {
    const allocator = std.testing.allocator;

    const Claims = struct {
        iat: i64,
        exp: i64,
        sub: []const u8,
        name: []const u8,
    };

    const iat = std.time.timestamp();
    const exp: i64 = iat + (15 * std.time.s_per_min);

    const claims = .{
        .iat = iat,
        .exp = exp,
        .sub = "1",
        .name = "BrainBlasted",
    };

    const secret = "your-256-bit-secret";
    const token = try jwt.encode(allocator, claims, .{ .hs256 = secret });
    defer allocator.free(token);

    // A token must be decoded with the same secret and algorithm it was decoded with.
    var data = try jwt.decode(Claims, allocator, token, .{
        .hs256 = secret,
    });
    defer data.deinit();

    try std.testing.expectEqual(claims.iat, data.claims.iat);
    try std.testing.expectEqual(claims.exp, data.claims.exp);
    try std.testing.expectEqualSlices(u8, claims.sub, data.claims.sub);
    try std.testing.expectEqualSlices(u8, claims.name, data.claims.name);
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

    try std.testing.expectError(error.TokenSignatureInvalid, decode(Claims, allocator, token, .{
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

    try std.testing.expectError(error.TokenExpired, decode(Claims, allocator, token, .{
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

    try std.testing.expectError(error.TokenTooEarly, decode(Claims, allocator, token, .{
        .hs256 = secret,
    }));
}

test decodeOpts {
    const allocator = std.testing.allocator;

    const Claims = struct {
        nbf: i64,
        exp: i64,
        list: []const []const u8,
    };

    const Validator = struct {
        fn validate(claims: *Claims) !void {
            if (claims.list.len == 0) {
                return error.EmptyList;
            }
        }
    };

    const now = std.time.timestamp();
    // This is in the past;
    const exp = now - 10;
    // and this is in the future...
    const nbf = now + 10;

    const claims: Claims = .{
        .nbf = nbf,
        .exp = exp,
        .list = &.{ "Foo", "Bar" },
    };

    const secret = "my-256-bit-secret";
    const token = try jwt.encode(allocator, claims, .{
        .hs256 = secret,
    });
    defer allocator.free(token);

    var data = try jwt.decodeOpts(
        Claims,
        allocator,
        token,
        .{ .hs256 = secret },
        .{
            .validator = Validator.validate,
            // ...but since we give decoding a leeway of 120 seconds,
            // the token will pass validation.
            .leeway_seconds = 120,
        },
    );
    defer data.deinit();

    try std.testing.expectEqual(claims.exp, data.claims.exp);
    try std.testing.expectEqual(claims.nbf, data.claims.nbf);

    try std.testing.expectEqual(claims.list.len, data.claims.list.len);
    try std.testing.expectEqualStrings(claims.list[0], data.claims.list[0]);
    try std.testing.expectEqualStrings(claims.list[1], data.claims.list[1]);
}

test "decodeOpts: returns error if custom validator failed" {
    const allocator = std.testing.allocator;

    const Claims = struct {
        list: []const []const u8,
    };

    const Validator = struct {
        fn validate(claims: *Claims) !void {
            if (claims.list.len == 0) {
                return error.EmptyList;
            }
        }
    };

    const claims: Claims = .{
        .list = &.{},
    };

    const secret = "my-256-bit-secret";
    const token = try encode(allocator, claims, .{
        .hs256 = secret,
    });
    defer allocator.free(token);

    try std.testing.expectError(error.TokenCustomValidatorFailed, decodeOpts(
        Claims,
        allocator,
        token,
        .{ .hs256 = secret },
        .{ .validator = Validator.validate },
    ));
}

test "decodeOpts: returns token if exp within leeway" {
    const allocator = std.testing.allocator;

    const Claims = struct {
        exp: i64,
    };

    const now = std.time.timestamp();
    const exp = now - 15;

    const claims: Claims = .{
        .exp = exp,
    };

    const secret = "my-256-bit-secret";
    const token = try encode(allocator, claims, .{
        .hs256 = secret,
    });
    defer allocator.free(token);

    var data = try decodeOpts(
        Claims,
        allocator,
        token,
        .{ .hs256 = secret },
        .{ .leeway_seconds = 120 },
    );
    defer data.deinit();

    try std.testing.expectEqual(claims.exp, data.claims.exp);
}

test "decodeOpts: returns token if nbf within leeway" {
    const allocator = std.testing.allocator;

    const Claims = struct {
        nbf: i64,
    };

    const now = std.time.timestamp();
    const nbf = now + 15;

    const claims: Claims = .{
        .nbf = nbf,
    };

    const secret = "my-256-bit-secret";
    const token = try encode(allocator, claims, .{
        .hs256 = secret,
    });
    defer allocator.free(token);

    var data = try decodeOpts(
        Claims,
        allocator,
        token,
        .{ .hs256 = secret },
        .{ .leeway_seconds = 120 },
    );
    defer data.deinit();

    try std.testing.expectEqual(claims.nbf, data.claims.nbf);
}
