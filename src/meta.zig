const std = @import("std");

// copied from https://github.com/capy-ui/capy/blob/4d41d962e6d0404a7beb9c37c1a5ba68556f9efb/src/trait.zig#L47C1-L73C6
fn isZigString(comptime T: type) bool {
    return comptime blk: {
        // Only pointer types can be strings, no optionals
        const info = @typeInfo(T);
        if (info != .pointer) break :blk false;

        const ptr = &info.pointer;
        // Check for CV qualifiers that would prevent coerction to []const u8
        if (ptr.is_volatile or ptr.is_allowzero) break :blk false;

        // If it's already a slice, simple check.
        if (ptr.size == .slice) {
            break :blk ptr.child == u8;
        }

        // Otherwise check if it's an array type that coerces to slice.
        if (ptr.size == .one) {
            const child = @typeInfo(ptr.child);
            if (child == .array) {
                const arr = &child.array;
                break :blk arr.child == u8;
            }
        }

        break :blk false;
    };
}

const ClaimValidationError = error{
    Iss,
    Sub,
    Jti,
    Iat,
    Exp,
    Nbf,
};

fn claimField(comptime err: ClaimValidationError) []const u8 {
    return switch (err) {
        error.Iss => "iss",
        error.Sub => "sub",
        error.Jti => "jti",
        error.Iat => "iat",
        error.Exp => "exp",
        error.Nbf => "nbf",
    };
}

pub fn claimCompileError(comptime err: ClaimValidationError) noreturn {
    const message = switch (err) {
        error.Iss, error.Sub, error.Jti => std.fmt.comptimePrint(
            "\"{s}\" claim must be of type `[]u8`, `[]const u8`, or coercable to one of the former.",
            .{claimField(err)},
        ),
        error.Iat, error.Exp, error.Nbf => std.fmt.comptimePrint(
            "\"{s}\" claim must be an integer.",
            .{claimField(err)},
        ),
    };
    @compileError(message);
}

pub fn validateClaimTypes(comptime T: type) ClaimValidationError!StandardClaimInfo {
    return comptime blk: {
        const info = getStandardClaims(T);

        if (info.has_iss and !isZigString(@FieldType(T, "iss"))) {
            break :blk error.Iss;
        }

        if (info.has_sub and !isZigString(@FieldType(T, "sub"))) {
            break :blk error.Sub;
        }

        if (info.has_jti and !isZigString(@FieldType(T, "jti"))) {
            break :blk error.Jti;
        }

        if (info.has_iat and @typeInfo(@FieldType(T, "iat")) != .int) {
            break :blk error.Iat;
        }

        if (info.has_exp and @typeInfo(@FieldType(T, "exp")) != .int) {
            break :blk error.Exp;
        }

        if (info.has_nbf and @typeInfo(@FieldType(T, "nbf")) != .int) {
            break :blk error.Nbf;
        }

        break :blk info;
    };
}

pub const StandardClaimInfo = struct {
    has_iss: bool = false,
    has_sub: bool = false,
    has_jti: bool = false,
    has_iat: bool = false,
    has_exp: bool = false,
    has_nbf: bool = false,
};

fn getStandardClaims(comptime T: type) StandardClaimInfo {
    return comptime blk: {
        var info: StandardClaimInfo = .{};

        info.has_iss = @hasField(T, "iss");
        info.has_sub = @hasField(T, "sub");
        info.has_jti = @hasField(T, "jti");
        info.has_iat = @hasField(T, "iat");
        info.has_exp = @hasField(T, "exp");
        info.has_nbf = @hasField(T, "nbf");

        break :blk info;
    };
}

test "validateClaimTypes accepts claims of correct type" {
    const iat: i64 = 42;
    const exp: i64 = 42;
    const nbf: i64 = 42;

    const claims = .{
        .iss = "test",
        .sub = "1",
        .jti = "3321432",
        .iat = iat,
        .exp = exp,
        .nbf = nbf,

        // non-standard claim
        .name = "BrainBlasted",
    };

    _ = try comptime validateClaimTypes(@TypeOf(claims));
}

test "validateClaimTypes rejects iss of incorrect type" {
    const claims = .{
        .iss = 32,
    };

    try std.testing.expectError(error.Iss, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes rejects sub of incorrect type" {
    const claims = .{
        .sub = 32,
    };

    try std.testing.expectError(error.Sub, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes rejects jti of incorrect type" {
    const claims = .{
        .jti = 32,
    };

    try std.testing.expectError(error.Jti, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes rejects iat of incorrect type" {
    const claims = .{
        .iat = "foo",
    };

    try std.testing.expectError(error.Iat, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes rejects nbf of incorrect type" {
    const claims = .{
        .nbf = "foo",
    };

    try std.testing.expectError(error.Nbf, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes rejects exp of incorrect type" {
    const claims = .{
        .exp = "foo",
    };

    try std.testing.expectError(error.Exp, comptime validateClaimTypes(@TypeOf(claims)));
}

test "getStandardClaims returns claims that are present" {
    const Claims = struct {
        iss: []const u8,
        sub: []const u8,
        jti: []const u8,
        iat: i64,
        exp: i64,
        nbf: i64,

        // non-standard claim
        name: []const u8,
    };

    const info = comptime getStandardClaims(Claims);
    try std.testing.expect(info.has_iss);
    try std.testing.expect(info.has_sub);
    try std.testing.expect(info.has_jti);
    try std.testing.expect(info.has_iat);
    try std.testing.expect(info.has_exp);
    try std.testing.expect(info.has_nbf);
}

test "getStandardClaims false when claims aren't present" {
    const Claims = struct {
        name: []const u8,
    };

    const info = comptime getStandardClaims(Claims);
    try std.testing.expect(!info.has_iss);
    try std.testing.expect(!info.has_sub);
    try std.testing.expect(!info.has_jti);
    try std.testing.expect(!info.has_iat);
    try std.testing.expect(!info.has_exp);
    try std.testing.expect(!info.has_nbf);
}
