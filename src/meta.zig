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

pub fn validateClaimTypes(comptime T: type) ClaimValidationError!void {
    return comptime blk: {
        const Claims = @typeInfo(T).@"struct";

        for (Claims.fields) |field| {
            if (std.mem.eql(u8, field.name, "iss")) {
                if (!isZigString(field.type)) {
                    break :blk error.Iss;
                }
            }

            if (std.mem.eql(u8, field.name, "sub")) {
                if (!isZigString(field.type)) {
                    break :blk error.Sub;
                }
            }

            if (std.mem.eql(u8, field.name, "jti")) {
                if (!isZigString(field.type)) {
                    break :blk error.Jti;
                }
            }

            if (std.mem.eql(u8, field.name, "iat")) {
                if (@typeInfo(field.type) != .int) {
                    break :blk error.Iat;
                }
            }

            if (std.mem.eql(u8, field.name, "exp")) {
                if (@typeInfo(field.type) != .int) {
                    break :blk error.Exp;
                }
            }

            if (std.mem.eql(u8, field.name, "nbf")) {
                if (@typeInfo(field.type) != .int) {
                    break :blk error.Nbf;
                }
            }
        }
    };
}

test "validateClaimTypes rejects iss of incorrect type" {
    const claims = .{
        .iss = 32,
    };

    try std.testing.expectError(error.Iss, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes accepts string iss" {
    const claims = .{
        .iss = "fooo",
    };

    try comptime validateClaimTypes(@TypeOf(claims));
}

test "validateClaimTypes rejects sub of incorrect type" {
    const claims = .{
        .sub = 32,
    };

    try std.testing.expectError(error.Sub, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes accepts string sub" {
    const claims = .{
        .sub = "fooo",
    };

    try comptime validateClaimTypes(@TypeOf(claims));
}

test "validateClaimTypes rejects jti of incorrect type" {
    const claims = .{
        .jti = 32,
    };

    try std.testing.expectError(error.Jti, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes accepts string jti" {
    const claims = .{
        .jti = "fooo",
    };

    try comptime validateClaimTypes(@TypeOf(claims));
}

test "validateClaimTypes rejects iat of incorrect type" {
    const claims = .{
        .iat = "foo",
    };

    try std.testing.expectError(error.Iat, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes accepts int iat" {
    const iat: i64 = 33;
    const claims = .{
        .iat = iat,
    };

    try comptime validateClaimTypes(@TypeOf(claims));
}

test "validateClaimTypes rejects nbf of incorrect type" {
    const claims = .{
        .nbf = "foo",
    };

    try std.testing.expectError(error.Nbf, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes accepts int nbf" {
    const nbf: i64 = 33;
    const claims = .{
        .nbf = nbf,
    };

    try comptime validateClaimTypes(@TypeOf(claims));
}

test "validateClaimTypes rejects exp of incorrect type" {
    const claims = .{
        .exp = "foo",
    };

    try std.testing.expectError(error.Exp, comptime validateClaimTypes(@TypeOf(claims)));
}

test "validateClaimTypes accepts int exp" {
    const exp: i64 = 33;
    const claims = .{
        .exp = exp,
    };

    try comptime validateClaimTypes(@TypeOf(claims));
}
