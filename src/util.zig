const std = @import("std");

const Allocator = std.mem.Allocator;

const Base64URL = std.base64.url_safe_no_pad;

pub const EncodingError = std.base64.Error || Allocator.Error;

pub fn base64URLEncode(allocator: Allocator, source: []const u8) EncodingError![]u8 {
    const base64 = try allocator.alloc(u8, Base64URL.Encoder.calcSize(source.len));
    _ = Base64URL.Encoder.encode(base64, source);
    return base64;
}

pub fn base64URLDecode(allocator: Allocator, base64: []const u8) EncodingError![]u8 {
    const decoded = try allocator.alloc(u8, try Base64URL.Decoder.calcSizeForSlice(base64));
    try Base64URL.Decoder.decode(decoded, base64);
    return decoded;
}

pub const TokenSegments = struct {
    header: []const u8,
    claims: []const u8,
    signature: []const u8,
    message: []const u8,
};

pub fn splitToken(token: []const u8) error{TokenFormatInvalid}!TokenSegments {
    const header_end = std.mem.indexOfScalar(
        u8,
        token,
        '.',
    ) orelse return error.TokenFormatInvalid;
    const signature_start = std.mem.indexOfScalarPos(
        u8,
        token,
        header_end + 1,
        '.',
    ) orelse return error.TokenFormatInvalid;

    return .{
        .header = token[0..header_end],
        .claims = token[header_end + 1 .. signature_start],
        .signature = token[signature_start + 1 ..],
        .message = token[0..signature_start],
    };
}
