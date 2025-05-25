const std = @import("std");

const Allocator = std.mem.Allocator;

const Base64URL = std.base64.url_safe_no_pad;

pub const EncodingError = std.base64.Error || Allocator.Error;

pub fn base64URLEncode(allocator: Allocator, source: []const u8) EncodingError![]u8 {
    var base64 = std.ArrayList(u8).init(allocator);
    try Base64URL.Encoder.encodeWriter(base64.writer(), source);
    return base64.toOwnedSlice();
}

pub fn base64URLDecode(allocator: Allocator, base64: []const u8) EncodingError![]u8 {
    const size = try Base64URL.Decoder.calcSizeForSlice(base64);
    var decoded = try std.ArrayList(u8).initCapacity(allocator, size);
    decoded.expandToCapacity();

    try Base64URL.Decoder.decode(decoded.items, base64);
    return decoded.toOwnedSlice();
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
