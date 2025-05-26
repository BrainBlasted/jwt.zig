# jwt.zig

Functions for encoding and decoding JSON Web Tokens ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519)).

## Overview

`jwt.zig` provides a simple, flexible, and type-safe implementation of the JSON Web Token
specification. Developers can create custom claims stucts that `jwt.zig` will encode into
and decode from compact JWS tokens.

### Claims

To encode or decode a token, you must provide a set of claims. Developers can use
any struct that can be serialized and deserialized from JSON for this. Typically
a claims struct will provide at least one of the standard claims described in
[RFC7519 Section 4.1](https://www.rfc-editor.org/rfc/rfc7519#section-4.1), but
none of those claims are mandatory.

The following standard claims are supported and checked for type correctness
at compile time if the provided struct has these fields:

* `iss`, `sub`, `jti`: `[]u8`, `[]const u8`, or coercable to one of the former.
* `iat`, `exp`, `nbf`: Any integer type that can represent the number of seconds
since the unix timestamp (UTC 1970-01-01). Recommended: `i64`.

```zig
const Claims = struct {
    iat: i64,
    exp: i64,
    sub: []const u8,
    // non-standard claim
    name: []const u8,
};
```

### Keys

`jwt.zig` currently only supports the three HMAC signing algorithms or `none` as signing
algorithms. Developers should store their secret keys in a secure location and load them
dynamically. Keys should **never** be stored in source code or committed to source control.

```zig
const secret = try std.process.getEnvVarOwned(allocator, "JWT_SECRET");
defer allocator.free(secret);

const key: jwt.Key = .{
    .hs256 = secret,
};
```

### Encoding

Once a developer has claims and a key, they can encode their claims struct into a token
with the `encode()` function. It returns an allocated byte string that the caller is
responsible for freeing.

Calling `encode()` triggers compile-time checks to ensure the given claims have the right
structure. 

```zig
const token = try jwt.encode(allocator, claims, key);
```

### Decoding

To validate a token, you call `decode()`, which will return a handle to the
decoded claims. The key given to `decode()` must be the same as the key
given to `encode()`, otherwise decoding will fail.

If the standard claims `exp` and `nbf` are present, they will be checked against
the current time for validity.

The caller *must* call `deinit()` on the returned item to release
the allocated memory.

```zig
const data = try jwt.decode(Claims, allocator, token, key);
defer data.deinit();
```

## References

* JWT Website ([jwt.io](https://jwt.io/))
* JSON Web Signatures ([RFC7515](https://www.rfc-editor.org/rfc/rfc7515))
* JSON Web Algorithms ([RFC7518](https://www.rfc-editor.org/rfc/rfc7518))
* JSON Web Tokens ([RFC7519](https://www.rfc-editor.org/rfc/rfc7519))
