"""Ed25519 signing and verification, written from RFC 8032.

Pure Python, standard library only (``hashlib`` for SHA-512). No crypto
library is used anywhere in this run: the point of the exercise is that
the signature is checked by code derived from the standard, not by a
dependency that might share an ancestor with the code that produced the
bytes under test.

This follows RFC 8032 section 5.1 -- PureEdDSA over edwards25519, the
scheme the vector's COSE ``alg`` of -8 (EdDSA) selects. Points are held
in extended homogeneous coordinates (X, Y, Z, T) with x = X/Z, y = Y/Z
and T = XY/Z, which keeps scalar multiplication to field operations.

Verification follows the RFC's cofactorless equation
[S]B = R + [k]A, and rejects a scalar S outside [0, L) as RFC 8032
section 5.1.7 directs. It is deliberately not constant-time: it handles
one published test key and no secrets.
"""

import hashlib

# Field and group constants, RFC 8032 section 5.1.
P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493


def _inv(x):
    return pow(x, P - 2, P)


D = -121665 * _inv(121666) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    """Recover the x coordinate of a compressed point, RFC 8032 section 5.1.3."""
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0

    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None

    if (x & 1) != sign:
        x = P - x
    return x


G_Y = 4 * _inv(5) % P
G_X = _recover_x(G_Y, 0)
G = (G_X, G_Y, 1, G_X * G_Y % P)
IDENTITY = (0, 1, 1, 0)


def _add(point, other):
    """Twisted Edwards addition with a = -1, RFC 8032 section 5.1.4."""
    x1, y1, z1, t1 = point
    x2, y2, z2, t2 = other
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(scalar, point):
    result = IDENTITY
    while scalar > 0:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _equal(point, other):
    x1, y1, z1, _ = point
    x2, y2, z2, _ = other
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _compress(point):
    x, y, z, _ = point
    zinv = _inv(z)
    x = x * zinv % P
    y = y * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(data):
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _sha512_modq(data):
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % L


def _expand(seed):
    """RFC 8032 section 5.1.5: clamp the first half, keep the second as prefix."""
    if len(seed) != 32:
        raise ValueError("an Ed25519 private key seed is 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    return scalar, digest[32:]


def public_key(seed):
    """Derive the 32-byte public key from a 32-byte seed (section 5.1.5)."""
    scalar, _ = _expand(seed)
    return _compress(_mul(scalar, G))


def sign(seed, message):
    """Deterministic PureEdDSA signature, RFC 8032 section 5.1.6."""
    scalar, prefix = _expand(seed)
    encoded_a = _compress(_mul(scalar, G))
    r = _sha512_modq(prefix + message)
    encoded_r = _compress(_mul(r, G))
    k = _sha512_modq(encoded_r + encoded_a + message)
    s = (r + k * scalar) % L
    return encoded_r + int.to_bytes(s, 32, "little")


def verify(public, message, signature, enforce_canonical_s=True):
    """Verify a PureEdDSA signature, RFC 8032 section 5.1.7.

    Returns ``(ok, reason)``. ``enforce_canonical_s=False`` deliberately
    skips the ``S < L`` range check so the run can demonstrate what that
    check is protecting against.
    """
    if len(public) != 32:
        return False, f"public key is {len(public)} bytes, not 32"
    if len(signature) != 64:
        return False, f"signature is {len(signature)} bytes, not 64"

    point_a = _decompress(public)
    if point_a is None:
        return False, "public key is not a point on the curve"

    encoded_r = signature[:32]
    point_r = _decompress(encoded_r)
    if point_r is None:
        return False, "signature R is not a point on the curve"

    s = int.from_bytes(signature[32:], "little")
    if enforce_canonical_s and s >= L:
        return False, "signature S is not in the range [0, L) (section 5.1.7)"

    k = _sha512_modq(encoded_r + public + message)
    if _equal(_mul(s, G), _add(point_r, _mul(k, point_a))):
        return True, "ok"
    return False, "the group equation [S]B = R + [k]A does not hold"
