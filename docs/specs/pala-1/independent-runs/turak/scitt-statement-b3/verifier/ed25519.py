"""Ed25519 (RFC 8032) in pure Python, stdlib only.

Written for the PALA-1 SCITT statement interop run so that neither the
signature check nor the byte-for-byte reproduction depends on a
third-party crypto stack. Correctness is anchored on RFC 8032 s7.1 TEST
vectors; see selftest().

Not constant-time. Never use for anything but test vectors.
"""

import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493   # group order
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _sha512(b):
    return hashlib.sha512(b).digest()


def _inv(x):
    return pow(x, P - 2, P)


# Extended homogeneous coordinates (X, Y, Z, T) with x=X/Z, y=Y/Z, xy=T/Z.
# RFC 8032 s5.1.4 -- avoids a modular inversion per point operation.

def _point_add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (2 * t1 * t2 * D) % P
    dd = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (dd - c) % P
    g = (dd + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _point_double(p):
    return _point_add(p, p)


def _scalarmult(p, e):
    q = (0, 1, 1, 0)  # neutral element
    while e > 0:
        if e & 1:
            q = _point_add(q, p)
        p = _point_double(p)
        e >>= 1
    return q


def _point_equal(p, q):
    x1, y1, z1, _ = p
    x2, y2, z2, _ = q
    return (x1 * z2 - x2 * z1) % P == 0 and (y1 * z2 - y2 * z1) % P == 0


def _recover_x(y, sign):
    """RFC 8032 s5.1.3 -- recover x from y and the sign bit."""
    if y >= P:
        return None
    xx = (y * y - 1) * _inv(D * y * y + 1) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = (x * SQRT_M1) % P
    if (x * x - xx) % P != 0:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = P - x
    return x


_BY = (4 * _inv(5)) % P
_BX = _recover_x(_BY, 0)
B = (_BX, _BY, 1, (_BX * _BY) % P)


def _point_compress(p):
    x, y, z, _ = p
    zi = _inv(z)
    x = (x * zi) % P
    y = (y * zi) % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(b):
    if len(b) != 32:
        return None
    y = int.from_bytes(b, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, (x * y) % P)


def _secret_expand(secret):
    if len(secret) != 32:
        raise ValueError("bad seed length")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8      # clear low 3 bits
    a |= (1 << 254)          # set bit 254
    return a, h[32:]


def public_key(seed):
    a, _ = _secret_expand(seed)
    return _point_compress(_scalarmult(B, a))


def sign(seed, msg):
    a, prefix = _secret_expand(seed)
    pub = _point_compress(_scalarmult(B, a))
    r = int.from_bytes(_sha512(prefix + msg), "little") % L
    rp = _point_compress(_scalarmult(B, r))
    k = int.from_bytes(_sha512(rp + pub + msg), "little") % L
    s = (r + k * a) % L
    return rp + int.to_bytes(s, 32, "little")


def verify(pub, msg, sig, reject_non_canonical_s=True):
    """RFC 8032 s5.1.7 verification (cofactorless form).

    reject_non_canonical_s enforces 0 <= S < L. RFC 8032 s5.1.7 step 1 says
    to reject S outside that range; a number of stacks historically did not,
    which is the classic Ed25519 signature-malleability gap.
    """
    if len(sig) != 64 or len(pub) != 32:
        return False
    a = _point_decompress(pub)
    if a is None:
        return False
    rp = _point_decompress(sig[:32])
    if rp is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if reject_non_canonical_s and s >= L:
        return False
    k = int.from_bytes(_sha512(sig[:32] + pub + msg), "little") % L
    return _point_equal(_scalarmult(B, s), _point_add(rp, _scalarmult(a, k)))


def selftest():
    """RFC 8032 s7.1 TEST 1 and TEST 2."""
    cases = [
        # (seed, public, message, signature)
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
         "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
         "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
         "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
         "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
         "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
    ]
    for seed_h, pub_h, msg_h, sig_h in cases:
        seed = bytes.fromhex(seed_h)
        pub = bytes.fromhex(pub_h)
        msg = bytes.fromhex(msg_h)
        sig = bytes.fromhex(sig_h)
        assert public_key(seed) == pub, "public key mismatch for %s" % seed_h
        assert sign(seed, msg) == sig, "signature mismatch for %s" % seed_h
        assert verify(pub, msg, sig), "verify failed for %s" % seed_h
        bad = bytearray(sig)
        bad[0] ^= 1
        assert not verify(pub, msg, bytes(bad)), "tampered sig verified"
    return True


if __name__ == "__main__":
    print("RFC 8032 s7.1 selftest:", "PASS" if selftest() else "FAIL")
