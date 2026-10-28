"""PALA-1 derived tree and RFC 6962 / RFC 9162 prefix-consistency proofs.

Written for bridge run B3 from:
  - PALA-1 s4.3 (the tree: leaf/node domain separation, promote-not-duplicate)
  - consistency-proof.md s1 (the derived tree over record hashes, seq order)
  - RFC 6962 s2.1   (MTH, the recursive Merkle Tree Hash)
  - RFC 6962 s2.1.2 (PROOF / SUBPROOF, consistency proof construction)
  - RFC 9162 s2.1.4.2 (consistency verification -- the normative algorithm)

stdlib only. The two tree constructions are implemented separately and
cross-checked against each other, because PALA-1 s4.3 asserts they agree
and that assertion is itself under test.
"""

import hashlib

# ------------------------------------------------------------------ the tree

def H(b):
    return hashlib.sha256(b).digest()


def leaf(d):
    """PALA-1 s4.3: leaf(d) = SHA-256(0x00 || d)."""
    return H(b"\x00" + d)


def node(l, r):
    """PALA-1 s4.3: node(l, r) = SHA-256(0x01 || l || r)."""
    return H(b"\x01" + l + r)


EMPTY = H(b"")  # PALA-1 s4.3 / consistency-proof.md s1: the empty tree's root


def tree_hash_bottom_up(leaves):
    """PALA-1 s4.3, iterative bottom-up form.

    An unpaired node is PROMOTED to the next level, never duplicated
    (duplication is the CVE-2012-2459 mistake).
    """
    if not leaves:
        return EMPTY
    level = [leaf(d) for d in leaves]
    while len(level) > 1:
        nxt = [node(level[i], level[i + 1])
               for i in range(0, len(level) - 1, 2)]
        if len(level) % 2:
            nxt.append(level[-1])          # promote
        level = nxt
    return level[0]


def _largest_pow2_below(n):
    """The largest power of 2 strictly less than n (n >= 2)."""
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaves):
    """RFC 6962 s2.1: the Merkle Tree Hash, recursive split at the largest
    power of two below n. PALA-1 s4.3 says this equals the bottom-up form;
    we implement both and assert it rather than assume it."""
    n = len(leaves)
    if n == 0:
        return EMPTY
    if n == 1:
        return leaf(leaves[0])
    k = _largest_pow2_below(n)
    return node(mth(leaves[:k]), mth(leaves[k:]))


def derived_root(record_hashes):
    """consistency-proof.md s1: the derived root of a chain of n records is
    the s4.3 tree hash over the n record hashes in seq order."""
    return tree_hash_bottom_up(record_hashes)


# ------------------------------------------- proof construction (RFC 6962)

def subproof(m, leaves, b):
    """RFC 6962 s2.1.2 SUBPROOF(m, D[n], b).

        SUBPROOF(m, D[m], true)  = {}
        SUBPROOF(m, D[m], false) = {MTH(D[m])}
        m <= k:  SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
        m >  k:  SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])

    with k the largest power of two strictly below n.
    """
    n = len(leaves)
    if m == n:
        return [] if b else [mth(leaves)]
    if not 0 < m < n:
        raise ValueError("SUBPROOF needs 0 < m <= n (m=%d, n=%d)" % (m, n))
    k = _largest_pow2_below(n)
    if m <= k:
        return subproof(m, leaves[:k], b) + [mth(leaves[k:])]
    return subproof(m - k, leaves[k:], False) + [mth(leaves[:k])]


def consistency_proof(first, leaves):
    """RFC 6962 s2.1.2: PROOF(m, D[n]) = SUBPROOF(m, D[n], true)."""
    return subproof(first, leaves, True)


# ------------------------------------------ proof verification (RFC 9162)

def verify_consistency(first, second, first_hash, second_hash, path,
                       enforce_domain=True):
    """RFC 9162 s2.1.4.2, step for step.

    Returns (ok, reason) -- a structured result, never an exception, as
    consistency-proof.md s3 requires of a verifier.

    The RFC states its own input domain: a client "has a tree head
    first_hash for tree size first, has a tree head second_hash for tree
    size second where 0 < first < second". enforce_domain=False lets a
    caller probe what the algorithm does outside that domain; it does not
    make the result conformant.
    """
    if enforce_domain and not (0 < first < second):
        return False, ("outside the RFC 9162 s2.1.4.2 input domain "
                       "0 < first < second (first=%d, second=%d)"
                       % (first, second))

    # Step 1: "If consistency_path is an empty array, stop and fail the
    #          proof verification."
    if not path:
        return False, "step 1: consistency_path is empty"

    p = list(path)

    # Step 2: "If first is an exact power of 2, then prepend first_hash to
    #          the consistency_path array."
    if first > 0 and first & (first - 1) == 0:
        p = [first_hash] + p

    # Step 3: "Set fn to first - 1 and sn to second - 1."
    fn, sn = first - 1, second - 1

    # Step 4: "If LSB(fn) is set, then right-shift both fn and sn equally
    #          until LSB(fn) is not set."
    while fn & 1:
        fn >>= 1
        sn >>= 1

    # Step 5: "Set both fr and sr to the first value in the
    #          consistency_path array."
    fr = sr = p[0]

    # Step 6: "For each subsequent value c in the consistency_path array:"
    for c in p[1:]:
        # 6.1
        if sn == 0:
            return False, "step 6.1: sn is 0 with path entries remaining"
        # 6.2
        if (fn & 1) or fn == sn:
            fr = node(c, fr)
            sr = node(c, sr)
            # 6.2.3
            if not (fn & 1):
                while fn != 0 and not (fn & 1):
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node(sr, c)
        # 6.3
        fn >>= 1
        sn >>= 1

    # Step 7
    if fr != first_hash:
        return False, ("step 7: recomputed first root %s != first_hash %s"
                       % (fr.hex(), first_hash.hex()))
    if sr != second_hash:
        return False, ("step 7: recomputed second root %s != second_hash %s"
                       % (sr.hex(), second_hash.hex()))
    if sn != 0:
        return False, "step 7: sn is %d, not 0" % sn
    return True, "ok"


def selftest():
    """Cross-check the two tree constructions PALA-1 s4.3 says agree, and
    round-trip build/verify a consistency proof for every 0 < m < n <= 24."""
    import os
    leaves = [os.urandom(32) for _ in range(24)]
    for n in range(0, 25):
        assert tree_hash_bottom_up(leaves[:n]) == mth(leaves[:n]), \
            "bottom-up != recursive MTH at n=%d" % n
    for n in range(2, 25):
        for m in range(1, n):
            proof = consistency_proof(m, leaves[:n])
            ok, why = verify_consistency(
                m, n,
                tree_hash_bottom_up(leaves[:m]),
                tree_hash_bottom_up(leaves[:n]),
                proof)
            assert ok, "proof %d->%d failed: %s" % (m, n, why)
    return True


if __name__ == "__main__":
    print("merkle.py selftest:", "PASS" if selftest() else "FAIL")
