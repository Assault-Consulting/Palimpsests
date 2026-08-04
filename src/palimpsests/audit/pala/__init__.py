# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""PALA-1 audit wire format — codec, Merkle aggregation, verification.

**Experimental.** The normative specification lives at
``docs/specs/pala-1/PALA-1.md`` and is a draft: its field set is not yet
frozen, and this codec makes no stability promise until the specification
reaches v1.0. Where code and specification disagree, the specification
wins.

The public surface is stdlib-only except ``seal_body``/``open_body``,
which need the ``[pala]`` extra (``cryptography``) and say so at call time
rather than at import time — header-only verification must work on a bare
install, because that is a property the format promises.
"""
from palimpsests.audit.pala.bodies import BodiesUnavailable, open_body, seal_body
from palimpsests.audit.pala.codec import (
    FIXED_HEADER_LEN,
    FORMAT_VERSION,
    KNOWN_RECORD_TYPES,
    MAGIC,
    Header,
    MalformedRecord,
    aad_for,
    body_digest_of,
    decode_tlvs,
    encode_tlvs,
    iter_records,
    nonce_for,
    record_hash,
)
from palimpsests.audit.pala.merkle import (
    leaf_hash,
    merkle_proof,
    merkle_root,
    node_hash,
    verify_proof,
)
from palimpsests.audit.pala.verify import VerifyResult, verify_headers

__all__ = [
    "FIXED_HEADER_LEN",
    "FORMAT_VERSION",
    "KNOWN_RECORD_TYPES",
    "MAGIC",
    "BodiesUnavailable",
    "Header",
    "MalformedRecord",
    "VerifyResult",
    "aad_for",
    "body_digest_of",
    "decode_tlvs",
    "encode_tlvs",
    "iter_records",
    "leaf_hash",
    "merkle_proof",
    "merkle_root",
    "node_hash",
    "nonce_for",
    "open_body",
    "record_hash",
    "seal_body",
    "verify_headers",
    "verify_proof",
]
