# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""PALA-1 record bodies: AES-256-GCM sealing and opening (§4.4).

This is the **only** module in the codec that needs a third-party package —
``cryptography``, installed via the ``[pala]`` extra — and it imports it
lazily, so header-only verification (the whole of ``verify``) works on a
bare install. That split mirrors the format's own boundary: the chain never
needs a key; only bodies do.
"""
from __future__ import annotations

from palimpsests.audit.pala.codec import (
    GCM_TAG_LEN,
    NONCE_LEN,
    aad_for,
    body_digest_of,
    nonce_for,
)

__all__ = ["seal_body", "open_body", "BodiesUnavailable"]


class BodiesUnavailable(RuntimeError):
    """Raised when body crypto is requested without the [pala] extra."""


def _aesgcm(key: bytes):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:  # pragma: no cover - import guard
        raise BodiesUnavailable(
            "record-body encryption needs the 'cryptography' package; "
            "install the [pala] extra. Header-only verification does not."
        ) from e
    if len(key) != 32:
        raise ValueError("PALA-1 body keys are 256-bit (32 bytes)")
    return AESGCM(key)


def seal_body(
    key: bytes, *, seq: int, boot_id: bytes, record_type: int, plaintext: bytes
) -> tuple[bytes, bytes]:
    """Encrypt one body per §4.4 and return ``(body, body_digest)``.

    ``body = nonce ‖ ciphertext ‖ tag`` — and ``body_len`` in the header
    MUST count all of it, nonce included (§2.3). The nonce is derived from
    ``seq`` (unique within a chain by §4.1); the AAD binds the ciphertext
    to its chain slot so bodies cannot be swapped between records.

    Order of operations is §4.4's, because it is otherwise circular:
    encrypt → digest → the caller fills the header → the caller hashes it.
    """
    nonce = nonce_for(seq)
    ct = _aesgcm(key).encrypt(nonce, plaintext, aad_for(seq, boot_id, record_type))
    body = nonce + ct
    return body, body_digest_of(body)


def open_body(
    key: bytes,
    *,
    seq: int,
    boot_id: bytes,
    record_type: int,
    body: bytes,
    body_digest: bytes,
) -> bytes:
    """Verify the digest, then decrypt — and keep the two failures apart.

    A digest mismatch means the body on disk is not the body the header
    committed to: tampering or corruption. A decryption failure *with a
    matching digest* means the key is wrong or destroyed (crypto-shredding,
    §4.4) — the log is not corrupt, and §7.5 requires reporting these
    distinctly. ``ValueError`` for the first, ``InvalidTag`` (propagated
    from the AEAD) for the second.
    """
    if body_digest_of(body) != body_digest:
        raise ValueError(
            "body does not match the header's body_digest — "
            "tampered or corrupted, independent of any key"
        )
    if len(body) < NONCE_LEN + GCM_TAG_LEN:
        raise ValueError("encrypted body shorter than nonce+tag")
    nonce, ct = body[:NONCE_LEN], body[NONCE_LEN:]
    return _aesgcm(key).decrypt(nonce, ct, aad_for(seq, boot_id, record_type))
