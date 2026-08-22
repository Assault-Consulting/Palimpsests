# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U8 groundwork — emitting the MERKLE records the proofs bridge reads.

U5 gave readers the seq→proof bridge; until now nothing on the writing
side produced a MERKLE record, so every real chain answered ``None``.
``merkle_checkpoint`` closes that: it aggregates every record written
since the previous checkpoint (the previous MERKLE record's own hash
included — so windows tile the chain exactly, per the coverage rule
stated in ``proofs.py``) and emits one MERKLE record carrying the tree
hash and the leaf count.

Package-internal by design, like the proofs bridge: the leaves are read
back from the file the writer keeps (unbuffered, so every emitted
record is already durable), and the record is emitted through the
writer's own serialized path — never by writing bytes beside it.

Not safe against a concurrent emit between the read and the checkpoint
record: call it from the same context that writes (the adapter's
thread), which is how every writer method is used already.
"""
from __future__ import annotations

import struct
from palimpsests.audit.pala import iter_records
from palimpsests.audit.pala.codec import (
    RT_MERKLE,
    TLV_MERKLE_LEAF_COUNT,
    TLV_MERKLE_TREE_HASH,
)
from palimpsests.audit.pala.codec import (
    record_hash as _record_hash,
)
from palimpsests.audit.pala.merkle import merkle_root
from pathlib import Path


def merkle_checkpoint(writer) -> bytes | None:
    """Aggregate the window since the last checkpoint into a MERKLE record.

    Returns the new record's hash, or None when there is nothing to
    aggregate (an empty file). Leaves are the record hashes of every
    record after the previous MERKLE record — that record itself
    included — in seq order, so a periodic caller tiles the whole chain
    and ``inclusion_proof`` can answer for every non-tail record.
    """
    data = Path(writer._path).read_bytes()
    window: list[bytes] = []
    for hb, _body in iter_records(data):
        (rtype,) = struct.unpack_from("<H", hb, 8)
        rh = _record_hash(hb)
        if rtype == RT_MERKLE:
            window = [rh]  # the new window starts at the checkpoint itself
        else:
            window.append(rh)
    if not window:
        return None
    root = merkle_root(window)
    return writer._emit(
        RT_MERKLE,
        tlvs=[
            (TLV_MERKLE_TREE_HASH, root),
            (TLV_MERKLE_LEAF_COUNT, struct.pack("<I", len(window))),
        ],
    )
