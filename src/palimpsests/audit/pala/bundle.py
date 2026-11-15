# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U8 — ``pala bundle``: one file a lawyer attaches and an auditor opens.

A bundle is a plain tar archive with five members, each independently
checkable, together answering the three questions plus *when*:

- ``records.pala`` — the records of the requested seq range, exact
  source bytes (header+body), untouched. The evidence itself.
- ``proofs.json`` — per seq: the inclusion proof binding the record to
  a chain-carried Merkle root (U5), or null with the honest state of a
  record no checkpoint covers yet.
- ``verification.json`` — the full-chain verdict at assembly time:
  consistency (the header chain, and the container walk that checks every
  body against the digest its header binds), completeness against the
  supplied anchor with its provenance and attempts, and the advisory
  notes. What the assembler saw; a verifier re-derives, never trusts it.
  ``consistent`` is the one answer to "does this log hold together";
  ``chain_ok`` alone covers the headers, and a body altered after writing
  does not show in it.
- ``time-claims.json`` — every time assertion in the range, stated with
  its trust level by name, so a reader never mistakes an unsynced clock
  for a synchronized one. Wall-clock is advisory; ordering is
  monotonic+seq (§5 of the spec).
- ``MANIFEST.json`` — the bundle format name/version, the assembling
  tool version, the source chain head, the range, and the SHA-256 of
  every member above. The outer integrity statement.

Deterministic by design, like the JSONL export: same source bytes, same
range, same anchor answer, same tool version → byte-identical bundle
(fixed member order, zeroed tar metadata, no timestamps). The bundle is
DERIVED and carries no signature: the chain stays authoritative, and
every claim inside names the records it came from so it can be
re-verified against them — with no code from this module.

The format (``docs/specs/bundle/pala-bundle-1.md``) is open: a release may
add a key to a JSON member, and none is removed, renamed or given another
meaning without a new format id.
"""
from __future__ import annotations

import io
import json
import struct
import tarfile
from dataclasses import dataclass
from hashlib import sha256
from palimpsests.audit.anchors import _portable_detail, _portable_error
from palimpsests.audit.names import time_trust_name
from palimpsests.audit.pala.codec import HEADER_FIELDS
from palimpsests.audit.pala.proofs import InclusionProof, range_proofs
from palimpsests.audit.reader import AuditReader
from pathlib import Path

__all__ = ["BUNDLE_FORMAT", "BundleResult", "assemble_bundle"]

BUNDLE_FORMAT = "pala-bundle/1"

#: The four fixed-header fields the bundle reads, where the codec's own
#: field map says they are — no offset is written here a second time.
_FIELD = {f.name: f for f in HEADER_FIELDS}


def _field(header: bytes, name: str) -> int:
    f = _FIELD[name]
    return struct.unpack_from("<" + f.format, header, f.offset)[0]

_MEMBERS = (
    "records.pala",
    "proofs.json",
    "verification.json",
    "time-claims.json",
)


@dataclass(frozen=True)
class BundleResult:
    path: Path
    records: int
    proven: int
    head: str
    chain_ok: bool  # the header chain alone
    #: The log holds together: the header chain, a well-formed container,
    #: and every body matching its header's digest. What a caller reports.
    consistent: bool = True


def _tool_version() -> str:
    import palimpsests

    return palimpsests.__version__


def _json_bytes(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _proof_json(p: InclusionProof | None):
    if p is None:
        return None
    return {
        "leaf": p.leaf.hex(),
        "path": [[side, h.hex()] for side, h in p.path],
        "root": p.root.hex(),
        "root_seq": p.root_seq,
    }


def assemble_bundle(
    source: str | Path,
    out: str | Path,
    *,
    from_seq: int | None = None,
    to_seq: int | None = None,
    anchor_source=None,
    reader: AuditReader | None = None,
) -> BundleResult:
    """Assemble the evidence bundle for ``source`` into the tar at ``out``.

    A damaged chain bundles too — the verdict inside says so; packaging
    broken evidence for inspection is half the point. That includes a
    container cut in the middle of a record, or bytes that are no container
    at all: the whole records before the damage are bundled, and
    ``verification.json`` says where the walk stopped. Raises OSError
    only when the source or the output path cannot be used.

    ``reader`` (since 0.15), when given, is used in place of opening one:
    the bundle is assembled from the bytes that reader already holds, and
    the file is not read again. It is used as given — never closed here —
    and must be open on the bytes ``source`` names; ``source`` is then not
    opened at all. ``reader`` and ``anchor_source`` together raise
    ``ValueError``, as in ``build_report``: a shared reader answers with
    the anchor it was opened with. The bundle is byte-identical either way.

    Memory: the records of the *selection* are held while the archive is
    written (``records.pala`` is one tar member), plus what the reader's
    ``verify()`` holds. The source file itself is mapped, not copied.
    """
    if reader is not None and anchor_source is not None:
        raise ValueError(
            "assemble_bundle: pass anchor_source or reader, not both — a shared "
            "reader answers with the anchor it was opened with, so this "
            "anchor_source would be ignored; open the reader with it instead"
        )
    if reader is not None:
        return _assemble(reader, out, from_seq, to_seq)
    with AuditReader.open(source, anchor=anchor_source) as opened:
        return _assemble(opened, out, from_seq, to_seq)


def _assemble(reader: AuditReader, out, from_seq, to_seq) -> BundleResult:
    # The reader's header index holds the whole records up to the first
    # container defect (§2.4) — past one, record boundaries cannot be
    # trusted; what the walk stopped on is in the container check below.
    picked: list[tuple[bytes, bytes]] = []
    time_claims: list[dict] = []
    for index in range(reader.record_count):
        seq = _field(reader._headers[index], "seq")
        if from_seq is not None and seq < from_seq:
            continue
        if to_seq is not None and seq > to_seq:
            continue
        stored = reader.record_bytes_at(index)
        picked.append((stored.header, stored.body))
        trust = _field(stored.header, "time_trust")
        time_claims.append(
            {
                "seq": seq,
                "monotonic_ns": _field(stored.header, "monotonic_ns"),
                "wall_clock_ns": _field(stored.header, "wall_clock_ns"),
                "time_trust": trust,
                "time_trust_name": time_trust_name(trust),
            }
        )

    ver = reader.verify()
    seqs = [tc["seq"] for tc in time_claims]
    proofs: dict[int, InclusionProof] = (
        {p.seq: p for p in range_proofs(reader, min(seqs), max(seqs))}
        if seqs
        else {}
    )
    proof_map = {str(s): _proof_json(proofs.get(s)) for s in seqs}
    # The reader's own walk (U21) — the same object the report's
    # ``container`` section is, so the bundle and the report of one
    # file cannot give two answers.
    container = reader.container_check()

    chain = ver.chain
    consistent = (
        chain.chain_ok and container.well_formed and not container.body_digest_mismatches
    )
    verification = {
        "consistent": consistent,
        "chain_ok": chain.chain_ok,
        "records": chain.count,
        "head": chain.head.hex(),
        "breaks": chain.breaks,
        "gaps": chain.gaps,
        "violations": chain.violations,
        "violation_codes": chain.violation_codes,
        "uninterpretable": chain.uninterpretable,
        "container": {
            "well_formed": container.well_formed,
            "malformed": container.malformed,
            "bytes_parsed": container.bytes_parsed,
            "bytes_total": container.bytes_total,
            "body_digest_mismatches": list(container.body_digest_mismatches),
        },
        "completeness": {
            "checked": ver.complete_to_anchor is not None,
            "ok": ver.complete_to_anchor,
            "anchor_lag": ver.anchor_lag,
        },
        "anchor": (
            {
                "head": ver.anchor.head.hex(),
                "source_kind": ver.anchor.source_kind,
                # named, not located: a bundle is made to be sent
                "source_detail": _portable_detail(
                    ver.anchor.source_kind, ver.anchor.source_detail),
            }
            if ver.anchor is not None
            else None
        ),
        "anchor_attempts": [
            {
                "source_kind": a.source_kind,
                "source_detail": _portable_detail(a.source_kind, a.source_detail),
                "outcome": a.outcome,
                "error": _portable_error(a.source_kind, a.source_detail, a.error),
            }
            for a in ver.anchor_attempts
        ],
        "advisory": [
            {"code": i.code, "at_seq": i.at_seq, "detail": i.detail}
            for i in ver.advisory.items
        ],
    }

    members: dict[str, bytes] = {
        "records.pala": b"".join(hb + body for hb, body in picked),
        "proofs.json": _json_bytes(
            {
                "$comment": (
                    "null = no MERKLE checkpoint covers this record yet; "
                    "'not yet aggregated' is not 'not included'."
                ),
                "proofs": proof_map,
            }
        ),
        "verification.json": _json_bytes(verification),
        "time-claims.json": _json_bytes(
            {
                "$comment": (
                    "wall_clock_ns is advisory and only as good as its "
                    "time_trust says; ordering authority is monotonic_ns "
                    "+ seq (spec §5)."
                ),
                "claims": time_claims,
            }
        ),
    }

    manifest = {
        "format": BUNDLE_FORMAT,
        "tool": {"name": "palimpsests", "version": _tool_version()},
        "source_head": chain.head.hex(),
        "range": {
            "from_seq": seqs[0] if seqs else None,
            "to_seq": seqs[-1] if seqs else None,
            "records": len(seqs),
        },
        "members": {
            name: {"sha256": sha256(members[name]).hexdigest()}
            for name in _MEMBERS
        },
    }

    out_path = Path(out)
    with tarfile.open(out_path, "w") as tar:
        for name in (*_MEMBERS, "MANIFEST.json"):
            payload = members[name] if name in members else _json_bytes(manifest)
            info = tarfile.TarInfo(name=name)
            info.size = len(payload)
            info.mtime = 0
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(payload))

    proven = sum(1 for v in proof_map.values() if v is not None)
    return BundleResult(
        path=out_path,
        records=len(seqs),
        proven=proven,
        head=chain.head.hex(),
        chain_ok=chain.chain_ok,
        consistent=consistent,
    )
