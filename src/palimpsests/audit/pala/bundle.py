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
from palimpsests.audit.names import time_trust_name
from palimpsests.audit.pala import MalformedRecord, iter_records
from palimpsests.audit.pala.proofs import InclusionProof, range_proofs
from palimpsests.audit.reader import AuditReader
from pathlib import Path

BUNDLE_FORMAT = "pala-bundle/1"

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


def _whole_records(data: bytes):
    """The records that are whole, up to the first container defect (§2.4).

    Past a defect, record boundaries cannot be trusted, so the walk stops
    there; what it stopped on is reported by the container check.
    """
    try:
        yield from iter_records(data)
    except MalformedRecord:
        return


def assemble_bundle(
    source: str | Path,
    out: str | Path,
    *,
    from_seq: int | None = None,
    to_seq: int | None = None,
    anchor_source=None,
) -> BundleResult:
    """Assemble the evidence bundle for ``source`` into the tar at ``out``.

    A damaged chain bundles too — the verdict inside says so; packaging
    broken evidence for inspection is half the point. That includes a
    container cut in the middle of a record, or bytes that are no container
    at all: the whole records before the damage are bundled, and
    ``verification.json`` says where the walk stopped. Raises OSError
    only when the source or the output path cannot be used.
    """
    data = Path(source).read_bytes()

    picked: list[tuple[bytes, bytes]] = []
    time_claims: list[dict] = []
    for hb, body in _whole_records(data):
        (seq,) = struct.unpack_from("<Q", hb, 12)
        if from_seq is not None and seq < from_seq:
            continue
        if to_seq is not None and seq > to_seq:
            continue
        picked.append((hb, body))
        trust = hb[11]
        (mono,) = struct.unpack_from("<Q", hb, 100)
        (wall,) = struct.unpack_from("<q", hb, 108)
        time_claims.append(
            {
                "seq": seq,
                "monotonic_ns": mono,
                "wall_clock_ns": wall,
                "time_trust": trust,
                "time_trust_name": time_trust_name(trust),
            }
        )

    with AuditReader.open(source, anchor=anchor_source) as reader:
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
                "source_detail": ver.anchor.source_detail,
            }
            if ver.anchor is not None
            else None
        ),
        "anchor_attempts": [
            {
                "source_kind": a.source_kind,
                "source_detail": a.source_detail,
                "outcome": a.outcome,
                "error": a.error,
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
