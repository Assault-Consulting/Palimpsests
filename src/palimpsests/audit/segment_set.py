# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U18 — a segmented chain, verified as a set.

A segment verified alone reports a missing prefix by design: its first
record is not a GENESIS. Only the set, read against its
``pala-segments/1`` manifest, can be called whole — or called consistent
with segments missing, which is what retention leaves behind.

``verify_segment_set(manifest_path)`` reads the manifest once (hashed and
parsed from the same bytes, as ``Verification.manifest`` does), then:

- verifies every segment the manifest lists that is still on disk — its
  records seeded with the manifest's ``prev_head`` for it, so the link
  into the segment is checked, not assumed; its bodies against their
  digests; its head and seq range against the manifest's entry;
- checks every seam the manifest declares: each entry's ``prev_head`` is
  the previous entry's ``head``;
- finds the segment a rotating writer is still writing — it is not in the
  manifest until it is closed — as the file beside it whose first record
  links to the last listed head, and verifies it the same way.

Two answers, kept apart. ``consistent``: everything present verifies and
agrees with the manifest. ``complete``: consistent, nothing listed is
missing, and the set starts at a GENESIS. A segment deleted under a
retention policy makes a set incomplete, never inconsistent; what the
manifest says about it — its head — is the only evidence left of it, and
is reported as declared, not verified.

A separate function, not a reader method (CONSUMER-SURFACE decision 6):
its input is a set of files, not one.
"""
from __future__ import annotations

import json
import os
import struct
from dataclasses import dataclass, field
from hashlib import sha256
from palimpsests.audit.pala.codec import FIXED_HEADER_LEN, MAGIC, ZERO32, iter_records
from palimpsests.audit.pala.segments import SEGMENTS_FORMAT
from palimpsests.audit.pala.verify import verify_headers
from palimpsests.audit.reader import AuditReader
from pathlib import Path

__all__ = ["SegmentCheck", "SegmentSetVerification", "verify_segment_set"]


@dataclass(frozen=True)
class SegmentCheck:
    """One segment of the set."""

    file: str  # the name the manifest gives it, or the tail's own
    listed: bool  # False only for a writer's live tail, found by its link
    present: bool  # the file is on disk
    verified: bool | None  # its records and bodies hold, from its declared start; None if absent
    head_matches: bool | None  # its last record is the manifest's head; None if not checkable
    seam_ok: bool  # its declared predecessor is the previous entry's head
    detail: str | None = None  # why something did not hold, in words


@dataclass(frozen=True)
class SegmentSetVerification:
    manifest_path: str
    manifest_sha256: bytes  # over the bytes read and judged
    segments: list[SegmentCheck] = field(default_factory=list)
    absent: list[str] = field(default_factory=list)  # listed, not on disk
    consistent: bool = False  # everything present verifies and agrees with the manifest
    complete: bool = False  # consistent, nothing absent, starting at a GENESIS
    head: bytes | None = None  # head of the last segment present that verified


def verify_segment_set(manifest_path: str | os.PathLike[str]) -> SegmentSetVerification:
    """Verify the segments a ``pala-segments/1`` manifest describes, as one set.

    Raises ``ValueError`` when the file is not such a manifest; everything
    else — absent, tampered or mismatched segments — is an answer.
    """
    mpath = Path(manifest_path)
    raw = mpath.read_bytes()
    digest = sha256(raw).digest()
    try:
        mf = json.loads(raw.decode("utf-8"))
    except ValueError as e:
        raise ValueError(f"{mpath} is not JSON: {e}") from e
    if not isinstance(mf, dict) or mf.get("format") != SEGMENTS_FORMAT:
        raise ValueError(f"{mpath} is not a {SEGMENTS_FORMAT} manifest")
    entries = mf.get("segments")
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise ValueError(f"{mpath}: 'segments' is not a list of objects")

    folder = mpath.parent
    checks: list[SegmentCheck] = []
    absent: list[str] = []
    last_head: bytes | None = None
    prev_entry_head: str | None = None
    for entry in entries:
        name = str(entry.get("file", ""))
        seam_ok = prev_entry_head is None or entry.get("prev_head") == prev_entry_head
        prev_entry_head = entry.get("head")
        path = folder / name
        if not path.is_file():
            absent.append(name)
            checks.append(SegmentCheck(name, True, False, None, None, seam_ok,
                                       None if seam_ok else "seam: prev_head is not the "
                                       "previous entry's head"))
            continue
        check, head = _check_file(path, name, entry, seam_ok)
        checks.append(check)
        if check.verified:
            last_head = head

    tail = _live_tail(folder, mpath, entries)
    if tail is not None:
        check, head = _check_file(tail, tail.name, {"prev_head": entries[-1].get("head")}, True,
                                  listed=False)
        checks.append(check)
        if check.verified:
            last_head = head

    consistent = all(
        c.seam_ok and (not c.present or (c.verified and c.head_matches is not False))
        for c in checks
    )
    starts_at_genesis = bool(entries) and entries[0].get("prev_head") == ZERO32.hex() \
        and entries[0].get("first_seq") == 0
    return SegmentSetVerification(
        manifest_path=os.fspath(mpath),
        manifest_sha256=digest,
        segments=checks,
        absent=absent,
        consistent=consistent,
        complete=consistent and not absent and starts_at_genesis,
        head=last_head,
    )


def _check_file(path: Path, name: str, entry: dict, seam_ok: bool,
                *, listed: bool = True) -> tuple[SegmentCheck, bytes | None]:
    """Verify one segment from its declared start, and against its entry."""
    data = path.read_bytes()
    headers = [hb for hb, _body in iter_records(data)] if data else []
    prev_hex = entry.get("prev_head")
    first_is_chain_start = prev_hex == ZERO32.hex()
    try:
        start_prev = None if first_is_chain_start else bytes.fromhex(str(prev_hex))
    except ValueError:
        return SegmentCheck(name, listed, True, False, None, seam_ok,
                            "the manifest's prev_head is not hex"), None
    result = verify_headers(headers, start_prev=start_prev)
    with AuditReader.from_bytes(data) as reader:
        bodies = reader.container_check()
    verified = result.chain_ok and bodies.well_formed and not bodies.body_digest_mismatches
    head_matches: bool | None = None
    problems: list[str] = []
    if "head" in entry:
        head_matches = result.head.hex() == entry["head"]
        if not head_matches:
            problems.append("its last record is not the head the manifest names")
    for key, actual in (("first_seq", _seq(headers, 0)), ("last_seq", _seq(headers, -1)),
                        ("records", len(headers))):
        if key in entry and entry[key] != actual:
            head_matches = False
            problems.append(f"the manifest says {key} {entry[key]}, the file has {actual}")
    if not result.chain_ok:
        problems.append("its records do not verify from the declared start "
                        f"(breaks {result.breaks}, gaps {result.gaps}, "
                        f"violations {[c for _, c in result.violation_codes]})")
    if not bodies.well_formed:
        problems.append(f"the container is malformed: {bodies.malformed}")
    if bodies.body_digest_mismatches:
        problems.append(f"body digest mismatch at seq {bodies.body_digest_mismatches}")
    if not seam_ok:
        problems.append("seam: prev_head is not the previous entry's head")
    check = SegmentCheck(name, listed, True, verified, head_matches, seam_ok,
                         "; ".join(problems) or None)
    return check, (result.head if headers else None)


def _seq(headers: list[bytes], i: int) -> int | None:
    return struct.unpack_from("<Q", headers[i], 12)[0] if headers else None


def _live_tail(folder: Path, mpath: Path, entries: list[dict]) -> Path | None:
    """The unlisted file whose first record links to the last listed head —
    a rotating writer's current segment. None when there is none (a
    ``pala segment`` manifest lists every segment)."""
    if not entries:
        return None
    last = entries[-1].get("head")
    listed = {str(e.get("file", "")) for e in entries}
    for path in sorted(folder.iterdir()):
        if not path.is_file() or path.name in listed or path == mpath:
            continue
        try:
            with open(path, "rb") as fh:
                fixed = fh.read(FIXED_HEADER_LEN)
        except OSError:
            continue
        if len(fixed) == FIXED_HEADER_LEN and fixed[:4] == MAGIC and fixed[36:68].hex() == last:
            return path
    return None
