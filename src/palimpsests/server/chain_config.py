# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""How the serve's chain is cut into segments, and which file is being written.

A serve that runs for months writes one chain. Left as one file it can
only be kept whole or lost whole; cut into segments, the old ones can be
archived or — once the retention the deployment declares has passed —
deleted, and what remains still names the history it continues
(``docs/RETENTION.md``).

The writer has made such cuts since 0.11 (``RotationPolicy``). The serve
had no way to ask for them: its chain was always the one file
``serve.pala``. This module reads the request from the environment, the
way the durability policy is read, and finds the file a restarted serve
has to continue.

The second half matters as much as the first. Once a chain has been cut,
``serve.pala`` is a *closed* segment. A serve that opened it again and
appended would write a second history after a head the manifest already
names as an end — a fork, made by the recorder itself. So the file to
continue is found from the manifest, whatever the policy says now: a
chain that was ever rotated is resumed at its live segment, and a policy
that has since been removed stops further cuts and nothing else.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from pathlib import Path

__all__ = [
    "RETENTION_VAR",
    "ROTATE_AGE_VAR",
    "ROTATE_BYTES_VAR",
    "ROTATE_RECORDS_VAR",
    "live_chain_path",
    "rotation_from_env",
]

#: Cut when the segment being written reaches this size: bytes, or a
#: number with ``KiB``, ``MiB`` or ``GiB``.
ROTATE_BYTES_VAR = "PALIMPSESTS_AUDIT_ROTATE_BYTES"
#: Cut when the segment being written holds this many records.
ROTATE_RECORDS_VAR = "PALIMPSESTS_AUDIT_ROTATE_RECORDS"
#: Cut when the segment being written is this old: seconds, or a number
#: with ``s``, ``m``, ``h`` or ``d``. Measured on the process's monotonic
#: clock, so it starts again when the serve does.
ROTATE_AGE_VAR = "PALIMPSESTS_AUDIT_ROTATE_AGE"
#: The retention the deployment declares for a closed segment, written into
#: the chain at every cut: seconds, or a number with ``s``, ``m``, ``h`` or
#: ``d``. A declaration — nothing here deletes a segment.
RETENTION_VAR = "PALIMPSESTS_AUDIT_RETENTION"

_SIZES = {"": 1, "kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30}
_DURATIONS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}
_QUANTITY = re.compile(r"\s*(\d+)\s*([A-Za-z]*)\s*\Z")


def _quantity(spelled: str, units: Mapping[str, int], what: str) -> int:
    match = _QUANTITY.match(spelled)
    if match is None or match.group(2).lower() not in units:
        allowed = ", ".join(u for u in units if u) or "none"
        raise ValueError(
            f"{spelled!r} is not {what}: a whole number, optionally followed by one of "
            f"{allowed} (as written here, or in any letter case)")
    return int(match.group(1)) * units[match.group(2).lower()]


def rotation_from_env(environ: Mapping[str, str]):
    """The rotation policy the environment asks for, or ``None`` for none.

    Raises ``ValueError`` naming the variable for a value that cannot be
    read, for a threshold of zero, and for a retention declared with no
    threshold — a floor for segments that are never cut is a mistake in
    the configuration, not a policy. A typo must not quietly become "do
    not rotate": the serve does not start.
    """
    from palimpsests.audit.pala_writer import RotationPolicy

    def read(name: str, units: Mapping[str, int], what: str) -> int | None:
        spelled = environ.get(name)
        if spelled is None or not spelled.strip():
            return None
        try:
            return _quantity(spelled, units, what)
        except ValueError as exc:
            raise ValueError(f"{name}={exc}") from exc

    max_bytes = read(ROTATE_BYTES_VAR, _SIZES, "a size")
    max_records = read(ROTATE_RECORDS_VAR, {"": 1}, "a number of records")
    max_age = read(ROTATE_AGE_VAR, _DURATIONS, "a duration")
    retention = read(RETENTION_VAR, _DURATIONS, "a duration")
    if max_bytes is None and max_records is None and max_age is None:
        if retention is not None:
            raise ValueError(
                f"{RETENTION_VAR} is set and no rotation threshold is "
                f"({ROTATE_BYTES_VAR}, {ROTATE_RECORDS_VAR}, {ROTATE_AGE_VAR}): a chain "
                "that is never cut has no closed segment for the retention to be about")
        return None
    try:
        return RotationPolicy(
            max_records=max_records, max_bytes=max_bytes,
            max_age_s=float(max_age) if max_age is not None else None,
            retention_s=retention,
        )
    except ValueError as exc:
        raise ValueError(f"the rotation policy cannot be used: {exc}") from exc


def live_chain_path(base: Path) -> Path:
    """The file a serve whose chain starts at ``base`` has to continue.

    ``base`` itself, until the chain has been cut. After a cut, the
    segment the writer was on — the file beside the manifest whose first
    record continues the last closed head; or, where a cut recorded its
    closed segment and stopped before the successor appeared, that last
    listed segment, which the writer folds back into use.

    Raises ``ValueError`` when the manifest is there and no segment to
    continue is: the serve then does not start, rather than begin a
    second history at ``base``.

    One case cannot be told from the disk: a live segment that existed and
    was deleted leaves exactly what an unfinished cut leaves. The chain is
    then continued from the last closed head and verifies — shorter than
    it was. That is a truncated tail, and as for a chain kept in one file,
    only a head anchored outside the host shows it.
    """
    from palimpsests.audit.pala.segments import SEGMENTS_FORMAT
    from palimpsests.audit.segment_set import _live_tail

    manifest = base.with_name(base.name + ".segments.json")
    if not manifest.exists():
        return base
    try:
        doc = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"{manifest} cannot be read ({exc})") from exc
    entries = doc.get("segments") if isinstance(doc, dict) else None
    if (not isinstance(doc, dict) or doc.get("format") != SEGMENTS_FORMAT
            or not isinstance(entries, list)
            or not all(isinstance(e, dict) for e in entries)):
        raise ValueError(f"{manifest} is not a {SEGMENTS_FORMAT} manifest")
    if not entries:
        return base
    tail = _live_tail(manifest.parent, manifest, entries)
    if tail is not None:
        return tail
    last = manifest.parent / str(entries[-1].get("file", ""))
    if last.name == str(entries[-1].get("file", "")) and last.is_file():
        return last  # a cut that did not finish: the writer undoes it
    raise ValueError(
        f"{manifest} says this chain was cut into segments, and the segment being "
        f"written is not beside it (the last one closed is {entries[-1].get('file')!r}). "
        "Starting again at the first file would begin a second history; restore the "
        "missing segment, or move the chain and its manifest away to start a new one")
