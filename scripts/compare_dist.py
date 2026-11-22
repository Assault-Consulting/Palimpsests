#!/usr/bin/env python3
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Compare a rebuilt distribution with a published one, by contents.

    python scripts/compare_dist.py dist/<file> <published file>

Two builds of the same source can differ as archives and agree as
contents: a wheel is a zip and an sdist a gzip, and the compression
library decides the compressed bytes. This reads both archives and
compares what is in them — member names in order, each member's SHA-256,
timestamp and mode. See docs/REPRODUCIBLE-BUILD.md.

Exit code: 0 same bytes or same contents, 1 different contents, 2 usage.
"""

from __future__ import annotations

import hashlib
import sys
import tarfile
import zipfile
from pathlib import Path

Member = tuple[str, str | None, object, int]


def wheel_members(path: Path) -> list[Member]:
    with zipfile.ZipFile(path) as archive:
        return [
            (info.filename, hashlib.sha256(archive.read(info)).hexdigest(),
             info.date_time, info.external_attr >> 16)
            for info in archive.infolist()
        ]


def sdist_members(path: Path) -> list[Member]:
    members: list[Member] = []
    with tarfile.open(path) as archive:
        for member in archive:
            handle = archive.extractfile(member) if member.isfile() else None
            digest = hashlib.sha256(handle.read()).hexdigest() if handle else None
            members.append((member.name, digest, member.mtime, member.mode))
    return members


def members(path: Path) -> list[Member]:
    return wheel_members(path) if path.suffix == ".whl" else sdist_members(path)


def compare(mine: Path, theirs: Path) -> tuple[int, list[str]]:
    """(exit code, lines to print)."""
    if mine.read_bytes() == theirs.read_bytes():
        return 0, ["same bytes"]
    a, b = members(mine), members(theirs)
    if a == b:
        return 0, [f"same contents ({len(a)} members); the archives differ in compression only"]
    lines = ["DIFFERENT CONTENTS"]
    names_a, names_b = [m[0] for m in a], [m[0] for m in b]
    for name in sorted(set(names_a) - set(names_b)):
        lines.append(f"  only in {mine.name}: {name}")
    for name in sorted(set(names_b) - set(names_a)):
        lines.append(f"  only in {theirs.name}: {name}")
    by_name = dict(zip(names_b, b, strict=True))
    for member in a:
        other = by_name.get(member[0])
        if other is not None and other != member:
            lines.append(f"  differs: {member[0]}")
    if names_a != names_b and sorted(names_a) == sorted(names_b):
        lines.append("  the members are in a different order")
    return 1, lines


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    code, lines = compare(Path(argv[0]), Path(argv[1]))
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
