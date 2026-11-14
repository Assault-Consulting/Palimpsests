# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Gather ``changelog.d/*.md`` into a new ``CHANGELOG.md`` section.

    python scripts/assemble_changelog.py VERSION DATE INTRO_FILE
    python scripts/assemble_changelog.py --check

The first form is a release step (RELEASING.md): every fragment's entries go
under their headings in the new ``## [VERSION] — DATE`` section, the fragments
are deleted, and the link references at the foot of the changelog move on.
``--check`` only parses the fragments and reports how many there are; it
writes nothing, and the test suite runs the same parse on every change so a
fragment that cannot be gathered fails long before a release.

The script refuses rather than guesses: a heading it does not know, text
before the first heading, a version already in the changelog, no fragments
at all. A release step that half-works is worse than one that stops.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ORDER = ("Security", "Added", "Changed", "Fixed", "Documentation")
UNRELEASED = "## [Unreleased]\n\n"
_HEADING = re.compile(r"^### (.+?)\s*$")
_LINK = re.compile(r"^\[Unreleased\]: (\S+)/compare/v(\S+?)\.\.\.HEAD$", re.M)


class Refused(Exception):
    """The fragments or the changelog are not in a state to be gathered."""


def fragments(root: Path) -> list[Path]:
    return sorted(p for p in (root / "changelog.d").glob("*.md") if p.name != "README.md")


def parse(path: Path) -> dict[str, list[str]]:
    """One fragment -> its text under each heading, in the file's order."""
    found: dict[str, list[str]] = {}
    current: str | None = None
    block: list[str] = []

    def close() -> None:
        text = "\n".join(block).strip("\n")
        if current is not None and text:
            found.setdefault(current, []).append(text)

    for line in path.read_text(encoding="utf-8").splitlines():
        m = _HEADING.match(line)
        if m:
            close()
            current, block = m.group(1), []
            if current not in ORDER:
                raise Refused(f"{path.name}: unknown heading '### {current}'")
            continue
        if current is None:
            if line.strip():
                raise Refused(f"{path.name}: text before the first ### heading")
            continue
        block.append(line)
    close()
    if not found:
        raise Refused(f"{path.name}: no entry under any heading")
    return found


def gather(paths: list[Path]) -> dict[str, list[str]]:
    chunks: dict[str, list[str]] = {h: [] for h in ORDER}
    for p in paths:
        for heading, texts in parse(p).items():
            chunks[heading].extend(texts)
    return chunks


def section(version: str, date: str, intro: str, chunks: dict[str, list[str]]) -> str:
    parts = [f"## [{version}] — {date}", ""]
    if intro:
        parts += [intro, ""]
    for h in ORDER:
        if chunks[h]:
            parts += [f"### {h}", "", "\n\n".join(chunks[h]), ""]
    return "\n".join(parts) + "\n"


def assemble(root: Path, version: str, date: str, intro: str) -> int:
    """Write the section, move the links, delete the fragments. Returns the count."""
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise Refused(f"version '{version}' is not X.Y.Z")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date):
        raise Refused(f"date '{date}' is not YYYY-MM-DD")
    paths = fragments(root)
    if not paths:
        raise Refused("changelog.d/ holds no fragments: nothing to release")
    chunks = gather(paths)  # every fragment parsed before anything is written

    cl = root / "CHANGELOG.md"
    text = cl.read_bytes().decode("utf-8")
    if "\r\n" in text:
        raise Refused("CHANGELOG.md has CRLF line endings; fix the checkout first")
    if f"## [{version}]" in text:
        raise Refused(f"CHANGELOG.md already has a [{version}] section")
    if text.count(UNRELEASED) != 1:
        raise Refused("CHANGELOG.md: '## [Unreleased]' followed by a blank line, not found once")
    link = _LINK.search(text)
    if link is None:
        raise Refused("CHANGELOG.md: the '[Unreleased]: …/compare/vX.Y.Z...HEAD' link not found")
    base = link.group(1)

    text = text.replace(UNRELEASED, UNRELEASED + section(version, date, intro.strip(), chunks), 1)
    text = text.replace(
        link.group(0),
        f"[Unreleased]: {base}/compare/v{version}...HEAD\n"
        f"[{version}]: {base}/releases/tag/v{version}",
        1,
    )
    cl.write_text(text, encoding="utf-8", newline="\n")
    for p in paths:
        p.unlink()
    return len(paths)


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        if argv == ["--check"]:
            paths = fragments(root)
            gather(paths)
            print(f"{len(paths)} fragment(s) in changelog.d/, all gatherable")
            return 0
        if len(argv) != 3:
            print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
            return 2
        version, date, intro_file = argv
        n = assemble(root, version, date, Path(intro_file).read_text(encoding="utf-8"))
    except Refused as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    print(f"{n} fragments gathered into [{version}] and deleted")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
