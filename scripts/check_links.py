#!/usr/bin/env python3
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Relative-link check for the repository's Markdown.

Every `[text](path)` that is not an external URL, a bare anchor, or a
mailto must resolve to a file or directory that exists. Run by CI, so
the answer is produced by a machine every time rather than asserted once
in a report.

    python scripts/check_links.py            # whole repo
    python scripts/check_links.py README.md  # named files

Exit 0 when every link resolves, 1 with the offenders listed otherwise.
Anchors are checked for existence of the *file*, not of the heading:
heading slugs differ between renderers, and a false failure there would
teach people to ignore this check.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
SKIP_PREFIX = ("http://", "https://", "#", "mailto:", "tel:")
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv"}


def markdown_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.md") if not any(part in SKIP_DIRS for part in p.parts))


def check(paths: list[Path]) -> list[tuple[Path, str]]:
    broken: list[tuple[Path, str]] = []
    for md in paths:
        text = md.read_text(encoding="utf-8")
        for m in LINK.finditer(text):
            target = m.group(1)
            if target.startswith(SKIP_PREFIX):
                continue
            target = target.split("#", 1)[0]
            if not target:
                continue  # a pure anchor written as [text](#x) — handled above
            if not (md.parent / target).exists():
                broken.append((md, m.group(1)))
    return broken


def main(argv: list[str]) -> int:
    root = Path(".")
    paths = [Path(a) for a in argv[1:]] or markdown_files(root)
    broken = check(paths)
    if not broken:
        print(f"links ok: {len(paths)} markdown file(s), every relative link resolves")
        return 0
    print(f"{len(broken)} broken relative link(s):", file=sys.stderr)
    for md, target in broken:
        print(f"  {md}: {target}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
