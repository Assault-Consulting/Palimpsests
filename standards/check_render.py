# SPDX-FileCopyrightText: 2026 Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Check that every literal block of a draft source survives into its render.

Usage: check_render.py SOURCE.md RENDERED.txt

The -00 posted text had seven literal blocks flattened into running prose:
kramdown-rfc reads a line of three backticks as an inline code span, not as
a fence, so the block became one paragraph and its line structure -- the
normative verification pseudocode included -- was lost. Nothing failed: the
document rendered, it just said something else.

Posted revisions (POSTED) are skipped: their text is archived by the IETF
and cannot change, so a check could only report, never prevent. The check
guards the revision being prepared. It fails when:
  1. a source uses ``` fences (kramdown's fence is ~~~);
  2. any non-blank line of a literal block in the source does not appear in
     the rendered text verbatim, internal indentation included (the renderer
     may add a fixed left margin, nothing else);
  3. a fence marker leaks into the rendered text.
"""

import re
import sys
from pathlib import Path

# Posted revisions: archived by the IETF, immutable -- skipped.
POSTED = {"draft-sparysh-pala-audit-00.md"}
FENCE = re.compile(r"^(```|~~~)\s*$")
MARGINS = ("", "   ")  # xml2rfc artwork indent; 0 when the block is too wide


def blocks(src: str):
    out, cur, fence = [], None, None
    for n, line in enumerate(src.splitlines(), 1):
        m = FENCE.match(line)
        if m and cur is None:
            cur, fence = [], m.group(1)
            start = n
        elif m and cur is not None and m.group(1) == fence:
            out.append((start, fence, cur))
            cur = None
        elif cur is not None:
            cur.append((n, line.rstrip()))
    return out


def main(src_path: str, txt_path: str) -> int:
    if Path(src_path).name in POSTED:
        print(f"skip: {src_path} is a posted revision (immutable)")
        return 0
    src = Path(src_path).read_text(encoding="utf-8")
    txt = Path(txt_path).read_text(encoding="utf-8")
    rendered = {t.rstrip() for t in txt.splitlines()}
    errors = []
    found = blocks(src)
    for start, fence, lines in found:
        if fence == "```":
            errors.append(f"{src_path}:{start}: ``` fence -- use ~~~")
        for n, line in lines:
            if line and not any(m + line in rendered for m in MARGINS):
                errors.append(f"{src_path}:{n}: not in render verbatim: {line!r}")
    for i, t in enumerate(txt.splitlines(), 1):
        if "```" in t or t.strip() == "~~~":
            errors.append(f"{txt_path}:{i}: fence marker leaked into render")
    total = sum(1 for *_, ls in found for _, text in ls if text)
    if errors:
        print("\n".join(errors))
        print(
            f"FAIL: {len(errors)} problem(s); {len(found)} blocks, {total} lines checked"
        )
        return 1
    print(f"ok: {len(found)} literal blocks, {total} lines survive verbatim")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
