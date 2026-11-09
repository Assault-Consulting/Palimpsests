# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Every generator of a committed, byte-compared artifact writes LF.

Measured on Windows during the 0.14.0 release: a generator that writes text
with the platform's newline produces CRLF there, and the regenerated file no
longer equals the committed one — for the test vectors, whose SHA-256 digests
are pinned in recorded verification runs, that would break published digests
if committed. Linux cannot show the CRLF, so the rule is checked in the
source: every text write in these generators names its ``newline``.
"""
from __future__ import annotations

import ast
import pytest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GENERATORS = [
    "docs/specs/pala-1/gen_vectors.py",
    "docs/specs/pala-1/profiles/gen_inference_vectors.py",
    "docs/specs/pala-1/gen_consistency_vectors.py",
    "scripts/build_notes.py",
    "scripts/build_compatibility.py",
]


def _text_writes(tree: ast.AST):
    """``x.write_text(...)`` calls and ``open(..., "w"...)`` calls."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        if isinstance(f, ast.Attribute) and f.attr == "write_text":
            yield node
        elif isinstance(f, ast.Name) and f.id == "open" and len(node.args) >= 2:
            mode = node.args[1]
            if isinstance(mode, ast.Constant) and "w" in str(mode.value) \
                    and "b" not in str(mode.value):
                yield node


@pytest.mark.parametrize("path", GENERATORS)
def test_every_text_write_names_its_newline(path):
    tree = ast.parse((REPO / path).read_text(encoding="utf-8"))
    writes = list(_text_writes(tree))
    assert writes, f"{path}: no text write found — has the generator moved?"
    for call in writes:
        kws = {k.arg: k.value for k in call.keywords}
        assert "newline" in kws, f"{path}:{call.lineno} writes text with the platform newline"
        assert isinstance(kws["newline"], ast.Constant) and kws["newline"].value == "\n", (
            f"{path}:{call.lineno}")
