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
    "docs/interop/gen_scitt_statement_vector_v3.py",
    "docs/specs/pala-1/gen_vectors.py",
    "docs/specs/pala-1/profiles/gen_inference_vectors.py",
    "docs/specs/pala-1/gen_consistency_vectors.py",
    "scripts/build_notes.py",
    "scripts/build_compatibility.py",
]
#: Directories of recorded runs: their scripts are records, not generators,
#: and are never edited after the fact.
_RECORDS = ("independent-runs", "dps-reading", "aac-verification")


def test_every_generator_is_on_the_list():
    """The first version of this list missed a generator in docs/interop, and
    the Windows runner found it. Every gen_*.py / build_*.py outside recorded
    runs must be listed, so the next one cannot be missed the same way."""
    found = {
        p.relative_to(REPO).as_posix()
        for pattern in ("gen_*.py", "build_*.py")
        for top in ("docs", "scripts")
        for p in (REPO / top).rglob(pattern)
        if not any(part.startswith(_RECORDS) for part in p.parts)
    }
    assert found == set(GENERATORS)


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


# What a generator writes is only half: a checkout that converts line endings
# (Windows runners default to autocrlf=true) turns the committed LF file into
# CRLF, and the comparison fails the other way. Each generated, byte-compared
# artifact must be exempt from conversion or pinned to LF.
ARTIFACTS = [
    "docs/specs/pala-1/test-vectors.json",
    "docs/specs/pala-1/profiles/inference-vectors.json",
    "docs/specs/pala-1/consistency-vectors.json",
    "docs/interop/scitt-statement-vector.json",
    "docs/interop/scitt-statement-vector-v3.json",
    "site/index.html",
    "site/notes/index.html",
    "site/notes/feed.xml",
    "site/sitemap.xml",
    "site/llms.txt",
    "integrations/COMPATIBILITY.md",
]


@pytest.mark.parametrize("path", ARTIFACTS)
def test_no_checkout_converts_a_generated_artifact(path):
    import shutil
    import subprocess

    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("not a git checkout")
    out = subprocess.run(["git", "-C", str(REPO), "check-attr", "text", "eol", "--", path],
                         capture_output=True, text=True, check=True).stdout
    attrs = {}
    for line in out.splitlines():
        _, name, value = line.split(": ")
        attrs[name] = value
    assert attrs.get("text") == "unset" or attrs.get("eol") == "lf", (path, attrs)
