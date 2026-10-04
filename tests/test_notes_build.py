# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The /notes/ section is generated from notes/*.md; the committed site must match a fresh build."""
from __future__ import annotations

import filecmp
import importlib.util
import pytest
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "build_notes", ROOT / "scripts" / "build_notes.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(module)
    return module


def test_committed_site_matches_a_fresh_build(tmp_path):
    build = _load()
    site = tmp_path / "site"
    shutil.copytree(ROOT / "site", site)
    build.build(ROOT / "notes", site)
    for path in sorted(site.rglob("*")):
        if path.is_file():
            committed = ROOT / "site" / path.relative_to(site)
            assert committed.exists(), f"{committed} is generated but not committed"
            assert filecmp.cmp(path, committed, shallow=False), (
                f"{committed} is stale: run python3 scripts/build_notes.py"
            )


def test_inline_markup_escapes_html_and_leaves_code_spans_alone():
    build = _load()
    out = build.inline("a <b> & `x **y** <z>` and **bold** [l](https://e.x/?a=1&b=2)")
    assert "a &lt;b&gt; &amp;" in out
    assert "<code>x **y** &lt;z&gt;</code>" in out
    assert "<b>bold</b>" in out
    assert '<a href="https://e.x/?a=1&amp;b=2">l</a>' in out


def test_render_rejects_what_the_dialect_does_not_have():
    build = _load()
    with pytest.raises(ValueError):
        build.render("# a top-level heading")
    with pytest.raises(ValueError):
        build.render("```\nunclosed")
