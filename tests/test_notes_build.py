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


def test_a_link_to_a_page_this_site_does_not_have_stops_the_build():
    build = _load()
    known = {"/", "/runbook/", "/runbook/a/", "/air-gapped/"}
    build.check_site_links(
        {"ok": "[a](https://palimpsests.dev/runbook/a/) [b](https://palimpsests.dev/air-gapped/#anchors)"
               " [c](https://palimpsests.dev/) [d](https://example.org/nope/)"},
        known,
    )
    with pytest.raises(ValueError, match="runbook/b/"):
        build.check_site_links({"bad": "[x](https://palimpsests.dev/runbook/b/)"}, known)


def _recipe(slug: str, nxt: str = "") -> str:
    return (f"---\ntitle: {slug}\nslug: {slug}\ngroup: run\norder: 1\nupdated: 2026-11-16\n"
            f"description: d\nnext: {nxt}\n---\n\nbody\n")


def test_runbook_next_must_name_another_runbook_page(tmp_path):
    build = _load()
    (tmp_path / "index.md").write_text(
        "---\ntitle: t\nupdated: 2026-11-16\ndescription: d\n---\n\nbody\n", encoding="utf-8")
    (tmp_path / "a.md").write_text(_recipe("a", "b"), encoding="utf-8")
    (tmp_path / "b.md").write_text(_recipe("b", "a"), encoding="utf-8")
    intro, recipes = build.load_runbook(tmp_path)
    assert intro is not None and [r.slug for r in recipes] == ["a", "b"]
    (tmp_path / "b.md").write_text(_recipe("b", "missing"), encoding="utf-8")
    with pytest.raises(ValueError, match="missing"):
        build.load_runbook(tmp_path)
    (tmp_path / "b.md").write_text(_recipe("b", "b"), encoding="utf-8")
    with pytest.raises(ValueError, match="'next' names no other runbook page"):
        build.load_runbook(tmp_path)


def test_every_runbook_page_is_listed_and_in_the_sitemap():
    build = _load()
    _, recipes = build.load_runbook(ROOT / "runbook")
    assert recipes, "the runbook has pages"
    listing = (ROOT / "site" / "runbook" / "index.html").read_text(encoding="utf-8")
    sitemap = (ROOT / "site" / "sitemap.xml").read_text(encoding="utf-8")
    for r in recipes:
        assert f'href="/runbook/{r.slug}/"' in listing
        assert f"<loc>{r.url}</loc>" in sitemap
