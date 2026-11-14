# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The release step that gathers changelog fragments (RELEASING.md).

It runs a few times a year, on a maintainer's machine, with a tag about to
follow it — so what matters is that it either does the whole thing or
refuses before writing anything, and that a fragment it cannot gather is
found on the pull request that adds it, not on release day.
"""
from __future__ import annotations

import importlib.util
import pytest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

CHANGELOG = """# Changelog

## [Unreleased]

## [0.1.0] — 2026-01-01

### Added

- The first thing.

[Unreleased]: https://example.invalid/p/compare/v0.1.0...HEAD
[0.1.0]: https://example.invalid/p/releases/tag/v0.1.0
"""


def _mod():
    spec = importlib.util.spec_from_file_location(
        "assemble_changelog_under_test", ROOT / "scripts" / "assemble_changelog.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _tree(tmp_path, **frags):
    (tmp_path / "changelog.d").mkdir()
    (tmp_path / "changelog.d" / "README.md").write_text("# Changelog fragments\n")
    (tmp_path / "CHANGELOG.md").write_text(CHANGELOG, encoding="utf-8", newline="\n")
    for name, text in frags.items():
        (tmp_path / "changelog.d" / f"{name}.md").write_text(text, encoding="utf-8")
    return tmp_path


def _snapshot(root):
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file()}


def test_fragments_are_gathered_under_their_headings_in_the_fixed_order(tmp_path):
    root = _tree(
        tmp_path,
        b="### Fixed\n\n- A fix.\n\n### Added\n\n- A second addition.\n",
        a="### Added\n\n- An addition.\n",
        c="### Security\n\n- A hardening.\n",
    )
    assert _mod().assemble(root, "0.2.0", "2026-02-02", "**Intro.**\n") == 3
    text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert text == """# Changelog

## [Unreleased]

## [0.2.0] — 2026-02-02

**Intro.**

### Security

- A hardening.

### Added

- An addition.

- A second addition.

### Fixed

- A fix.

## [0.1.0] — 2026-01-01

### Added

- The first thing.

[Unreleased]: https://example.invalid/p/compare/v0.2.0...HEAD
[0.2.0]: https://example.invalid/p/releases/tag/v0.2.0
[0.1.0]: https://example.invalid/p/releases/tag/v0.1.0
"""


def test_the_fragments_are_deleted_and_the_readme_is_kept(tmp_path):
    root = _tree(tmp_path, a="### Added\n\n- An addition.\n")
    _mod().assemble(root, "0.2.0", "2026-02-02", "")
    assert [p.name for p in (root / "changelog.d").iterdir()] == ["README.md"]


def test_the_changelog_is_written_with_lf_on_every_platform(tmp_path):
    root = _tree(tmp_path, a="### Added\r\n\r\n- Written on Windows.\r\n")
    _mod().assemble(root, "0.2.0", "2026-02-02", "Intro.\n")
    assert b"\r" not in (root / "CHANGELOG.md").read_bytes()


@pytest.mark.parametrize(
    ("frags", "version", "why"),
    [
        ({"a": "### Added\n\n- ok\n", "z": "### Improved\n\n- no such heading\n"},
         "0.2.0", "unknown heading"),
        ({"a": "### Added\n\n- ok\n", "z": "- an entry with no heading\n"},
         "0.2.0", "before the first"),
        ({"a": "### Added\n\n- ok\n", "z": "### Added\n\n"}, "0.2.0", "no entry"),
        ({}, "0.2.0", "no fragments"),
        ({"a": "### Added\n\n- ok\n"}, "0.1.0", "already has"),
        ({"a": "### Added\n\n- ok\n"}, "v0.2.0", "not X.Y.Z"),
    ],
)
def test_a_refusal_leaves_every_file_as_it_was(tmp_path, frags, version, why):
    root = _tree(tmp_path, **frags)
    before = _snapshot(root)
    mod = _mod()
    with pytest.raises(mod.Refused, match=why):
        mod.assemble(root, version, "2026-02-02", "Intro.\n")
    assert _snapshot(root) == before


def test_a_changelog_checked_out_with_crlf_is_refused_not_rewritten(tmp_path):
    root = _tree(tmp_path, a="### Added\n\n- ok\n")
    (root / "CHANGELOG.md").write_bytes(CHANGELOG.replace("\n", "\r\n").encode())
    before = _snapshot(root)
    mod = _mod()
    with pytest.raises(mod.Refused, match="CRLF"):
        mod.assemble(root, "0.2.0", "2026-02-02", "")
    assert _snapshot(root) == before


def test_every_fragment_in_this_tree_can_be_gathered():
    # the same parse the release runs, on every change: a fragment with a
    # heading the release does not know fails here, on its own pull request
    mod = _mod()
    for p in mod.fragments(ROOT):
        mod.parse(p)


def test_the_real_changelog_is_in_the_shape_the_release_step_needs():
    mod = _mod()
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert text.count(mod.UNRELEASED) == 1
    assert mod._LINK.search(text) is not None
