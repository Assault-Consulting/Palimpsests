# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Every deprecation is listed, warns, and still works.

A name on its way out is a promise with a date: it resolves until the
release the table names, and using it says what to use instead. This holds
the table in ``docs/INTEGRATION-SURFACE.md`` to the code in both
directions — a deprecation in the code that the table does not list fails
here, and so does a row the code no longer backs.
"""
from __future__ import annotations

import importlib
import pytest
import re
import subprocess
import sys
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOC = (ROOT / "docs" / "INTEGRATION-SURFACE.md").read_text(encoding="utf-8")

#: dotted name -> (deprecated in, removed in, replacement in the same module)
DEPRECATED = {
    "palimpsests.audit.pala.scitt.check_statement_against_head":
        ("0.15", "1.0", "verify_statement"),
    "palimpsests.cli.EXIT_TAMPERED": ("0.15", "1.0", "EXIT_VIOLATION"),
}


def _table_rows() -> dict[str, tuple[str, str, str]]:
    section = DOC.split("## Deprecations", 1)[1].split("\n## ", 1)[0]
    rows = {}
    for line in section.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 5 and cells[0].startswith("`palimpsests."):
            rows[cells[0].strip("`")] = (cells[1], cells[2], cells[3].strip("`"))
    return rows


def test_the_table_is_the_list():
    assert _table_rows() == DEPRECATED


def test_no_deprecation_in_the_code_is_missing_from_the_table():
    warned = []
    for path in sorted((ROOT / "src" / "palimpsests").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        warned += [path.name] * len(re.findall(r"^\s+DeprecationWarning,$", text, re.M))
    assert sorted(warned) == ["cli.py", "scitt.py"], (
        "a DeprecationWarning was added or removed: list it in DEPRECATED and in "
        "the Deprecations table of docs/INTEGRATION-SURFACE.md")


def _use(dotted: str) -> None:
    module_name, name = dotted.rsplit(".", 1)
    obj = getattr(importlib.import_module(module_name), name)
    if callable(obj):
        try:
            obj(b"not a statement", None, b"\x00" * 32)
        except ValueError:
            pass  # it refuses the input after it has warned


@pytest.mark.parametrize("dotted", sorted(DEPRECATED))
def test_using_it_says_since_when_until_when_and_what_instead(dotted):
    since, removed, replacement = DEPRECATED[dotted]
    module_name, name = dotted.rsplit(".", 1)
    assert hasattr(importlib.import_module(module_name), replacement)
    with pytest.warns(DeprecationWarning) as caught:
        _use(dotted)
    (message,) = {str(w.message) for w in caught}
    assert name in message and replacement in message
    assert f"deprecated since {since}" in message and f"removed in {removed}" in message


def test_the_old_exit_code_name_resolves_warns_and_is_the_same_number():
    from palimpsests import cli

    with pytest.warns(DeprecationWarning, match="EXIT_VIOLATION"):
        old = cli.EXIT_TAMPERED
    assert old == cli.EXIT_VIOLATION == 1
    with pytest.warns(DeprecationWarning):
        from palimpsests.cli import EXIT_TAMPERED  # noqa: F401
    with pytest.raises(AttributeError):
        cli.EXIT_NO_SUCH_NAME  # noqa: B018
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # the names in use warn about nothing
        assert (cli.EXIT_VERIFIED, cli.EXIT_VIOLATION, cli.EXIT_PARTIAL,
                cli.EXIT_UNREADABLE) == (0, 1, 2, 3)


def test_the_package_itself_uses_no_deprecated_name():
    """Importing everything and running the CLI's help under
    ``-W error::DeprecationWarning`` — the package must not trip its own
    warnings."""
    code = (
        "import palimpsests.cli, palimpsests.audit.pala.scitt, palimpsests.audit.report;"
        "import palimpsests.audit.reader, palimpsests.audit.pala.bundle"
    )
    done = subprocess.run(
        [sys.executable, "-W", "error::DeprecationWarning", "-c", code],
        capture_output=True, text=True, check=False)
    assert done.returncode == 0, done.stderr
    used = []
    for path in sorted((ROOT / "src" / "palimpsests").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for dotted in DEPRECATED:
            name = dotted.rsplit(".", 1)[1]
            # its own definition, its warning text and __all__ aside
            uses = [ln for ln in text.splitlines()
                    if re.search(rf"\b{name}\(", ln) and not ln.lstrip().startswith("def ")]
            used += [(path.name, ln.strip()) for ln in uses]
    assert used == []
