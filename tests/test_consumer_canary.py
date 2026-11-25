# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The consumer canary's own logic (scripts/consumer_canary.py).

The canary runs someone else's test suite, so what is tested here is the
part that decides: which requirements are installed around the checkout,
what the ledger of expected failures means, and which of three outcomes a
run is. A canary that is green for the wrong reason is the failure to fear.
"""
from __future__ import annotations

import importlib.util
import pytest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LEDGER = ROOT / ".github" / "consumer-canary" / "auditor-expected.txt"


@pytest.fixture(scope="module")
def canary():
    spec = importlib.util.spec_from_file_location(
        "consumer_canary_under_test", ROOT / "scripts" / "consumer_canary.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_the_consumers_pin_on_this_package_is_left_out(canary, tmp_path):
    (tmp_path / "pyproject.toml").write_text('''
[project]
name = "consumer"
dependencies = [
    "fastapi>=0.115",
    "palimpsests[pala]>=0.14.1,<0.15",
    "Palimpsests_extra_tools>=1",
]
[project.optional-dependencies]
dev = ["pytest>=8", "palimpsests[pkcs11]>=0.14.1,<0.15"]
report = ["reportlab>=4.2"]
''', encoding="utf-8")
    pyproject = tmp_path / "pyproject.toml"
    assert canary.requirements(pyproject, []) == ["fastapi>=0.115", "Palimpsests_extra_tools>=1"]
    assert canary.requirements(pyproject, ["dev"])[-1] == "pytest>=8"
    with pytest.raises(canary.CanaryError, match="no extra"):
        canary.requirements(pyproject, ["nope"])


def test_the_checkout_gets_the_extras_the_consumer_asks_for(canary, tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('''
[project]
name = "consumer"
dependencies = [
    "fastapi>=0.115",
    "palimpsests[pala, SCITT]>=0.15,<0.16",
    "palimpsests_extra_tools[other]>=1",
]
[project.optional-dependencies]
dev = ["pytest>=8"]
pkcs11 = ["Palimpsests[pkcs11]>=0.15,<0.16"]
''', encoding="utf-8")
    assert canary.package_extras(pyproject, []) == ["pala", "scitt"]
    assert canary.package_extras(pyproject, ["dev"]) == ["pala", "scitt"]
    assert canary.package_extras(pyproject, ["pkcs11"]) == ["pala", "pkcs11", "scitt"]
    with pytest.raises(canary.CanaryError, match="no extra"):
        canary.package_extras(pyproject, ["nope"])


def test_a_consumer_that_asks_for_no_extra_gets_none(canary, tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "consumer"\ndependencies = ["palimpsests>=0.15"]\n', encoding="utf-8"
    )
    assert canary.package_extras(pyproject, []) == []


def test_an_extra_this_checkout_does_not_define_breaks_the_canary(canary, tmp_path):
    package = tmp_path / "pyproject.toml"
    package.write_text(
        '[project]\nname = "palimpsests"\n[project.optional-dependencies]\npala = []\n',
        encoding="utf-8",
    )
    canary.check_extras_exist(["pala"], package)
    with pytest.raises(canary.CanaryError, match="does not define: scitt"):
        canary.check_extras_exist(["pala", "scitt"], package)


def test_the_workflow_installs_the_checkout_with_the_consumers_extras():
    from pathlib import Path

    workflow = (
        Path(__file__).resolve().parents[1] / ".github" / "workflows" / "consumer-canary.yml"
    ).read_text(encoding="utf-8")
    assert "consumer_canary.py extras _consumer/auditor/sidecar --extra dev" in workflow
    assert 'pip install -e ".${extras:+[${extras}]}"' in workflow
    assert 'pip install -e ".[pala]"' not in workflow


def test_a_ledger_line_needs_a_reason(canary, tmp_path):
    f = tmp_path / "l.txt"
    f.write_text("# a comment\n\ntests.a::test_x  # the report is /2 now\n", encoding="utf-8")
    assert canary.read_ledger(f) == {"tests.a::test_x": "the report is /2 now"}
    for bad in ("tests.a::test_x\n", "tests.a::test_x  #\n",
                "tests.a::t  # one\ntests.a::t  # two\n"):
        f.write_text(bad, encoding="utf-8")
        with pytest.raises(canary.CanaryError):
            canary.read_ledger(f)


JUNIT = """<?xml version="1.0"?>
<testsuites><testsuite>
  <testcase classname="tests.a" name="test_ok"/>
  <testcase classname="tests.a" name="test_fails"><failure message="x">t</failure></testcase>
  <testcase classname="tests.b" name="test_errors"><error message="x">t</error></testcase>
  <testcase classname="tests.b" name="test_skipped"><skipped message="x"/></testcase>
  <testcase classname="tests.b" name="test_param[a-b]"/>
</testsuite></testsuites>"""


def test_the_report_is_read_as_ran_and_failed(canary, tmp_path):
    f = tmp_path / "j.xml"
    f.write_text(JUNIT, encoding="utf-8")
    ran, failed = canary.read_junit(f)
    assert failed == {"tests.a::test_fails", "tests.b::test_errors"}
    assert ran == failed | {"tests.a::test_ok", "tests.b::test_param[a-b]"}  # skipped: not run


def test_the_three_things_a_ledger_can_be_against_a_run(canary):
    ran = {"t::ok", "t::fails", "t::listed_fails", "t::listed_passes"}
    failed = {"t::fails", "t::listed_fails"}
    ledger = {"t::listed_fails": "r", "t::listed_passes": "r", "t::gone": "r"}
    unexpected, caught_up, unknown = canary.classify(ran, failed, ledger)
    assert unexpected == ["t::fails"]  # the one that fails the check
    assert caught_up == ["t::listed_passes"]  # a warning: remove the line
    assert unknown == ["t::gone"]  # a warning: renamed, removed or skipped


def test_the_committed_ledger_parses_and_explains_every_line(canary):
    ledger = canary.read_ledger(LEDGER)
    for test_id, reason in ledger.items():
        assert "::" in test_id and len(reason) > 30, test_id


def test_a_run_against_another_copy_of_the_package_is_refused(canary, tmp_path, monkeypatch):
    """Green because the released wheel was tested is the outcome to rule out."""
    ledger = tmp_path / "l.txt"
    ledger.write_text("", encoding="utf-8")
    monkeypatch.setattr(
        canary, "package_under_test",
        lambda _py: Path("/somewhere/site-packages/palimpsests/__init__.py"))
    with pytest.raises(canary.CanaryError, match="not this checkout"):
        canary.run(tmp_path, ledger)
    assert canary.main(["run", str(tmp_path), "--expected", str(ledger)]) == 2


def test_a_suite_that_runs_nothing_is_a_broken_canary_not_a_green_one(canary, tmp_path):
    (tmp_path / "test_nothing.py").write_text("# no tests here\n", encoding="utf-8")
    ledger = tmp_path / "l.txt"
    ledger.write_text("", encoding="utf-8")
    assert canary.main(["run", str(tmp_path), "--expected", str(ledger)]) == 2


def test_a_real_run_fails_only_on_what_the_ledger_does_not_list(canary, tmp_path):
    suite = tmp_path / "suite"
    suite.mkdir()
    (suite / "test_c.py").write_text(
        "def test_ok():\n    pass\n\ndef test_known():\n    assert False\n", encoding="utf-8")
    ledger = tmp_path / "l.txt"
    ledger.write_text("test_c::test_known  # broken on purpose, for this test\n",
                      encoding="utf-8")
    assert canary.main(["run", str(suite), "--expected", str(ledger)]) == 0
    ledger.write_text("", encoding="utf-8")
    assert canary.main(["run", str(suite), "--expected", str(ledger)]) == 1
