# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Run a consumer's own test suite against this checkout of the package.

    python scripts/consumer_canary.py deps CONSUMER_DIR [--extra NAME ...]
    python scripts/consumer_canary.py run  CONSUMER_DIR --expected FILE

A consumer pins a released version, so a change here that breaks it is
found when it lifts the pin — a release too late. This runs the consumer's
tests against the package as it is on this commit, and compares what fails
with a short ledger of failures that are *expected*: breaks made on purpose,
each with its reason, waiting for the consumer to follow.

``deps`` prints the consumer's requirements without its requirement on this
package, so they can be installed around the checkout instead of over it.

``run`` exits

    0  every failure is in the ledger (entries that now pass are reported
       as warnings: the consumer has caught up, and the entry should go)
    1  a test fails that the ledger does not expect — this commit breaks
       the consumer in a way nobody wrote down
    2  the canary itself did not work: the suite did not run, ran no
       tests, or ran against some other copy of the package

Exit 2 is kept apart on purpose. A canary that reports green because it
tested the released wheel, or collected nothing, is worse than no canary.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = "palimpsests"
_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


class CanaryError(Exception):
    """The canary could not do its job (exit 2), as distinct from a finding."""


def _is_this_package(requirement: str) -> bool:
    m = _NAME.match(requirement)
    return bool(m) and re.sub(r"[-_.]+", "-", m.group(1)).lower() == PACKAGE


def requirements(pyproject: Path, extras: list[str]) -> list[str]:
    """The consumer's requirements, base plus ``extras``, minus this package."""
    project = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]
    wanted = list(project.get("dependencies", []))
    optional = project.get("optional-dependencies", {})
    for extra in extras:
        if extra not in optional:
            raise CanaryError(f"{pyproject}: no extra named '{extra}'")
        wanted += optional[extra]
    return [r for r in wanted if not _is_this_package(r)]


def read_ledger(path: Path) -> dict[str, str]:
    """``test id  # reason`` per line -> {id: reason}. A reason is required:
    an expected failure nobody can explain is an unexpected one."""
    ledger: dict[str, str] = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        test_id, sep, reason = line.partition("#")
        test_id, reason = test_id.strip(), reason.strip()
        if not sep or not reason:
            raise CanaryError(f"{path}:{n}: '{test_id}' has no '# reason'")
        if test_id in ledger:
            raise CanaryError(f"{path}:{n}: '{test_id}' is listed twice")
        ledger[test_id] = reason
    return ledger


def read_junit(path: Path) -> tuple[set[str], set[str]]:
    """(every test that ran, those that failed or errored), as
    ``module.path::name`` — pytest's junit ``classname`` and ``name``."""
    ran: set[str] = set()
    failed: set[str] = set()
    for case in ET.parse(path).getroot().iter("testcase"):
        test_id = f"{case.get('classname')}::{case.get('name')}"
        if case.find("skipped") is not None:
            continue
        ran.add(test_id)
        if case.find("failure") is not None or case.find("error") is not None:
            failed.add(test_id)
    return ran, failed


def classify(
    ran: set[str], failed: set[str], ledger: dict[str, str]
) -> tuple[list[str], list[str], list[str]]:
    """(unexpected failures, ledger entries that now pass, ledger entries
    that name no test that ran)."""
    unexpected = sorted(failed - ledger.keys())
    caught_up = sorted(t for t in ledger if t in ran and t not in failed)
    unknown = sorted(t for t in ledger if t not in ran)
    return unexpected, caught_up, unknown


def package_under_test(python: str) -> Path:
    out = subprocess.run(
        [python, "-c", f"import {PACKAGE}; print({PACKAGE}.__file__)"],
        capture_output=True, text=True, check=False,
    )
    if out.returncode != 0:
        raise CanaryError(f"cannot import {PACKAGE}: {out.stderr.strip()}")
    return Path(out.stdout.strip()).resolve()


def run(consumer: Path, ledger_path: Path) -> int:
    ledger = read_ledger(ledger_path)
    imported = package_under_test(sys.executable)
    if ROOT not in imported.parents:
        raise CanaryError(
            f"the suite would run against {imported}, not this checkout ({ROOT}); "
            "install the checkout with `pip install -e .` before the consumer"
        )
    print(f"package under test: {imported}")
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "junit.xml"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",
             f"--junitxml={report}", "-o", "junit_family=xunit1"],
            cwd=consumer, check=False,
        )
        if not report.is_file():
            raise CanaryError(f"pytest wrote no report (exit {proc.returncode})")
        ran, failed = read_junit(report)
    if not ran:
        raise CanaryError("the consumer's suite ran no tests")
    unexpected, caught_up, unknown = classify(ran, failed, ledger)

    print(f"\nconsumer suite: {len(ran)} ran, {len(failed)} failed, "
          f"{len(ledger)} expected to fail")
    for t in caught_up:
        print(f"::warning::{t} is in the ledger and passes now — remove its line "
              f"from {ledger_path.name}")
    for t in unknown:
        print(f"::warning::{t} is in the ledger and did not run — renamed, removed "
              f"or skipped; check {ledger_path.name}")
    for t in sorted(failed & ledger.keys()):
        print(f"expected: {t}  # {ledger[t]}")
    if unexpected:
        for t in unexpected:
            print(f"::error::{t} fails against this commit and is not in the ledger")
        print(
            "\nThis commit changes something the consumer relies on. Either it "
            "should not, or the break is intended: then add each test above to "
            f"{ledger_path} with its reason, and tell the consumer."
        )
        return 1
    print("no failure outside the ledger")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    deps = sub.add_parser("deps")
    deps.add_argument("consumer", type=Path)
    deps.add_argument("--extra", action="append", default=[])
    runp = sub.add_parser("run")
    runp.add_argument("consumer", type=Path)
    runp.add_argument("--expected", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "deps":
            print("\n".join(requirements(args.consumer / "pyproject.toml", args.extra)))
            return 0
        return run(args.consumer, args.expected)
    except (CanaryError, OSError, ET.ParseError, tomllib.TOMLDecodeError) as e:
        print(f"::error::canary broken: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
