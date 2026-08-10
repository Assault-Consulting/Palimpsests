# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""OpenSSF Gold coverage gate: statement >= 90%, branch >= 80%.

Reads ``coverage.json`` (from ``pytest --cov-report=json``) and exits
non-zero if either bar is missed. Both criteria are checked together so
neither can regress silently behind the other.

The gate sits at the OpenSSF criterion bars (``test_statement_coverage90``,
``test_branch_coverage80``). The internal aspiration is branch 82%+; the
gate is kept at the criterion bar so a single refactor landing before more
tests do not block unrelated work.
"""

from __future__ import annotations

import json
import sys

STATEMENT_MIN = 90.0
BRANCH_MIN = 80.0
REPORT = "coverage.json"


def main() -> int:
    with open(REPORT) as fh:
        totals = json.load(fh)["totals"]

    statements = totals["num_statements"]
    stmt = 100.0 * totals["covered_lines"] / statements if statements else 100.0
    branches = totals["num_branches"]
    branch = (
        100.0 * (branches - totals["missing_branches"]) / branches
        if branches
        else 100.0
    )

    print(
        f"statement {stmt:.2f}% (gate {STATEMENT_MIN:.0f}%)   "
        f"branch {branch:.2f}% (gate {BRANCH_MIN:.0f}%)"
    )

    failures = []
    if stmt < STATEMENT_MIN:
        failures.append(f"statement {stmt:.2f}% < {STATEMENT_MIN:.0f}%")
    if branch < BRANCH_MIN:
        failures.append(f"branch {branch:.2f}% < {BRANCH_MIN:.0f}%")

    if failures:
        print("coverage gate FAILED:", "; ".join(failures))
        return 1

    print("OpenSSF Gold coverage gate passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
