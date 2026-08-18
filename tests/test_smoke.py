# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Smoke test: the package imports and exposes a version.

Keeps CI green on the bootstrap skeleton. Real contract tests land in
phase 1 alongside the engine Protocol.
"""
from __future__ import annotations

import palimpsests
from importlib.metadata import version as distribution_version


def test_version_is_exposed() -> None:
    assert isinstance(palimpsests.__version__, str)
    assert palimpsests.__version__


def test_version_matches_distribution_metadata() -> None:
    """The constant and pyproject.toml must not drift.

    They did: the 0.8.0 release shipped ``__version__ = "0.7.0"``. The
    assertion above passed the whole time — a non-empty string is a weak
    claim, and the value was wrong.

    This matters beyond tidiness because ``palimpsests.audit.export`` stamps
    the constant into every JSONL export as the producing tool. A stale value
    publishes artifacts that name the wrong verifier, which is a provenance
    defect in a project whose deliverable is a verifiable record.

    Reads the installed distribution metadata rather than parsing
    pyproject.toml: metadata is what pip resolved, and therefore what
    describes the code actually on the machine.
    """
    assert palimpsests.__version__ == distribution_version("palimpsests")
