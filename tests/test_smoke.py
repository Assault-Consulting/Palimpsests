"""Smoke test: the package imports and exposes a version.

Keeps CI green on the bootstrap skeleton. Real contract tests land in
phase 1 alongside the engine Protocol.
"""
from __future__ import annotations

import palimpsests


def test_version_is_exposed() -> None:
    assert isinstance(palimpsests.__version__, str)
    assert palimpsests.__version__
