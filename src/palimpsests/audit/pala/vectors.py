# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The published PALA-1 test vectors, loadable from any installed copy.

A vector set reachable only by cloning the repository is checkable only
by people who already have it — close to the opposite of what publishing
one is for. The wheel therefore carries both published files (the
envelope set and the profile companion), placed at build time from
``docs/specs/pala-1/`` — the single source of truth in git — and this
module is the one canonical way to read them, so no consumer guesses
paths inside a wheel.

``importlib.resources`` rather than ``__file__``: the latter breaks under
zipimport or in a frozen build, which is exactly where a self-check
matters most. A plain source checkout (including an editable install,
where build-time includes do not materialize) falls back to the repo
files themselves — same bytes, per the packaging round-trip test.
"""
from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

_FILES = {"core": "core.json", "inference": "inference.json"}

_REPO_PATHS = {
    "core": ("docs", "specs", "pala-1", "test-vectors.json"),
    "inference": ("docs", "specs", "pala-1", "profiles", "inference-vectors.json"),
}


def available() -> tuple[str, ...]:
    """The vector-set names ``load`` accepts."""
    return tuple(sorted(_FILES))


def load(name: str = "core") -> dict:
    """Return the published vector set ``name`` ("core" or "inference")."""
    try:
        filename = _FILES[name]
    except KeyError:
        raise KeyError(
            f"unknown vector set {name!r}; available: {', '.join(available())}"
        ) from None

    ref = resources.files("palimpsests.audit.pala").joinpath("_vectors", filename)
    try:
        if ref.is_file():
            return json.loads(ref.read_text(encoding="utf-8"))
    except (OSError, ModuleNotFoundError):
        pass

    # Source checkout / editable install: the repo files are the same
    # bytes the wheel would carry (the round-trip test pins this).
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent.joinpath(*_REPO_PATHS[name])
        if candidate.is_file():
            return json.loads(candidate.read_text(encoding="utf-8"))
    raise FileNotFoundError(
        f"vector set {name!r} not found in the package or the source tree"
    )
