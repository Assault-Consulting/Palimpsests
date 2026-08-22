# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""U9: the published vectors are loadable from any installed copy.

The round-trip test is the important one: force-include from ``docs/``
is exactly the shape that produces a correct wheel and a broken
sdist-built wheel if ``docs/`` ever leaves the sdist — the classic
"works locally, fails on the release runner". So the test builds the
sdist, builds a wheel FROM the unpacked sdist, and asserts both vector
files inside are byte-identical to the repo's.
"""
from __future__ import annotations

import json
import pytest
import subprocess
import sys
import tarfile
import zipfile
from palimpsests.audit.pala import vectors
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CORE = REPO / "docs" / "specs" / "pala-1" / "test-vectors.json"
INFERENCE = REPO / "docs" / "specs" / "pala-1" / "profiles" / "inference-vectors.json"


def test_available_names_both_sets():
    assert vectors.available() == ("core", "inference")


def test_load_returns_the_published_content():
    core = vectors.load("core")
    inf = vectors.load("inference")
    assert len(core["records"]) == 12
    assert core["chain_head"] == json.loads(CORE.read_text())["chain_head"]
    assert inf["chain_head"] == json.loads(INFERENCE.read_text())["chain_head"]
    # the companion is the profile set: it names its profile and carries
    # the top-level semantics block (decoded r2/r3 expectations, keyed by
    # seq) that a profile-aware reader checks its rendering against
    assert inf["profile"] == "inference"
    kinds = {v.get("kind_name") for v in inf["semantics"].values() if isinstance(v, dict)}
    assert "TOOL_CALL" in kinds


def test_unknown_set_is_a_clean_keyerror():
    with pytest.raises(KeyError):
        vectors.load("nope")


def test_sdist_to_wheel_roundtrip_carries_the_vectors(tmp_path):
    pytest.importorskip("build")
    # 1) sdist from the repo
    subprocess.run(
        [sys.executable, "-m", "build", "--sdist", "--outdir", str(tmp_path)],
        cwd=REPO, check=True, capture_output=True,
    )
    (sdist,) = tmp_path.glob("*.tar.gz")
    with tarfile.open(sdist) as tf:
        tf.extractall(tmp_path / "unpacked", filter="data")
    (srcdir,) = (tmp_path / "unpacked").iterdir()
    # 2) wheel FROM the unpacked sdist — the release runner's path
    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(tmp_path)],
        cwd=srcdir, check=True, capture_output=True,
    )
    (wheel,) = tmp_path.glob("*.whl")
    with zipfile.ZipFile(wheel) as zf:
        packed_core = zf.read("palimpsests/audit/pala/_vectors/core.json")
        packed_inf = zf.read("palimpsests/audit/pala/_vectors/inference.json")
    # 3) byte-identical to the source of truth
    assert packed_core == CORE.read_bytes()
    assert packed_inf == INFERENCE.read_bytes()
