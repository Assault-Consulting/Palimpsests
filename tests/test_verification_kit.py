# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""The verification kit says one thing in each of its three files.

The kit is what an outside implementer holds. Its digests, its list of
values and its list of demos are written by hand in more than one place;
these tests hold them to each other and to the frozen files.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SPEC = Path(__file__).resolve().parents[1] / "docs" / "specs" / "pala-1"
KIT = SPEC / "verification-kit"
README = (KIT / "README.md").read_text(encoding="utf-8")
TEMPLATE = (KIT / "RUN-RECORD-TEMPLATE.md").read_text(encoding="utf-8")
SCRIPT = (KIT / "fetch-inputs.sh").read_text(encoding="utf-8")

INPUTS = ["PALA-1.md", "profiles/robotics.md", "profiles/inference.md", "test-vectors.json"]
#: Frozen with the core: the file on disk is the file at the tag.
FROZEN = ["PALA-1.md", "profiles/robotics.md", "test-vectors.json"]


def _readme_digests() -> dict[str, str]:
    return {name: digest for digest, name in re.findall(r"(?m)^([0-9a-f]{64})  (\S+)$", README)}


def _script_digests() -> dict[str, str]:
    return dict(re.findall(r"(?m)^(\S+) ([0-9a-f]{64})$", SCRIPT))


def test_readme_and_script_pin_the_same_four_inputs() -> None:
    assert list(_readme_digests()) == INPUTS
    assert _readme_digests() == _script_digests()


def test_pinned_digests_are_those_of_the_frozen_files() -> None:
    pinned = _readme_digests()
    for name in FROZEN:
        assert hashlib.sha256((SPEC / name).read_bytes()).hexdigest() == pinned[name], name


def test_the_inference_profile_has_moved_on_and_the_kit_says_so() -> None:
    current = hashlib.sha256((SPEC / "profiles" / "inference.md").read_bytes()).hexdigest()
    assert current != _readme_digests()["profiles/inference.md"]
    assert "revised since" in README


def test_manual_download_links_are_the_four_inputs_at_the_tag() -> None:
    base = "https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/"
    assert re.findall(re.escape(base) + r"(\S+)", README) == INPUTS
    assert 'REF="${PALA1_REF:-pala1-v1.0}"' in SCRIPT


def test_readme_and_template_number_the_same_eleven_values() -> None:
    readme = re.findall(r"(?m)^\| (\d+) \| (?:`([a-z_]+)`|inclusion proof for leaf 7) \|", README)
    template = re.findall(r"(?m)^\| (\d+) \| (?:`([a-z_]+)`|Leaf-7 inclusion proof)", TEMPLATE)
    assert [n for n, _ in readme] == [str(i) for i in range(1, 12)]
    assert readme == template


def test_the_seven_demos_are_the_vectors_own() -> None:
    demos = list(json.loads((SPEC / "test-vectors.json").read_text(encoding="utf-8"))["demos"])
    assert len(demos) == 7
    in_template = re.findall(r"(?m)^\| `([a-z_]+)` \| \| \|$", TEMPLATE)
    assert in_template == demos
    for demo in demos:
        assert f"`{demo}`" in README, demo


def test_every_document_the_kit_puts_off_limits_exists() -> None:
    named = re.findall(r"`\.\./([A-Za-z0-9_.\-/]+)`", README)
    assert {"INDEPENDENT-VERIFICATION.md", "CLARIFICATIONS.md", "independent-runs/"} <= set(named)
    for name in named:
        assert (SPEC / name).exists(), name


def test_template_asks_what_the_readme_requires() -> None:
    for field in ("Read before the run", "Eligibility attestation", "AI assistance"):
        assert f"| {field} |" in TEMPLATE, field
    assert "2026-07-06" in README and "2026-07-06" in TEMPLATE
    assert "do not publish" in TEMPLATE


def test_the_fifth_run_is_in_the_record_the_kit_points_to() -> None:
    record = (SPEC / "INDEPENDENT-VERIFICATION.md").read_text(encoding="utf-8")
    assert "### 5.1 Runs after the freeze" in record
    assert "| Run | #5 " in record
    assert (SPEC / "independent-runs" / "turak" / "RUN-RECORD.md").exists()
