# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""The verification kit says one thing in each of its files.

The kit is what an outside implementer holds. Its digests, its lists of
values and its lists of cases are written by hand in more than one
place; these tests hold them to each other, to the frozen core and to
the r9 profile files.

If a test here fails because ``profiles/inference.md`` or its vectors
changed, read ``inference.md`` section 9.1 first: r1-r9 are not edited in
place. A new revision gets a new track file (kit README, section 5); the
r9 track stays pinned to the files of the 0.15.0 tag.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SPEC = Path(__file__).resolve().parents[1] / "docs" / "specs" / "pala-1"
KIT = SPEC / "verification-kit"
README = (KIT / "README.md").read_text(encoding="utf-8")
PROFILE = (KIT / "PROFILE-R9.md").read_text(encoding="utf-8")
TEMPLATE = (KIT / "RUN-RECORD-TEMPLATE.md").read_text(encoding="utf-8")
PROFILE_TEMPLATE = (KIT / "RUN-RECORD-PROFILE-TEMPLATE.md").read_text(encoding="utf-8")
SCRIPT = (KIT / "fetch-inputs.sh").read_text(encoding="utf-8")

CORE_INPUTS = ["PALA-1.md", "profiles/robotics.md", "profiles/inference.md", "test-vectors.json"]
#: Frozen with the core: the file on disk is the file at the tag.
CORE_FROZEN = ["PALA-1.md", "profiles/robotics.md", "test-vectors.json"]
PROFILE_INPUTS = [
    "PALA-1.md",
    "test-vectors.json",
    "profiles/inference.md",
    "profiles/inference-vectors.json",
    "profiles/payload-digest-vectors.json",
    "profiles/retention-continuation.md",
]


def _doc_digests(text: str) -> dict[str, str]:
    return {name: digest for digest, name in re.findall(r"(?m)^([0-9a-f]{64})  (\S+)$", text)}


def _script_digests(track: str) -> dict[str, str]:
    block = SCRIPT.split(f"\n{track})\n", 1)[1].split(";;", 1)[0]
    return dict(re.findall(r"(?m)^(\S+) ([0-9a-f]{64})$", block))


def _sha256(name: str) -> str:
    return hashlib.sha256((SPEC / name).read_bytes()).hexdigest()


# --- the core track ---------------------------------------------------------


def test_core_readme_and_script_pin_the_same_four_inputs() -> None:
    assert list(_doc_digests(README)) == CORE_INPUTS
    assert _doc_digests(README) == _script_digests("core")
    assert 'REF="${PALA1_REF:-pala1-v1.0}"' in SCRIPT


def test_core_digests_are_those_of_the_frozen_files() -> None:
    pinned = _doc_digests(README)
    for name in CORE_FROZEN:
        assert _sha256(name) == pinned[name], name


def test_core_track_carries_the_freeze_day_profile_not_the_current_one() -> None:
    assert _sha256("profiles/inference.md") != _doc_digests(README)["profiles/inference.md"]
    assert "as it stood on the freeze day" in README


def test_core_manual_links_are_the_four_inputs_at_the_format_tag() -> None:
    base = "https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/pala1-v1.0/docs/specs/pala-1/"
    assert re.findall(re.escape(base) + r"(\S+)", README) == CORE_INPUTS


def test_core_readme_and_template_number_the_same_eleven_values() -> None:
    readme = re.findall(r"(?m)^\| (\d+) \| (?:`([a-z_]+)`|inclusion proof for leaf 7) \|", README)
    template = re.findall(r"(?m)^\| (\d+) \| (?:`([a-z_]+)`|Leaf-7 inclusion proof)", TEMPLATE)
    assert [n for n, _ in readme] == [str(i) for i in range(1, 12)]
    assert readme == template


def test_core_demos_are_the_vectors_own() -> None:
    demos = list(json.loads((SPEC / "test-vectors.json").read_text(encoding="utf-8"))["demos"])
    assert len(demos) == 7
    assert re.findall(r"(?m)^\| `([a-z_]+)` \| \| \|$", TEMPLATE) == demos
    for demo in demos:
        assert f"`{demo}`" in README, demo


# --- the profile track ------------------------------------------------------


def test_profile_task_and_script_pin_the_same_six_inputs() -> None:
    assert list(_doc_digests(PROFILE)) == PROFILE_INPUTS
    assert _doc_digests(PROFILE) == _script_digests("profile")
    assert 'REF="${PALA1_REF:-v0.15.0}"' in SCRIPT
    assert "/Palimpsests/v0.15.0/docs/specs/pala-1/" in PROFILE


def test_profile_digests_are_those_of_the_files_on_disk() -> None:
    """r9 is not edited in place: the tag's bytes are still the tree's."""
    pinned = _doc_digests(PROFILE)
    for name in PROFILE_INPUTS:
        assert _sha256(name) == pinned[name], name


def test_profile_track_reads_the_revision_the_vectors_declare() -> None:
    vectors = json.loads((SPEC / "profiles" / "inference-vectors.json").read_text(encoding="utf-8"))
    assert vectors["profile_revision"] == "r9"
    assert "revision\nr9" in PROFILE or "revision r9" in PROFILE.replace("\n", " ")
    assert "r9 is the revision Palimpsests 1.0 implements" in (
        SPEC / "profiles" / "inference.md"
    ).read_text(encoding="utf-8").replace("\n", " ")


def test_profile_pass_bar_states_what_the_vectors_hold() -> None:
    vectors = json.loads((SPEC / "profiles" / "inference-vectors.json").read_text(encoding="utf-8"))
    records = vectors["records"]
    flat = PROFILE.replace("\n", " ")
    assert len(records) == 32 and "32 records" in flat
    assert sum("body_hex" in r for r in records) == 22 and "the 22 records with a body" in flat

    boots = [0] + [r["seq"] for r in records if r["record_type"] == "0x0002"][1:]
    assert boots == [0, 24, 27] and "they begin at `seq` 0, 24 and 27" in flat

    numbered = [key for key in vectors["semantics"] if key.isdigit()]
    assert f"{len(numbered)} entries — `seq` {', '.join(numbered)}" in flat

    for key in numbered:
        entry = vectors["semantics"][key]
        if "ref_seq" in entry:
            assert records[entry["ref_seq"]]["record_hash"] == entry["ref_hash"], key

    rules = [k for k in vectors["semantics"] if not k.isdigit() and k != "$comment"]
    assert rules == re.findall(r"(?m)^\| `([a-z_]+)` \| \| \|$", PROFILE_TEMPLATE)[-len(rules):]
    for rule in rules:
        assert f"`{rule}`" in PROFILE, rule


def test_profile_pass_bar_counts_the_payload_digest_cases() -> None:
    digests = json.loads(
        (SPEC / "profiles" / "payload-digest-vectors.json").read_text(encoding="utf-8")
    )
    cases, deep = digests["cases"], digests["deep_cases"]
    with_digest = sum("sha256" in c for c in cases + deep)
    without = sum("sha256" not in c for c in cases + deep)
    assert (len(cases), len(deep)) == (33, 4)
    assert digests["counts"] == {"digested": with_digest, "no_digest": without} == {
        "digested": 22,
        "no_digest": 15,
    }
    flat = PROFILE.replace("\n", " ")
    assert "33 cases and 4 deep cases" in flat
    assert "22 digested" in flat and "15 with none" in flat
    assert "37 JSON values: 22 with a digest, 15 with none" in flat


def test_profile_task_and_template_list_the_same_items_and_cases() -> None:
    items = re.findall(r"(?m)^\| (P\d) \|", PROFILE)
    assert items == [f"P{i}" for i in range(1, 9)]
    assert re.findall(r"(?m)^\| (P\d) \|", PROFILE_TEMPLATE) == items

    cases = re.findall(r"(?m)^\| `([a-z_]+)` \| [a-z`]", PROFILE)
    assert cases == [
        "unclosed_boot",
        "last_boot_unclosed",
        "continuation_wrong_predecessor",
        "unknown_kind",
    ]
    assert re.findall(r"(?m)^\| `([a-z_]+)` \| \| \|$", PROFILE_TEMPLATE)[: len(cases)] == cases


# --- both -------------------------------------------------------------------


def test_every_document_the_kit_names_exists() -> None:
    named = re.findall(r"`\.\./([A-Za-z0-9_.\-/]+)`", README + PROFILE)
    assert {"INDEPENDENT-VERIFICATION.md", "CLARIFICATIONS.md", "independent-runs/"} <= set(named)
    for name in named:
        assert (SPEC / name.replace("<name>/", "")).exists(), name
    for local in re.findall(r"\]\(([A-Z0-9\-]+\.md)\)", README + PROFILE):
        assert (KIT / local).exists(), local


def test_templates_ask_what_the_readme_requires() -> None:
    for template in (TEMPLATE, PROFILE_TEMPLATE):
        for field in ("Other reading", "Eligibility attestation", "AI assistance"):
            assert f"| {field} |" in template, field
        assert "2026-07-06" in template
        assert "do not publish" in template
        assert "kit README §1.3" in template and "kit README §1.5" in template
    assert "### 1.3 What you may read, and must list" in README
    assert "### 1.5 AI assistance" in README
    assert "2026-07-06" in README


def test_the_website_and_the_draft_are_listed_not_forbidden() -> None:
    must_not = README.split("### 1.2", 1)[1].split("### 1.3", 1)[0]
    may = README.split("### 1.3", 1)[1].split("### 1.4", 1)[0]
    assert "Internet-Draft" not in must_not and "website" not in must_not
    assert "Internet-Draft" in may and "website" in may
    assert "`palimpsests` package" in must_not


def test_the_record_has_a_place_for_each_kind_of_run() -> None:
    record = (SPEC / "INDEPENDENT-VERIFICATION.md").read_text(encoding="utf-8")
    assert "### 5.1 Runs after the freeze" in record
    assert "| Run | #5 " in record
    assert (SPEC / "independent-runs" / "turak" / "RUN-RECORD.md").exists()
    assert "## 8. Profile runs — the inference profile" in record
    assert "verification-kit/PROFILE-R9.md" in record
    assert "No profile run is on record" in record
