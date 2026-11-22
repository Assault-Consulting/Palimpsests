# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""The release workflow and RELEASING.md say the same thing about provenance.

Text checks only: the workflow runs for the first time on a tag, so what can
be held here is its shape — which jobs wait for which — and that the asset
the document tells a reader to download is the one the workflow uploads.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
RELEASING = (ROOT / "RELEASING.md").read_text(encoding="utf-8")
ASSET = "palimpsests.intoto.jsonl"


def _jobs() -> dict[str, str]:
    body = WORKFLOW.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([a-z][a-z0-9_-]*):\n", body)
    return dict(zip(parts[1::2], parts[2::2], strict=True))


def _needs(job: str) -> set[str]:
    match = re.search(r"(?m)^    needs: (.+)$", _jobs()[job])
    if match is None:
        return set()
    return set(re.findall(r"[a-z][a-z0-9_-]*", match.group(1)))


def test_nothing_waits_for_the_provenance_job() -> None:
    jobs = _jobs()
    assert "provenance" in jobs
    for name in jobs:
        assert "provenance" not in _needs(name), name


def test_provenance_runs_after_the_release_exists() -> None:
    assert _needs("provenance") == {"build", "release"}


def test_publish_job_is_untouched_by_provenance() -> None:
    publish = _jobs()["publish"]
    assert _needs("publish") == {"build"}
    assert "attestations" not in publish
    assert "contents: write" not in publish


def test_provenance_job_permissions_are_the_three_it_uses() -> None:
    block = re.search(r"(?ms)^    permissions:\n(.*?)^    steps:", _jobs()["provenance"])
    assert block is not None
    granted = set(re.findall(r"(?m)^      ([a-z-]+): write$", block.group(1)))
    assert granted == {"id-token", "attestations", "contents"}


def test_attestation_action_is_pinned_by_commit() -> None:
    match = re.search(r"actions/attest-build-provenance@([0-9a-f]+)", WORKFLOW)
    assert match is not None
    assert len(match.group(1)) == 40


def test_both_distributions_are_subjects() -> None:
    provenance = _jobs()["provenance"]
    assert "dist/*.whl" in provenance
    assert "dist/*.tar.gz" in provenance


def test_document_names_the_asset_the_workflow_uploads() -> None:
    assert ASSET in _jobs()["provenance"]
    assert ASSET in RELEASING
    assert ASSET not in _jobs()["release"]


def _run_blocks(job_text: str) -> list[str]:
    """The shell of every `run:` step, whitespace-normalised."""
    blocks = re.findall(r"(?ms)^        run: \|\n(.*?)(?=^      - |^  [a-z]|\Z)", job_text)
    return [" ".join(block.split()) for block in blocks]


def test_ci_rehearses_the_build_job_command_for_command() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    body = ci.split("\njobs:\n", 1)[1]
    parts = re.split(r"(?m)^  ([a-z][a-z0-9_-]*):\n", body)
    ci_jobs = dict(zip(parts[1::2], parts[2::2], strict=True))
    rehearsal = ci_jobs["release-rehearsal"]
    build = _jobs()["build"]
    assert _run_blocks(build)
    assert _run_blocks(rehearsal) == _run_blocks(build)
    python = r'python-version: "([0-9.]+)"'
    assert re.findall(python, rehearsal) == re.findall(python, build)
    assert "release-rehearsal" in ci_jobs["ci-complete"]


def test_release_lock_pins_what_an_older_python_needs() -> None:
    lock = (ROOT / ".github" / "requirements" / "release.txt").read_text(encoding="utf-8")
    pinned = set(re.findall(r"(?m)^([a-z0-9-]+)==", lock))
    assert "typing-extensions" in pinned
