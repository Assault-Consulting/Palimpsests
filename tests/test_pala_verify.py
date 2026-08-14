# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for §7.1 chain-start semantics (spec defect #4)
plus edge-case vectors: empty log and single-record log (issue #131)."""

from __future__ import annotations

from palimpsests.audit.pala import iter_records, verify_headers
from palimpsests.audit.pala.codec import ZERO32
from palimpsests.audit.pala_writer import PalaWriter
from pathlib import Path

# ── edge-case: empty log (zero records) ────────────────────────────────


def test_empty_log_verify_headers_returns_chain_ok():
    """An empty chain has no breaks, gaps, or violations — chain_ok is True."""
    res = verify_headers([])
    assert res.chain_ok is True
    assert res.count == 0
    assert res.head == ZERO32
    assert res.breaks == []
    assert res.gaps == []
    assert res.violations == []
    assert res.uninterpretable == []
    assert res.complete_to_anchor is None


def test_empty_log_cli_exits_partial(tmp_path):
    """CLI over an empty file: 0 records, PARTIAL (no anchor supplied)."""
    from palimpsests.cli import app
    from typer.testing import CliRunner

    runner = CliRunner()
    p = tmp_path / "empty.pala"
    p.write_bytes(b"")
    result = runner.invoke(app, ["pala", "verify", str(p)])
    assert result.exit_code == 2  # PARTIAL
    assert "0 records" in result.output
    assert "chain intact" in result.output
    assert "NOT CHECKED" in result.output


def test_empty_log_json_output(tmp_path):
    """JSON output for an empty log has the expected shape."""
    import json as _json
    from palimpsests.cli import app
    from typer.testing import CliRunner

    runner = CliRunner()
    p = tmp_path / "empty.pala"
    p.write_bytes(b"")
    result = runner.invoke(app, ["pala", "verify", str(p), "--json"])
    assert result.exit_code == 2
    payload = _json.loads(result.output)
    assert payload["verdict"] == "partial"
    assert payload["records"] == 0
    assert payload["first_violation"] is None
    assert payload["counts"]["records"] == 0
    assert payload["consistency"]["ok"] is True
    assert payload["completeness"]["checked"] is False
    assert payload["exit_code"] == 2


# ── edge-case: single-record log (GENESIS only) ────────────────────────


def _single_genesis_container(tmp_path) -> Path:
    """Write a single GENESIS record and return the path."""
    p = tmp_path / "single.pala"
    w = PalaWriter(p)
    w.genesis()
    w.close()
    return p


def test_single_record_verify_headers_returns_chain_ok(tmp_path):
    """A single GENESIS with prev_hash=0 is a valid one-record chain."""
    p = _single_genesis_container(tmp_path)
    data = p.read_bytes()
    headers = [hb for hb, _ in iter_records(data)]
    res = verify_headers(headers)
    assert res.chain_ok is True
    assert res.count == 1
    assert res.head != ZERO32  # head is the record_hash of the GENESIS
    assert res.breaks == []
    assert res.gaps == []
    assert res.violations == []
    assert res.uninterpretable == []
    assert res.complete_to_anchor is None


def test_single_record_cli_exits_partial(tmp_path):
    """CLI over a single-record file: 1 record, PARTIAL (no anchor)."""
    from palimpsests.cli import app
    from typer.testing import CliRunner

    runner = CliRunner()
    p = _single_genesis_container(tmp_path)
    result = runner.invoke(app, ["pala", "verify", str(p)])
    assert result.exit_code == 2  # PARTIAL
    assert "1 records" in result.output
    assert "chain intact" in result.output
    assert "NOT CHECKED" in result.output


def test_single_record_json_output(tmp_path):
    """JSON output for a single-record log has the expected shape."""
    import json as _json
    from palimpsests.cli import app
    from typer.testing import CliRunner

    runner = CliRunner()
    p = _single_genesis_container(tmp_path)
    result = runner.invoke(app, ["pala", "verify", str(p), "--json"])
    assert result.exit_code == 2
    payload = _json.loads(result.output)
    assert payload["verdict"] == "partial"
    assert payload["records"] == 1
    assert payload["first_violation"] is None
    assert payload["counts"]["records"] == 1
    assert payload["consistency"]["ok"] is True
    assert payload["completeness"]["checked"] is False
    assert payload["exit_code"] == 2


def test_single_record_verified_with_anchor(tmp_path):
    """A single-record chain verifies when the correct anchor is supplied."""
    from palimpsests.audit.pala import record_hash
    from palimpsests.cli import app
    from typer.testing import CliRunner

    runner = CliRunner()
    p = _single_genesis_container(tmp_path)
    data = p.read_bytes()
    headers = [hb for hb, _ in iter_records(data)]
    head = record_hash(headers[0])
    result = runner.invoke(app, ["pala", "verify", str(p), "--anchor", head.hex()])
    assert result.exit_code == 0  # VERIFIED
    assert "chain intact" in result.output
    assert "matches the supplied anchor" in result.output


# ── original regression tests ──────────────────────────────────────────


def test_missing_genesis_discriminating_input_matches_the_demo():
    """Regression for spec defect #4 (freeze-candidate run, run #4).

    The discriminating input is the real chain minus its GENESIS: the first
    record then carries a NON-zero prev_hash, which is where the literal
    pre-fix §7.1 pseudocode diverged from §4.2 prose — producing a bogus
    "GENESIS must have prev_hash = 0" violation about a non-GENESIS record
    plus a spurious break. The demo's earlier synthetic input (single seq-0,
    zero-prev record) sat in the agreement zone of both readings and masked
    the divergence in BOTH in-repo implementations at once (a common-mode
    blind spot the differential test could not see). Asserts the §8 demo
    triple exactly, strictly.
    """
    from palimpsests.audit.pala import iter_records, verify_headers
    from pathlib import Path

    vectors = json.loads(
        (Path(__file__).parent.parent / "docs/specs/pala-1/test-vectors.json")
        .read_text()
    )
    container = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in vectors["records"]
    )
    headers = [hb for hb, _ in iter_records(container)]

    res = verify_headers(headers[1:])  # drop the GENESIS

    assert res.chain_ok is False
    assert res.breaks == []            # the links around it are perfectly sound
    assert res.gaps == []
    assert res.violations == [(0, "chain does not start with a GENESIS record")]
    # And the published demo says exactly this:
    demo = vectors["demos"]["missing_genesis"]
    assert demo["breaks"] == [] and demo["chain_ok"] is False
    assert [list(v) for v in res.violations] == demo["violations"]


def test_first_record_genesis_with_nonzero_prev_is_still_a_violation():
    """The zero-prev demand applies exactly when the first record IS a
    GENESIS (§7.1 as aligned): a forged GENESIS pointing at a predecessor
    must still be caught."""
    from palimpsests.audit.pala import Header, iter_records, verify_headers
    from pathlib import Path

    vectors = json.loads(
        (Path(__file__).parent.parent / "docs/specs/pala-1/test-vectors.json")
        .read_text()
    )
    container = b"".join(
        bytes.fromhex(r["header_hex"]) + bytes.fromhex(r.get("body_hex", ""))
        for r in vectors["records"]
    )
    genesis_hb = next(hb for hb, _ in iter_records(container))
    h = Header.decode(genesis_hb)
    forged = Header(
        record_type=h.record_type, seq=h.seq, boot_id=h.boot_id,
        prev_hash=b"\x11" * 32, assurance_tier=h.assurance_tier,
        time_trust=h.time_trust, span_id=h.span_id,
        parent_span_id=h.parent_span_id, monotonic_ns=h.monotonic_ns,
        wall_clock_ns=h.wall_clock_ns, key_id=h.key_id,
        body_len=h.body_len, body_digest=h.body_digest, tlvs=h.tlvs,
    )
    res = verify_headers([forged.encode()])
    assert any("prev_hash = 32 zero bytes" in msg for _, msg in res.violations)
    assert res.breaks == []
