# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for §7.1 chain-start semantics (spec defect #4)."""


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
    import json
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
    import json
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
