"""Tests for ``palimpsests pala verify``.

The container under test is built from the committed specification
vectors (``docs/specs/pala-1/test-vectors.json``): headers concatenated
with their bodies, per the §2.4 file container. That keeps the CLI tests
anchored to the same bytes the reference implementation reproduces in CI
— no second source of truth — and, deliberately, none of this needs
``cryptography``: the command is header-only by design.
"""
from __future__ import annotations

import json
import pytest
from palimpsests.cli import app
from pathlib import Path
from typer.testing import CliRunner

runner = CliRunner()

_VECTORS = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "specs"
    / "pala-1"
    / "test-vectors.json"
)


def _vectors() -> dict:
    return json.loads(_VECTORS.read_text(encoding="utf-8"))


def _container(vec: dict) -> tuple[bytes, list[tuple[int, int, int]]]:
    """Concatenate the vector records into a §2.4 container.

    Returns the bytes and, per record, ``(offset, header_len, body_len)``
    so tests can aim a mutation at a specific header or body.
    """
    out = bytearray()
    spans: list[tuple[int, int, int]] = []
    for r in vec["records"]:
        hb = bytes.fromhex(r["header_hex"])
        body = bytes.fromhex(r["body_hex"]) if "body_hex" in r else b""
        spans.append((len(out), len(hb), len(body)))
        out += hb + body
    return bytes(out), spans


@pytest.fixture()
def stream(tmp_path):
    vec = _vectors()
    data, spans = _container(vec)
    p = tmp_path / "vectors.pala"
    p.write_bytes(data)
    return p, data, spans, vec


def test_partial_without_anchor(stream):
    p, _, _, _ = stream
    result = runner.invoke(app, ["pala", "verify", str(p)])
    assert result.exit_code == 2
    assert "chain intact" in result.output
    assert "NOT CHECKED" in result.output


def test_verified_against_published_head(stream):
    p, _, _, vec = stream
    result = runner.invoke(
        app, ["pala", "verify", str(p), "--anchor", vec["chain_head"]]
    )
    assert result.exit_code == 0
    assert "matches the supplied anchor" in result.output


def test_stale_anchor_diagnosed_as_lag_not_replacement(stream):
    # The vectors' anchor_head names the head as of the ANCHOR record —
    # two records before the chain head. That is an unanchored tail, and
    # the diagnosis (not just the failure) is the contract.
    p, _, _, vec = stream
    result = runner.invoke(
        app, ["pala", "verify", str(p), "--anchor", vec["anchor_head"]]
    )
    assert result.exit_code == 1
    assert "unanchored tail" in result.output
    assert "replaced" not in result.output.split("unanchored tail")[0]


def test_foreign_anchor_diagnosed_as_replacement(stream):
    p, _, _, _ = stream
    result = runner.invoke(app, ["pala", "verify", str(p), "--anchor", "ff" * 32])
    assert result.exit_code == 1
    assert "names no record" in result.output


def test_body_bitflip_fails_digest_not_chain(stream):
    # Flip one byte inside an encrypted body: the chain (headers only)
    # still links, but the body no longer matches the digest bound into
    # its header — exactly the §1.2 split the format promises.
    p, data, spans, vec = stream
    victim = next(i for i, (_, _, blen) in enumerate(spans) if blen > 0)
    off, hlen, _ = spans[victim]
    mutated = bytearray(data)
    mutated[off + hlen] ^= 0x01
    p.write_bytes(bytes(mutated))
    result = runner.invoke(app, ["pala", "verify", str(p), "--anchor", vec["chain_head"]])
    assert result.exit_code == 1
    assert "body digest mismatch" in result.output
    assert "chain breaks" not in result.output


def test_header_bitflip_breaks_the_chain(stream):
    # Flip one byte inside a mid-chain header's prev_hash (offset 36..67).
    p, data, spans, vec = stream
    off, _, _ = spans[5]
    mutated = bytearray(data)
    mutated[off + 40] ^= 0x01
    p.write_bytes(bytes(mutated))
    result = runner.invoke(app, ["pala", "verify", str(p), "--anchor", vec["chain_head"]])
    assert result.exit_code == 1
    assert "chain breaks" in result.output


def test_truncated_tail_is_a_container_defect(stream):
    p, data, _, _ = stream
    p.write_bytes(data[:-3])
    result = runner.invoke(app, ["pala", "verify", str(p)])
    assert result.exit_code == 1
    assert "malformed container" in result.output
    assert "truncated" in result.output


def test_missing_file_is_unreadable(tmp_path):
    result = runner.invoke(app, ["pala", "verify", str(tmp_path / "absent.pala")])
    assert result.exit_code == 3


def test_bad_anchor_hex_is_unreadable(stream):
    p, _, _, _ = stream
    result = runner.invoke(app, ["pala", "verify", str(p), "--anchor", "zz"])
    assert result.exit_code == 3
    result = runner.invoke(app, ["pala", "verify", str(p), "--anchor", "abcd"])
    assert result.exit_code == 3


def test_witness_records_reported_never_verified(stream):
    p, _, _, vec = stream
    result = runner.invoke(app, ["pala", "verify", str(p), "--anchor", vec["chain_head"]])
    assert result.exit_code == 0
    assert "WITNESS record(s) at seq [10]" in result.output
    assert "not verified by this tool" in result.output


def test_json_output_shape(stream):
    p, _, _, vec = stream
    result = runner.invoke(
        app, ["pala", "verify", str(p), "--anchor", vec["chain_head"], "--json"]
    )
    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["exit_code"] == 0
    assert payload["records"] == len(vec["records"])
    assert payload["head"] == vec["chain_head"]
    assert payload["consistency"]["ok"] is True
    assert payload["completeness"] == {
        "checked": True,
        "ok": True,
        "anchor_lag": None,
        "reason": None,
    }
    assert payload["witness"]["records"] == [10]


def test_json_output_on_tamper_is_still_json(stream):
    p, data, spans, _ = stream
    off, _, _ = spans[5]
    mutated = bytearray(data)
    mutated[off + 40] ^= 0x01
    p.write_bytes(bytes(mutated))
    result = runner.invoke(app, ["pala", "verify", str(p), "--json"])
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["exit_code"] == 1
    assert payload["consistency"]["ok"] is False
    assert payload["consistency"]["breaks"]
