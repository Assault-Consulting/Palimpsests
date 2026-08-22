# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""``pala selftest`` — is this installed build sound?

Runs the linked verifier against the vectors packaged in the wheel (U9)
and compares every published expectation: per-record hashes, the chain
head, and the verify block. One command, exit 0/1, for the question
every installation eventually asks.

Two checks that a vector run alone would NOT cover, included
deliberately (the track plan's correction): ``__version__`` is compared
against the distribution metadata — the 0.8.0 release shipped with
exactly that drift — and both versions are reported so the output is
useful in a bug report.
"""
from __future__ import annotations

import palimpsests
from dataclasses import dataclass, field
from hashlib import sha256
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from palimpsests.audit.pala import vectors as published
from palimpsests.audit.pala import verify_headers


@dataclass
class SelftestResult:
    ok: bool
    lines: list[str] = field(default_factory=list)


def _check_set(name: str, lines: list[str]) -> bool:
    data = published.load(name)
    headers = [bytes.fromhex(r["header_hex"]) for r in data["records"]]

    for r, hb in zip(data["records"], headers, strict=True):
        if sha256(hb).hexdigest() != r["record_hash"]:
            lines.append(
                f"  {name}: record_hash mismatch at seq {r['seq']} — FAIL"
            )
            return False

    result = verify_headers(headers)
    expected_head = data["chain_head"]
    ok = (
        result.chain_ok
        and result.count == len(headers)
        and result.head.hex() == expected_head
    )
    verify_block = data.get("verify")
    if ok and isinstance(verify_block, dict):
        ok = result.chain_ok == verify_block.get("chain_ok", True) and (
            result.count == verify_block.get("count", len(headers))
        )
    lines.append(
        f"  {name}: {result.count} records, chain_ok={result.chain_ok}, "
        f"head {'matches' if result.head.hex() == expected_head else 'MISMATCH'}"
        f" — {'ok' if ok else 'FAIL'}"
    )
    return ok


def run_selftest() -> SelftestResult:
    """Verify this build against the packaged published vectors."""
    lines: list[str] = []
    ok = True

    declared = palimpsests.__version__
    try:
        installed = distribution_version("palimpsests")
    except PackageNotFoundError:
        installed = None
    if installed is None:
        lines.append(f"  version: {declared} (distribution metadata unavailable)")
    elif installed == declared:
        lines.append(f"  version: {declared} — ok")
    else:
        lines.append(
            f"  version: __version__ {declared} != distribution {installed} — FAIL"
        )
        ok = False

    for name in published.available():
        ok = _check_set(name, lines) and ok

    return SelftestResult(ok=ok, lines=lines)
