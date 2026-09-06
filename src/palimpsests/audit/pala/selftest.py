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

A third, from the U14 track: a **characteristic** line. The vectors are
17 and 8 records; nothing in them would notice if ``verify()`` started
materialising the chain again. So the selftest also writes a synthetic
chain of :data:`CHARACTERISTIC_RECORDS` records to a temporary file,
opens and verifies it, and reports records/s and the Python-heap peak
per record. The rate is information (it belongs to the machine); the
per-record heap is a **tripwire**: above :data:`HEAP_BYTES_PER_RECORD_MAX`
the selftest fails, because that is the slope that once turned a
million records into a SIGKILL, and the whole point of U14 was to make
it small and keep it small.
"""
from __future__ import annotations

import palimpsests
import tempfile
import time
import tracemalloc
from dataclasses import dataclass, field
from hashlib import sha256
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from palimpsests.audit.pala import vectors as published
from palimpsests.audit.pala import verify_headers
from pathlib import Path

#: Records in the synthetic characteristic chain. Large enough that the
#: per-record slope dominates fixed costs, small enough to write and
#: verify in about a second on modest hardware.
CHARACTERISTIC_RECORDS = 20_000

#: Tripwire: Python-heap peak during ``open()`` + ``verify()``, divided by
#: the record count. After U14 Phase 2 the reader sits near 130 B/record
#: on a calm chain (offset arrays, the verifier's head list, the seq
#: map); before it, ~1.7 KB/record. 512 leaves the honest headroom of a
#: different interpreter, and still trips on a return to the old slope.
HEAP_BYTES_PER_RECORD_MAX = 512


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

    ok = _characteristic(lines) and ok

    return SelftestResult(ok=ok, lines=lines)


def _characteristic(lines: list[str]) -> bool:
    """Write a synthetic chain, verify it, report the reader's slope."""
    from palimpsests.audit.pala_writer import DISP_ACKNOWLEDGED, PalaWriter
    from palimpsests.audit.reader import AuditReader

    n = CHARACTERISTIC_RECORDS
    with tempfile.TemporaryDirectory(prefix="pala-selftest-") as tmp:
        path = Path(tmp) / "characteristic.pala"
        # Deterministic composition: sessions of KV operations with a
        # tool pair per session and an oversight pair every few sessions
        # — the serving-like mix the U14 fixtures call "calm", so the
        # number means the same thing the track's results files mean.
        with PalaWriter(path, boot_id=b"\x5e" * 16) as w:
            w.genesis()
            w.boot()
            written = 2
            session = 0
            while written < n:
                sid = w.session_start(f"s{session}")
                written += 1
                for i in range(min(40, n - written - 4)):
                    w.kv_save(bytes([(session + i) % 251]) * 32)
                    written += 1
                call = w.tool_call("fs.read", args_digest=bytes([session % 251]) * 32)
                w.tool_result(w.seq - 1, call, 0, result_digest=b"\x01" * 32)
                written += 2
                if session % 5 == 0:
                    cand = w.incident_candidate(1, 1)
                    w.oversight_ack(w.seq - 1, cand, DISP_ACKNOWLEDGED, b"\x0e" * 16)
                    written += 2
                w.session_end(sid)
                written += 1
                session += 1

        tracemalloc.start()
        t0 = time.perf_counter()
        with AuditReader.open(path) as reader:
            ver = reader.verify()
            count = ver.chain.chain_ok and ver.chain.count
        elapsed = time.perf_counter() - t0
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    if not count:
        lines.append("  characteristic: synthetic chain did not verify — FAIL")
        return False
    per_record = peak / count
    rate = count / elapsed if elapsed > 0 else float("inf")
    ok = per_record <= HEAP_BYTES_PER_RECORD_MAX
    lines.append(
        f"  characteristic: {count} records, verify {rate:,.0f} rec/s "
        f"({elapsed:.2f} s), py-heap peak {peak / 1e6:.1f} MB "
        f"= {per_record:.0f} B/record (tripwire {HEAP_BYTES_PER_RECORD_MAX}) "
        f"— {'ok' if ok else 'FAIL'}"
    )
    return ok
