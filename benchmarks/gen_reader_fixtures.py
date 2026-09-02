# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""U14 — fixture generator for AuditReader verification-cost measurement.

Composition is part of the result, not a detail: the cost of the
referential advisory pass depends directly on how many records
participate in it (an ``OVERSIGHT_ACK`` resolved to its candidate, a
``KEY_SHRED`` resolved to its targets). Every fixture therefore ships
with a ``.composition.json`` manifest recording exactly what was
written; a measurement quoted without its composition is not
reproducible.

Three profiles:

- ``calm``       — a realistic serving cycle: sessions, KV/prefix
                   traffic, sparse tool use, an incident/ack pair per
                   ~10k records (~0.02% referential). The baseline.
- ``toolheavy``  — a ceiling, not a norm: dense tool loops with an
                   incident/ack pair in every unit (~28% referential).
- ``encrypted``  — bodies sealed with ``key_id != 0`` (AES-256-GCM,
                   the section-8 vector key). Referential participation
                   is zero **by construction**: kinds live in bodies the
                   verifier cannot open. This is the one profile whose
                   verify() cost has never been measured — a hypothesis,
                   not a baseline.

Generation is deterministic for a given (profile, records) pair except
for ``boot_id`` and wall-clock fields, which the wire format takes from
the environment; the manifest records both.

Run:  python benchmarks/gen_reader_fixtures.py --profile calm \\
          --records 100000 --out /tmp/u14
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import time
from palimpsests.audit.pala.bodies import seal_body
from palimpsests.audit.pala.codec import (
    body_digest_of,
    encode_tlvs,
    record_hash,
)
from palimpsests.audit.pala_writer import PalaWriter
from pathlib import Path

# The section-8 vector key convention: 31 zero bytes then 0x2a, key_id 7.
VECTOR_KEY = bytes(31) + b"\x2a"
VECTOR_KEY_ID = 7

SIZES_LADDER = (10_000, 50_000, 100_000, 250_000, 1_000_000)


def _digest(tag: str, i: int) -> bytes:
    return hashlib.sha256(f"{tag}:{i}".encode()).digest()


def gen_calm(path: Path, records: int) -> dict[str, int]:
    """Serving cycle; incident/ack pair every ~10_000 records."""
    counts: dict[str, int] = {}

    def bump(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    with PalaWriter(path) as w:
        w.genesis()
        bump("GENESIS")
        w.boot()
        bump("BOOT")
        w.model_load(_digest("model", 0), _digest("cfg", 0))
        bump("MODEL_LOAD")
        span = w.session_start("s0")
        bump("SESSION_START")
        block = 0
        while w.seq < records - 1:
            i = w.seq
            if i // 1000 != block:
                w.session_end(span)
                bump("SESSION_END")
                block = i // 1000
                span = w.session_start(f"s{block}")
                bump("SESSION_START")
            elif i % 10_000 == 5_000:
                cand_seq = w.seq
                cand_hash = w.incident_candidate(1, 1)
                bump("INCIDENT_CANDIDATE")
                w.oversight_ack(cand_seq, cand_hash, 1, _digest("op", 1)[:16])
                bump("OVERSIGHT_ACK")
            elif i % 200 == 199:
                w.aggregate(
                    1_000_000_000,
                    requests=8,
                    tokens_prefill=512,
                    tokens_decode=256,
                    prefill_saved=128,
                    sessions_open=1,
                )
                bump("AGGREGATE")
            elif i % 97 == 3:
                call_seq = w.seq
                call_hash = w.tool_call(
                    "search", args_digest=_digest("args", i), span_id=span
                )
                bump("TOOL_CALL")
                w.tool_result(call_seq, call_hash, 0, span_id=span)
                bump("TOOL_RESULT")
            else:
                w.kv_save(_digest("kv", i), span_id=span)
                bump("KV_SAVE")
        w.anchor()
        bump("ANCHOR")
    return counts


def gen_toolheavy(path: Path, records: int) -> dict[str, int]:
    """Repeating 7-record unit with an incident/ack pair → ~28% referential."""
    counts: dict[str, int] = {}

    def bump(name: str) -> None:
        counts[name] = counts.get(name, 0) + 1

    def call_pair(tool: str, tag: str) -> None:
        cs = w.seq
        ch = w.tool_call(tool, args_digest=_digest(tag, cs), span_id=span)
        bump("TOOL_CALL")
        w.tool_result(cs, ch, 0, span_id=span)
        bump("TOOL_RESULT")

    with PalaWriter(path) as w:
        w.genesis()
        bump("GENESIS")
        w.boot()
        bump("BOOT")
        span = w.session_start("agent")
        bump("SESSION_START")
        while w.seq < records - 1:
            call_pair("shell", "a")
            cand_seq = w.seq
            cand_hash = w.incident_candidate(1, 1)
            bump("INCIDENT_CANDIDATE")
            w.oversight_ack(cand_seq, cand_hash, 1, _digest("op", 2)[:16])
            bump("OVERSIGHT_ACK")
            call_pair("shell", "b")
            w.kv_save(_digest("kv", w.seq), span_id=span)
            bump("KV_SAVE")
        w.anchor()
        bump("ANCHOR")
    return counts


def gen_encrypted(path: Path, records: int) -> dict[str, int]:
    """Wire-level chain whose event bodies are sealed (``key_id = 7``).

    ``PalaWriter`` writes cleartext bodies by design (inference profile);
    this profile assembles records the way the section-8 vectors do:
    ``Header`` + ``seal_body`` with the spec's nonce/AAD derivation. The
    chain is fully §7.1-valid; only body *reading* needs the key.
    """
    # Imported here: the Header dataclass is codec-internal surface used
    # exactly the way pala_writer uses it; keeping the import local makes
    # that dependency visible in one place.
    from palimpsests.audit.pala.codec import Header  # noqa: PLC0415

    counts: dict[str, int] = {"GENESIS": 1, "BOOT": 1}
    boot_id = os.urandom(16)
    head = bytes(32)
    seq = 0
    fh = open(path, "wb")
    try:
        for rtype, body_plain in _encrypted_prelude():
            hdr = Header(
                record_type=rtype,
                seq=seq,
                boot_id=boot_id,
                prev_hash=head,
                assurance_tier=0,
                time_trust=0,
                span_id=bytes(16),
                parent_span_id=bytes(16),
                monotonic_ns=time.monotonic_ns(),
                wall_clock_ns=0,
                key_id=0,
                body_len=len(body_plain),
                body_digest=body_digest_of(body_plain) if body_plain else bytes(32),
                tlvs=[],
            )
            hb = hdr.encode()
            fh.write(hb + body_plain)
            head = record_hash(hb)
            seq += 1
        rtype_event = 0x0010  # RT_EVENT
        while seq < records:
            plain = encode_tlvs([(0x0001, _digest("evt", seq)[:16])])
            sealed, bdig = seal_body(
                VECTOR_KEY,
                seq=seq,
                boot_id=boot_id,
                record_type=rtype_event,
                plaintext=plain,
            )
            hdr = Header(
                record_type=rtype_event,
                seq=seq,
                boot_id=boot_id,
                prev_hash=head,
                assurance_tier=0,
                time_trust=0,
                span_id=bytes(16),
                parent_span_id=bytes(16),
                monotonic_ns=time.monotonic_ns(),
                wall_clock_ns=0,
                key_id=VECTOR_KEY_ID,
                body_len=len(sealed),
                body_digest=bdig,
                tlvs=[],
            )
            hb = hdr.encode()
            fh.write(hb + sealed)
            head = record_hash(hb)
            seq += 1
            counts["EVENT_SEALED"] = counts.get("EVENT_SEALED", 0) + 1
    finally:
        fh.close()
    return counts


def _encrypted_prelude() -> list[tuple[int, bytes]]:
    return [(0x0001, b""), (0x0002, b"")]  # GENESIS, BOOT


PROFILES = {"calm": gen_calm, "toolheavy": gen_toolheavy, "encrypted": gen_encrypted}
REFERENTIAL = {"INCIDENT_CANDIDATE", "OVERSIGHT_ACK", "KEY_SHRED"}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", choices=sorted(PROFILES), required=True)
    ap.add_argument("--records", type=int, required=True)
    ap.add_argument("--out", type=Path, required=True, help="output directory")
    args = ap.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)
    name = f"{args.profile}-{args.records}"
    fixture = args.out / f"{name}.pala"
    fixture.unlink(missing_ok=True)  # a generator owns its output
    t0 = time.monotonic()
    counts = PROFILES[args.profile](fixture, args.records)
    dt = time.monotonic() - t0

    total = sum(counts.values())
    ref = sum(v for k, v in counts.items() if k in REFERENTIAL)
    manifest = {
        "profile": args.profile,
        "requested_records": args.records,
        "written_records": total,
        "bytes": fixture.stat().st_size,
        "counts": dict(sorted(counts.items())),
        "referential_records": ref,
        "referential_share": round(ref / total, 6) if total else 0.0,
        "generation_seconds": round(dt, 2),
        "generator": "benchmarks/gen_reader_fixtures.py",
    }
    (args.out / f"{name}.composition.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
