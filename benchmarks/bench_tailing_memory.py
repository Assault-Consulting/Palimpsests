# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""U14 / PR-5 — does a live ``TailingReader``'s resident memory grow linearly?

The question, from the U14 plan: ``IncrementalVerifier._seen`` holds one
32-byte object per record for the whole pass — bounded by the file in
batch mode, unbounded in a live reader that is *meant* to grow. Reading
the implementation before measuring adds a second, larger suspect:
``TailingReader._verified`` is a ``bytearray`` that mirrors **every
verified byte** in memory (it is what ``snapshot()`` re-verifies), and
``snapshot()`` copies it wholesale — a transient duplicate of the entire
verified prefix per call.

This bench measures all three, separately:

- the growth slope of RSS and of the Python heap, in bytes per record,
  as a writer appends and the tailing reader keeps up;
- the sizes of the two internal accumulators (``_verified`` bytes,
  ``_seen`` entries) at each milestone — labeled *internal
  instrumentation*: reads private fields, may break, exists so the
  slope can be attributed rather than guessed;
- the ``snapshot()`` cost at selected milestones: wall time and the
  RSS high-water jump (``VmHWM``) it causes.

Honest-measurement rules as in ``bench_reader_verify.py``: each repeat
in a fresh child process; ranges over repeats; container runs
NON-CANONICAL — the *slope* travels, absolute RSS does not.

Run:  python benchmarks/bench_tailing_memory.py --records 300000 \\
          --batch 50000 --repeats 2 --json out.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path


def _proc_status_kb(field: str) -> float:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(field + ":"):
            return int(line.split()[1])
    return -1.0


def _digest(tag: str, i: int) -> bytes:
    return hashlib.sha256(f"{tag}:{i}".encode()).digest()


def run_one(records: int, batch: int, snapshot_every: int, workdir: Path) -> dict:
    """Child process: write live, tail live, sample at milestones."""
    import tracemalloc
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.audit.tailing import TailingReader

    path = workdir / "tail.pala"
    path.unlink(missing_ok=True)

    tracemalloc.start()
    writer = PalaWriter(path)
    writer.genesis()
    writer.boot()
    span = writer.session_start("tail-bench")

    reader = TailingReader(path, poll_interval=0.001)
    events = reader.events()
    consumed = 0

    def drain_to(target: int) -> None:
        nonlocal consumed
        deadline = time.monotonic() + 120.0
        while consumed < target:
            ev = next(events)
            if ev.kind == "record":
                consumed += 1
            if time.monotonic() > deadline:
                raise RuntimeError(f"tail did not catch up: {consumed}/{target}")

    milestones: list[dict] = []
    next_snap = snapshot_every if snapshot_every else 0
    written = writer.seq
    while written < records:
        step = min(batch, records - written)
        for _ in range(step):
            writer.kv_save(_digest("kv", writer.seq), span_id=span)
        written = writer.seq
        drain_to(written)

        row: dict[str, float] = {
            "records": float(consumed),
            "rss_mb": _proc_status_kb("VmRSS") / 1024.0,
            "pyheap_mb": tracemalloc.get_traced_memory()[0] / 2**20,
            "file_mb": path.stat().st_size / 2**20,
        }
        # Internal instrumentation — private fields, attribution only.
        verified = getattr(reader, "_verified", None)
        verifier = getattr(reader, "_verifier", None)
        seen = getattr(verifier, "seen", None) if verifier is not None else None
        row["internal_verified_mb"] = (
            len(verified) / 2**20 if verified is not None else -1.0
        )
        row["internal_seen_entries"] = (
            float(len(seen)) if seen is not None else -1.0
        )

        if next_snap and consumed >= next_snap:
            next_snap += snapshot_every
            hwm_before = _proc_status_kb("VmHWM") / 1024.0
            t0 = time.monotonic()
            reader.snapshot()
            row["snapshot_s"] = time.monotonic() - t0
            row["snapshot_hwm_jump_mb"] = (
                _proc_status_kb("VmHWM") / 1024.0 - hwm_before
            )
        milestones.append(row)

    reader.close()
    writer.close()
    tracemalloc.stop()

    first, last = milestones[0], milestones[-1]
    drec = last["records"] - first["records"]
    slopes = {}
    if drec > 0:
        for k, label in (("rss_mb", "rss"), ("pyheap_mb", "pyheap"),
                         ("internal_verified_mb", "verified")):
            slopes[f"slope_{label}_bytes_per_record"] = round(
                (last[k] - first[k]) * 2**20 / drec, 1
            )
    return {"milestones": milestones, "slopes": slopes}


def _rng(vals: list[float]) -> dict[str, float]:
    return {"min": round(min(vals), 1), "max": round(max(vals), 1),
            "median": round(statistics.median(vals), 1), "n": len(vals)}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--records", type=int, default=300_000)
    ap.add_argument("--batch", type=int, default=50_000)
    ap.add_argument("--snapshot-every", type=int, default=100_000)
    ap.add_argument("--repeats", type=int, default=2)
    ap.add_argument("--json", type=Path)
    ap.add_argument("--one", action="store_true", help="internal: child run")
    ap.add_argument("--workdir", type=Path, default=Path("/tmp/u14-tail"))
    args = ap.parse_args()

    args.workdir.mkdir(parents=True, exist_ok=True)
    if args.one:
        print(json.dumps(run_one(
            args.records, args.batch, args.snapshot_every, args.workdir
        )))
        return

    runs = []
    for _ in range(args.repeats):
        proc = subprocess.run(
            [sys.executable, __file__, "--one",
             "--records", str(args.records), "--batch", str(args.batch),
             "--snapshot-every", str(args.snapshot_every),
             "--workdir", str(args.workdir)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"child failed:\n{proc.stderr[-2000:]}")
        runs.append(json.loads(proc.stdout.strip().splitlines()[-1]))

    slope_keys = sorted(runs[0]["slopes"])
    print(f"\n== TailingReader growth, {args.records} records, "
          f"n={args.repeats} (fresh process each) ==")
    for k in slope_keys:
        r = _rng([run["slopes"][k] for run in runs])
        print(f"  {k:<34} {r['min']:>8.1f} – {r['max']:<8.1f} B/rec "
              f"(median {r['median']}, n={r['n']})")
    snaps = [m for run in runs for m in run["milestones"] if "snapshot_s" in m]
    if snaps:
        print("  snapshot() at milestones:")
        for m in snaps:
            print(f"    @{int(m['records']):>7} rec: {m['snapshot_s']:.2f} s, "
                  f"VmHWM jump {m['snapshot_hwm_jump_mb']:.0f} MB")

    out = {"records": args.records, "batch": args.batch,
           "repeats": args.repeats, "runs": runs, "canonical": False,
           "note": "container/laptop runs are non-canonical; "
                   "slopes travel, absolute RSS does not"}
    if args.json:
        args.json.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
