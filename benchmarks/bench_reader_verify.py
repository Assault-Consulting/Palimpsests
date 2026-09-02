# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""U14 — what ``AuditReader.verify()`` actually costs, measured honestly.

Honest-measurement rules, stated up front:

- **A range, never a point.** Spread between identical runs of the full
  path has been observed up to 1.5x. Every metric below is reported as
  min–max over ``--repeats`` (default 3); a single run is not a
  measurement, and the next person must not build a decision on a lucky
  number.
- **One process per run.** RSS does not reliably return to baseline
  inside a long-lived Python process, so each repeat executes in a
  fresh child interpreter and reports one JSON line.
- **Composition travels with the number.** The fixture's
  ``.composition.json`` (from ``gen_reader_fixtures.py``) is embedded in
  the output; a figure quoted without it is not reproducible.
- **A container run is NON-CANONICAL.** Ratios travel; absolute numbers
  belong to the machine that produced them. Record the environment.

What is measured, per fixture:

- RSS (VmRSS) and tracemalloc peak after ``open()`` and after
  ``verify()``, separately — the floor and the spike.
- Wall time: ``open()``; the §7.1 chain pass alone
  (``verify_headers`` over ``iter_records``); ``verify()`` in full.
  The referential pass is reported as the difference and labeled so.
- ``build_report(..., reader=)`` wall time, on the already-open reader.

Run:  python benchmarks/bench_reader_verify.py FIX.pala [FIX2.pala ...] \\
          [--repeats 3] [--json out.json] [--profile-hotspots]
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path


def _vmrss_mb() -> float:
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1]) / 1024.0
    return -1.0


def run_one(fixture: Path) -> dict[str, float]:
    """Executed in the child process: one full measured pass."""
    from palimpsests.audit.pala.codec import iter_records
    from palimpsests.audit.pala.verify import verify_headers
    from palimpsests.audit.reader import AuditReader
    from palimpsests.audit.report import build_report

    out: dict[str, float] = {}
    data = fixture.read_bytes()

    t = time.monotonic()
    result = verify_headers(h for h, _ in iter_records(data))
    out["t_chain_only_s"] = time.monotonic() - t
    out["records"] = float(result.count)
    del data

    tracemalloc.start()
    t = time.monotonic()
    reader = AuditReader.open(fixture)
    out["t_open_s"] = time.monotonic() - t
    out["rss_after_open_mb"] = _vmrss_mb()
    cur, peak = tracemalloc.get_traced_memory()
    out["pyheap_after_open_mb"] = cur / 2**20
    out["pyheap_peak_open_mb"] = peak / 2**20

    tracemalloc.reset_peak()
    t = time.monotonic()
    reader.verify()
    out["t_verify_full_s"] = time.monotonic() - t
    out["rss_after_verify_mb"] = _vmrss_mb()
    cur, peak = tracemalloc.get_traced_memory()
    out["pyheap_after_verify_mb"] = cur / 2**20
    out["pyheap_peak_verify_mb"] = peak / 2**20
    out["t_referential_derived_s"] = out["t_verify_full_s"] - out["t_chain_only_s"]

    t = time.monotonic()
    build_report(fixture, reader=reader)
    out["t_report_with_reader_s"] = time.monotonic() - t
    out["rss_after_report_mb"] = _vmrss_mb()
    tracemalloc.stop()
    reader.close()
    return out


def _range(values: list[float]) -> dict[str, float]:
    return {
        "min": round(min(values), 3),
        "max": round(max(values), 3),
        "median": round(statistics.median(values), 3),
        "n": len(values),
    }


def measure(fixture: Path, repeats: int) -> dict:
    runs: list[dict[str, float]] = []
    for _ in range(repeats):
        proc = subprocess.run(
            [sys.executable, __file__, "--one", str(fixture)],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"child failed for {fixture} (rc={proc.returncode}):\n{proc.stderr[-2000:]}"
            )
        runs.append(json.loads(proc.stdout.strip().splitlines()[-1]))

    keys = sorted(runs[0])
    agg = {k: _range([r[k] for r in runs]) for k in keys}
    comp_path = fixture.with_suffix("").with_suffix("")  # strip .pala
    comp_file = fixture.parent / (fixture.stem + ".composition.json")
    composition = (
        json.loads(comp_file.read_text()) if comp_file.exists() else None
    )
    del comp_path
    return {
        "fixture": fixture.name,
        "bytes": fixture.stat().st_size,
        "repeats": repeats,
        "metrics": agg,
        "composition": composition,
        "canonical": False,
        "note": "container/laptop runs are non-canonical; ratios travel, absolutes do not",
    }


def _print_table(entry: dict) -> None:
    m = entry["metrics"]
    ref = (entry.get("composition") or {}).get("referential_share")
    print(f"\n== {entry['fixture']}  ({entry['bytes'] / 2**20:.1f} MiB"
          f"{'' if ref is None else f', referential {ref:.2%}'}) ==")
    order = [
        ("open()", "t_open_s", "s"),
        ("chain pass alone", "t_chain_only_s", "s"),
        ("verify() full", "t_verify_full_s", "s"),
        ("  referential (derived)", "t_referential_derived_s", "s"),
        ("report(reader=)", "t_report_with_reader_s", "s"),
        ("RSS after open", "rss_after_open_mb", "MB"),
        ("RSS after verify", "rss_after_verify_mb", "MB"),
        ("RSS after report", "rss_after_report_mb", "MB"),
        ("py-heap peak @verify", "pyheap_peak_verify_mb", "MB"),
    ]
    for label, key, unit in order:
        r = m[key]
        print(f"  {label:<26} {r['min']:>9.2f} – {r['max']:<9.2f} {unit}"
              f"   (median {r['median']:.2f}, n={r['n']})")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("fixtures", nargs="*", type=Path)
    ap.add_argument("--one", type=Path, help="internal: single child run")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--json", type=Path, help="write aggregated results here")
    ap.add_argument(
        "--profile-hotspots",
        action="store_true",
        help="cProfile verify() on the first fixture (one run, no ranges)",
    )
    args = ap.parse_args()

    if args.one:
        print(json.dumps(run_one(args.one)))
        return
    if not args.fixtures:
        ap.error("pass at least one fixture (.pala)")

    results = []
    for fx in args.fixtures:
        entry = measure(fx, args.repeats)
        _print_table(entry)
        results.append(entry)

    if args.profile_hotspots:
        import cProfile
        import pstats
        from palimpsests.audit.reader import AuditReader

        fx = args.fixtures[0]
        reader = AuditReader.open(fx)
        prof = cProfile.Profile()
        prof.enable()
        reader.verify()
        prof.disable()
        reader.close()
        print(f"\n== cProfile: verify() on {fx.name} (top 15 cumulative) ==")
        pstats.Stats(prof).sort_stats("cumulative").print_stats(15)

    if args.json:
        args.json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
