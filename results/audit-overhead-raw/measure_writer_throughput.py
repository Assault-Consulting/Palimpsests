"""Point 3 — writer throughput ceiling, isolated from the model. Emits a
representative kind mix to disk in a tight loop; reports steady-state records/s
and bytes/s. Warm-up run discarded; >=5 kept runs; variance reported. This upper-
bounds the audit subsystem's contribution independent of the engine, so it can be
put next to the actual lifecycle-event rate under inference (Point 1)."""

import csv
import json
import os
import statistics
import tempfile
import time
from palimpsests.providers.native import PalaWriter

D32 = bytes(range(32))
SPAN = b"\x00" * 16
RECORDS_PER_RUN = 20000
RUNS = 7  # 1 warm-up discarded + 6 kept
WARMUP = 1


def one_session_batch(w):
    """Emit one session's worth of the representative mix (the Point-1 per-session
    counts, minus the once-per-chain genesis/boot). Returns records emitted."""
    n = 0
    w.session_start(f"s{n}", role="engine.native")
    n += 1
    w.prefix_warm(token_count=128)
    n += 1
    for _ in range(1):
        w.prefix_copy(128, span_id=SPAN)
        n += 1
    w.kv_save(D32, span_id=SPAN)
    n += 1
    w.session_end(SPAN)
    n += 1
    return n


def run_once(path):
    if os.path.exists(path):
        os.remove(path)
    w = PalaWriter(path)
    w.genesis()
    w.boot()
    w.model_load(D32, D32)
    emitted = 3
    t0 = time.perf_counter()
    while emitted < RECORDS_PER_RUN:
        emitted += one_session_batch(w)
    w.anchor()
    emitted += 1
    w.close()  # flush
    wall = time.perf_counter() - t0
    size = os.path.getsize(path)
    return {
        "records": emitted,
        "wall_s": wall,
        "records_per_s": emitted / wall,
        "bytes": size,
        "bytes_per_s": size / wall,
    }


def main():
    path = os.path.join(tempfile.gettempdir(), "writer_tp.pala")
    runs = []
    for i in range(RUNS):
        r = run_once(path)
        r["run"] = i
        r["warmup"] = i < WARMUP
        runs.append(r)
        print(
            f"run {i}{' (warmup, discarded)' if r['warmup'] else ''}: "
            f"{r['records_per_s']:.0f} rec/s, {r['bytes_per_s'] / 1e6:.1f} MB/s",
            flush=True,
        )

    kept = [r for r in runs if not r["warmup"]]
    rps = [r["records_per_s"] for r in kept]
    bps = [r["bytes_per_s"] for r in kept]

    out_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(out_dir, "writer_throughput.csv"), "w", newline="") as fh:
        wtr = csv.DictWriter(
            fh,
            fieldnames=[
                "run",
                "warmup",
                "records",
                "wall_s",
                "records_per_s",
                "bytes",
                "bytes_per_s",
            ],
        )
        wtr.writeheader()
        wtr.writerows(runs)

    summary = {
        "records_per_run": RECORDS_PER_RUN,
        "runs_kept": len(kept),
        "records_per_s_median": round(statistics.median(rps), 1),
        "records_per_s_stdev": round(statistics.pstdev(rps), 1),
        "records_per_s_min": round(min(rps), 1),
        "records_per_s_max": round(max(rps), 1),
        "bytes_per_s_median": round(statistics.median(bps), 1),
        "MB_per_s_median": round(statistics.median(bps) / 1e6, 2),
    }
    with open(os.path.join(out_dir, "writer_throughput_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
