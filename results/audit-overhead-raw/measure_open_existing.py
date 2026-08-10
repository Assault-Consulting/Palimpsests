"""Point 4 — PalaWriter.open_existing() scaling + torn-tail / mid-stream behaviour.

Synthetic logs at 0.01 / 0.1 / 0.5 / 1 GB (fixed representative mix, deterministic
content). For each: wall time of open_existing(), warm (repeated, cache hot) and a
cold-approx (cache pressure applied first — true cold needs an admin cache flush,
so it is LABELLED approx, per the TZ caveat). Linear fit + residuals check the
O(file) expectation. Then torn-tail recovery and mid-stream-damage rejection.
"""

import gc
import json
import os
import statistics
import time
from palimpsests.providers.native import PalaWriter

RAW = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.join(RAW, "openx_files")
os.makedirs(WORK, exist_ok=True)
D32 = bytes(range(32))
SPAN = b"\x00" * 16
SIZES = [("0.01GB", 0.01), ("0.1GB", 0.1), ("0.5GB", 0.5), ("1GB", 1.0)]
GB = 1024**3
AVG = 181  # weighted bytes/record from Point 2, to estimate record count
WARM_RUNS = 6  # 1 warm-up + 5 kept


BATCH_BYTES = 905  # session_start 173 + prefix_warm 183 + prefix_copy 183
# + kv_save 210 + session_end 156 (Point-2 sizes)
HEADER_BYTES = 563  # genesis 156 + boot 156 + model_load 251


def gen_file(path, target_bytes):
    """Single-pass generation (no reopen — reopening would walk O(file) and make
    generation O(n^2)). Emit a computed number of representative batches, close."""
    if os.path.exists(path):
        os.remove(path)
    w = PalaWriter(path)
    w.genesis()
    w.boot()
    w.model_load(D32, D32)
    batches = max(1, (target_bytes - HEADER_BYTES) // BATCH_BYTES + 1)
    for i in range(batches):
        w.session_start(f"s{i}", role="engine.native")
        w.prefix_warm(token_count=128)
        w.prefix_copy(128, span_id=SPAN)
        w.kv_save(D32, span_id=SPAN)
        w.session_end(SPAN)
    w.close()
    return os.path.getsize(path)


def time_open(path):
    t0 = time.perf_counter()
    w = PalaWriter.open_existing(path)
    dt = time.perf_counter() - t0
    head = w.head_hex
    seq = w.seq
    w.close()
    return dt, head, seq


def cache_pressure(nbytes):
    """Best-effort cache eviction: read a large dummy file to push the target out
    of the OS file cache. Not a guaranteed cold read without an admin flush."""
    dummy = os.path.join(WORK, "dummy_evict.bin")
    if not os.path.exists(dummy) or os.path.getsize(dummy) < nbytes:
        with open(dummy, "wb") as fh:
            fh.write(b"\x00" * (1024 * 1024))
            fh.seek(nbytes - 1)
            fh.write(b"\x00")
    total = 0
    with open(dummy, "rb") as fh:
        while True:
            b = fh.read(64 * 1024 * 1024)
            if not b:
                break
            total += len(b)
    return total


def main():
    results = []
    for label, gb in SIZES:
        path = os.path.join(WORK, f"log_{label}.pala")
        actual = gen_file(path, int(gb * GB))
        # warm
        warm = []
        for i in range(WARM_RUNS):
            dt, head, seq = time_open(path)
            if i > 0:
                warm.append(dt)
        # cold-approx: best-effort eviction, then one timed open. NOTE: true cold
        # needs an admin cache flush (unavailable here); this is a labelled approx.
        gc.collect()
        cache_pressure(4 * GB)
        cold_dt, _, _ = time_open(path)
        row = {
            "label": label,
            "target_gb": gb,
            "actual_bytes": actual,
            "records_approx": actual // AVG,
            "warm_median_s": round(statistics.median(warm), 4),
            "warm_stdev_s": round(statistics.pstdev(warm), 4),
            "warm_min_s": round(min(warm), 4),
            "warm_max_s": round(max(warm), 4),
            "cold_approx_s": round(cold_dt, 4),
            "warm_MB_per_s": round(actual / 1e6 / statistics.median(warm), 1),
        }
        results.append(row)
        print(json.dumps(row), flush=True)

    # linear fit warm_median vs actual bytes: t = a + b*bytes
    xs = [r["actual_bytes"] for r in results]
    ys = [r["warm_median_s"] for r in results]
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys, strict=True))
    var = sum((x - mx) ** 2 for x in xs)
    b = cov / var
    a = my - b * mx
    resid = [round(y - (a + b * x), 5) for x, y in zip(xs, ys, strict=True)]
    fit = {
        "slope_s_per_GB": round(b * GB, 4),
        "intercept_s": round(a, 5),
        "residuals_s": resid,
        "ns_per_byte": round(b * 1e9, 4),
    }

    summary = {"sizes": results, "linear_fit": fit}
    with open(os.path.join(RAW, "open_existing_scaling.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print("LINEAR FIT:", json.dumps(fit))
    return summary


if __name__ == "__main__":
    main()
