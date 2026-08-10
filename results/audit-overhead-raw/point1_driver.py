"""Point 1 driver — alternates audit on/off across isolated subprocess runs,
warm-up per arm discarded, aggregates median + IQR + overhead % + an honest
overlap verdict. Each run is a fresh process (clean memory, no cross-run state).
No explicit sleep (convention): the subprocess teardown + next model load is the
natural cool-down between timed regions."""

import csv
import json
import os
import statistics
import subprocess
import sys

PY = r"D:\Palimpsests\Palimpsests-vulkan\.venv-vulkan\Scripts\python.exe"
RUN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "point1_run.py")
PER_ARM = 8  # first of each arm is warm-up (discarded) -> 7 kept
OUT_DIR = os.path.dirname(os.path.abspath(__file__))


def iqr(xs):
    xs = sorted(xs)
    n = len(xs)
    q1 = statistics.median(xs[: n // 2])
    q3 = statistics.median(xs[(n + 1) // 2 :])
    return q1, q3


def main():
    order = []
    for i in range(PER_ARM):
        order += [("on", i), ("off", i)]  # on/off/on/off…

    rows = []
    for arm, i in order:
        proc = subprocess.run([PY, RUN, arm], capture_output=True, text=True)
        line = proc.stdout.strip().splitlines()[-1]
        r = json.loads(line)
        r["idx"] = i
        r["warmup"] = i == 0
        rows.append(r)
        print(
            f"[{arm} #{i}{' warmup' if r['warmup'] else ''}] "
            f"{r['tokens_per_s']:.2f} tok/s, wall {r['wall_s']:.2f}s, "
            f"tokens {r['tokens']}, peakRSS {r['peak_rss_mb']}MB",
            flush=True,
        )

    with open(os.path.join(OUT_DIR, "point1_runs.csv"), "w", newline="") as fh:
        w = csv.DictWriter(
            fh,
            fieldnames=[
                "arm",
                "idx",
                "warmup",
                "wall_s",
                "tokens",
                "tokens_per_s",
                "peak_rss_mb",
                "wss_mb",
            ],
        )
        w.writeheader()
        w.writerows(rows)

    def arm_stats(arm):
        vals = [r["tokens_per_s"] for r in rows if r["arm"] == arm and not r["warmup"]]
        walls = [r["wall_s"] for r in rows if r["arm"] == arm and not r["warmup"]]
        toks = {r["tokens"] for r in rows if r["arm"] == arm and not r["warmup"]}
        q1, q3 = iqr(vals)
        return {
            "n": len(vals),
            "median_tok_s": statistics.median(vals),
            "q1": q1,
            "q3": q3,
            "min": min(vals),
            "max": max(vals),
            "stdev": statistics.pstdev(vals),
            "median_wall_s": statistics.median(walls),
            "token_counts": sorted(toks),
        }

    on, off = arm_stats("on"), arm_stats("off")
    overhead_pct = (off["median_tok_s"] - on["median_tok_s"]) / off["median_tok_s"] * 100.0
    # overlap: do the [min,max] ranges of the two arms overlap?
    overlap = not (on["max"] < off["min"] or off["max"] < on["min"])
    iqr_overlap = not (on["q3"] < off["q1"] or off["q3"] < on["q1"])

    summary = {
        "per_arm_kept": on["n"],
        "on": on,
        "off": off,
        "overhead_pct_median": round(overhead_pct, 3),
        "ranges_overlap": overlap,
        "iqr_overlap": iqr_overlap,
        "determinism_ok": on["token_counts"] == off["token_counts"]
        and len(on["token_counts"]) == 1,
        "verdict": (
            "indistinguishable from noise"
            if overlap
            else f"separated: audit costs ~{overhead_pct:.2f}% tokens/s"
        ),
    }
    with open(os.path.join(OUT_DIR, "point1_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    sys.exit(main())
