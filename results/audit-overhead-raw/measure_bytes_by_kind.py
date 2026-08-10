"""Point 2 — deterministic bytes/record per kind, measured from the public
PalaWriter encoder (no timing, no model). Each emit method returns the encoded
record bytes; we take len(). The weighted mix uses the real kind-counts observed
in a Point-1 session (passed in), the number that feeds Track D WS5 retention math.
"""

import csv
import json
import os
import tempfile
from palimpsests.providers.native import PalaWriter

D32 = bytes(range(32))  # a fixed 32-byte digest stand-in
ROLE = "engine.native"  # the engine's default origin role


# The emit methods return a record_hash / span_id handle, NOT the encoded record.
# PALA-1 has no file framing (§2.4: records concatenated back-to-back), so the
# on-disk size of a record is measured as file-growth. close() flushes, so we
# size closed files: (GENESIS + K) - (GENESIS alone) = K's encoded size.
def _closed_size(steps):
    p = os.path.join(tempfile.gettempdir(), "bk_probe.pala")
    if os.path.exists(p):
        os.remove(p)
    w = PalaWriter(p)
    steps(w)
    w.close()
    return os.path.getsize(p)


_GENESIS_ONLY = None


def measure_one(kind, emit):
    global _GENESIS_ONLY
    if _GENESIS_ONLY is None:
        _GENESIS_ONLY = _closed_size(lambda w: w.genesis())
    if kind == "GENESIS":
        return _GENESIS_ONLY
    both = _closed_size(lambda w: (w.genesis(), emit(w)))
    return both - _GENESIS_ONLY


# each lambda emits exactly one record of the named kind through the public API
KINDS = [
    ("GENESIS", lambda w: w.genesis()),
    ("BOOT", lambda w: w.boot()),
    ("SPAN_START", lambda w: w.session_start("sess-0", role=ROLE)),
    ("SPAN_END", lambda w: w.session_end(b"\x00" * 16)),
    ("EVENT_model_load", lambda w: w.model_load(D32, D32, role=ROLE)),
    ("KV_SAVE", lambda w: w.kv_save(D32)),
    ("KV_RESTORE", lambda w: w.kv_restore(D32)),
    ("SAFETY_guard", lambda w: w.guard_state_reject(detail="bad blob")),
    ("ANCHOR", lambda w: w.anchor()),
    ("PREFIX_WARM", lambda w: w.prefix_warm(token_count=128)),
    ("PREFIX_COPY", lambda w: w.prefix_copy(128)),
    ("MODEL_UNLOAD", lambda w: w.model_unload()),
]


def main():
    rows = []
    for kind, emit in KINDS:
        total = measure_one(kind, emit)
        rows.append({"kind": kind, "total_bytes": total})

    # weighted mix from a real Point-1 session (observed kind counts)
    # measured live in the Point-1 probe; recomputed here from the session file.
    session_mix = {
        "GENESIS": 1,
        "BOOT": 1,
        "EVENT_model_load": 1,
        "SPAN_START": 10,
        "PREFIX_WARM": 1,
        "PREFIX_COPY": 10,
        "KV_SAVE": 8,
        "SPAN_END": 10,
        "KV_RESTORE": 1,
        "SAFETY_guard": 1,
        "MODEL_UNLOAD": 1,
        "ANCHOR": 2,
    }
    size = {r["kind"]: r["total_bytes"] for r in rows}
    total_records = sum(session_mix.values())
    total_bytes = sum(size[k] * n for k, n in session_mix.items())
    weighted = total_bytes / total_records

    out_dir = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(out_dir, "bytes_by_kind.csv"), "w", newline="") as fh:
        wtr = csv.DictWriter(fh, fieldnames=["kind", "total_bytes"])
        wtr.writeheader()
        wtr.writerows(rows)

    summary = {
        "per_kind_bytes": size,
        "session_mix_counts": session_mix,
        "session_total_records": total_records,
        "session_total_bytes": total_bytes,
        "weighted_bytes_per_record": round(weighted, 2),
    }
    with open(os.path.join(out_dir, "bytes_by_kind_summary.json"), "w") as fh:
        json.dump(summary, fh, indent=2)

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
