"""KV Persistence benchmark — probe + native arms (resume / re-prefill).

Internal capability map: KV Persistence = N6 (save_state / load_state ->
backend state_get / state_set -> llama_state_seq_get/set_data). Public
name "KV Persistence" everywhere in reports.

Three things live here, selected by ``--mode``:

- ``probe`` — the step-0 PROBE-GATE (three questions, run before any grid):
  1. ROUND-TRIP INTEGRITY (corruption gate, blocking): prefill a prefix,
     take a greedy reference continuation, save_state -> FRESH backend ->
     load_state -> continue; the restored continuation must be
     token-identical. A divergence is a DEFECT, not a slow number — stop.
  2. UNIFIED-KV INTERACTION: seed a slot from a prefix holder via seq_cp
     (shared cells, the Run 3/4 kv_unified path), then state_get. Does the
     blob serialize the FULL LOGICAL context (self-contained, restorable
     without the holder, size ~ n_past x cell-weight) or only the UNIQUE
     cells (cheap, restorable only against a live holder) — or does it
     FAIL to compose? Blob size vs the two predictions plus a
     restore-without-holder check decide the branch.
  3. BLOB SCALING: measured bytes vs n_past at {500, 1500, 3000} against
     the 28.0 KiB/token cell weight (1.5B, Run 3).

- ``resume`` — the persistence treatment: read a previously-saved blob
  (from RAM for the in-memory primitive cost, or from disk via an
  UNBUFFERED read that bypasses the OS page cache for an honest warm-disk
  resume), load_state, and continue one short turn. Reports write / read /
  state_set times separately — they have different natures.

- ``reprefill`` — the mechanism baseline: prefill the whole prefix from
  scratch, then continue. ours-resume / ours-reprefill = the mechanism
  ratio (reuse vs recompute on our own scheduler — never "vs
  llama-server").

Cold-cache discipline (methodological requirement, see ``_read_unbuffered``):
the disk-resume read is issued with FILE_FLAG_NO_BUFFERING so a
just-written blob is NOT served from the OS page cache — otherwise the
break-even is unearned. The SSD controller cache cannot be defeated from
user space and is declared as a residual in the report.
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import json
import os
import platform
import statistics
import tempfile
import time
from _workload import big_system_prompt, session_suffix
from bench_shared_prefix import SYSTEM_FMT, USER_FMT, make_backend, mem_snapshot

GEN_TOKENS = 64  # continuation length after a resume / reprefill (plan §3)
REF_TOKENS = 16  # greedy reference length in the round-trip integrity check


def _now() -> float:
    return time.perf_counter()


# ── unbuffered (cache-bypassing) file read for the honest disk path ────────

_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_FLAG_NO_BUFFERING = 0x20000000
_SECTOR = 4096  # NO_BUFFERING requires sector-aligned buffer + length


def _read_unbuffered(path: str) -> bytes:
    """Read a whole file bypassing the Windows page cache.

    FILE_FLAG_NO_BUFFERING guarantees the bytes come from the device, not
    from RAM where a just-written blob would otherwise sit — the honest
    warm-disk resume number. Reads are issued into a sector-aligned buffer
    in sector-multiple chunks (the flag's hard requirement); the final
    short tail is recovered with a normal buffered read of just those
    bytes (negligible, already past the cache question for the bulk).
    """
    size = os.path.getsize(path)
    aligned = (size // _SECTOR) * _SECTOR
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(
        path,
        _GENERIC_READ,
        _FILE_SHARE_READ,
        None,
        _OPEN_EXISTING,
        _FILE_FLAG_NO_BUFFERING,
        None,
    )
    if handle == -1 or handle == ctypes.c_void_p(-1).value:
        raise OSError(f"CreateFileW failed for {path}: {ctypes.GetLastError()}")
    try:
        # over-allocate one sector so the last full-sector read never runs
        # past the buffer even when size is not a sector multiple.
        buf = (ctypes.c_char * (aligned + _SECTOR))()
        read = ctypes.wintypes.DWORD(0)
        ok = kernel32.ReadFile(handle, buf, aligned, ctypes.byref(read), None)
        if not ok:
            raise OSError(f"ReadFile failed: {ctypes.GetLastError()}")
        out = bytes(buf[: read.value])
    finally:
        kernel32.CloseHandle(handle)
    if aligned < size:
        with open(path, "rb") as fh:
            fh.seek(aligned)
            out += fh.read(size - aligned)
    return out


# ── blob production (framed like NativeSession.save_state) ─────────────────


def _prefix_tokens(backend, prefix_tokens: int, sess: int) -> list[int]:
    text = SYSTEM_FMT.format(sp=big_system_prompt(prefix_tokens)) + USER_FMT.format(
        msg=session_suffix(sess)
    )
    return backend.tokenize(text, add_special=True)


def _prefill(backend, seq_id: int, toks: list[int]):
    from palimpsests.providers.native.backend import BatchEntry

    return backend.decode([BatchEntry(seq_id=seq_id, tokens=toks, start_pos=0, wants_logits=True)])


def _greedy(logits) -> int:
    import numpy as np

    return int(np.argmax(logits))


def _continue(backend, seq_id: int, first_logits, start_pos: int, n: int) -> list[int]:
    from palimpsests.providers.native.backend import BatchEntry

    out = [_greedy(first_logits)]
    pos = start_pos
    for _ in range(n - 1):
        res = backend.decode(
            [BatchEntry(seq_id=seq_id, tokens=[out[-1]], start_pos=pos, wants_logits=True)]
        )
        out.append(_greedy(res[seq_id]))
        pos += 1
    return out


# ── mode: probe ────────────────────────────────────────────────────────────


def run_probe(args: argparse.Namespace) -> None:
    from palimpsests.providers.native.backend import BatchEntry

    result = {"scenario": {"kv_unified": bool(args.kv_unified)}, "q1": [], "q3": []}

    def emit(tag, **kw):
        e = {"probe": tag, **kw}
        print(f"PROBE {json.dumps(e)}", flush=True)
        return e

    # ── Q1 round-trip integrity + Q3 blob scaling (share the prefill) ─────
    for p in (500, 1500, 3000):
        backend = make_backend_for(args)
        toks = _prefix_tokens(backend, p, 0)
        first = _prefill(backend, 0, toks)[0]
        n_past = len(toks)
        # Save the blob NOW — before the reference continuation advances this
        # sequence's KV past n_past (otherwise state_get captures the extra
        # cells and the restore feeds ref[0] into an occupied position).
        blob = state_blob(backend, 0)
        ref = _continue(backend, 0, first, n_past, REF_TOKENS)
        backend.close()

        # restore into a FRESH backend (no shared holder, no residual KV)
        backend2 = make_backend_for(args)
        seq_set(backend2, 0, blob)
        # continue: the saved KV holds positions 0..n_past-1; feed ref[0] at
        # n_past (decoding into an occupied position returns -1 on this build)
        out2 = backend2.decode(
            [BatchEntry(seq_id=0, tokens=[ref[0]], start_pos=n_past, wants_logits=True)]
        )
        restored = [ref[0]] + _continue(backend2, 0, out2[0], n_past + 1, REF_TOKENS - 1)
        backend2.close()

        ok = restored == ref
        kib_per_tok = len(blob) / n_past / 1024
        result["q1"].append(
            emit(
                "roundtrip",
                prefix=p,
                n_past=n_past,
                token_identical=ok,
                blob_bytes=len(blob),
                kib_per_tok=round(kib_per_tok, 2),
            )
        )
        result["q3"].append({"n_past": n_past, "blob_bytes": len(blob)})
        if not ok:
            emit("CORRUPTION_GATE_FAILED", prefix=p, ref=ref, restored=restored)
            print("PROBE JSON:", json.dumps(result), flush=True)
            return

    # ── Q2 unified-KV interaction (the sharpest question) ─────────────────
    # Seed a slot from a prefix holder via seq_cp (shared cells), give it a
    # unique suffix, then state_get. Size decides FULL-LOGICAL vs UNIQUE-ONLY.
    from palimpsests.providers.native.scheduler import Scheduler

    backend = make_backend_for(args)
    sch = Scheduler(backend, max_active=2)
    holder = sch.reserve_prefix_holder()
    prefix_only = backend.tokenize(SYSTEM_FMT.format(sp=big_system_prompt(1500)), add_special=True)
    plen = sch.warm_prefix(holder, prefix_only)
    seq = sch.open_slot()
    sch.copy_prefix_to_slot(holder, seq, plen)
    suffix = backend.tokenize(USER_FMT.format(msg=session_suffix(0)), add_special=False)
    # Decode the suffix directly (not run_turn) so we control the KV position:
    # the slot now holds plen shared prefix cells + len(suffix) unique cells.
    first_shared = backend.decode(
        [BatchEntry(seq_id=seq, tokens=suffix, start_pos=plen, wants_logits=True)]
    )[seq]
    n_past_shared = plen + len(suffix)
    # Save BEFORE the reference continuation (same reason as Q1).
    blob_shared = backend.state_get(seq)
    ref_shared = _continue(backend, seq, first_shared, n_past_shared, REF_TOKENS)
    pred_full = 28.0 * n_past_shared * 1024
    pred_unique = 28.0 * len(suffix) * 1024
    d_full = abs(len(blob_shared) - pred_full) / pred_full
    d_uniq = abs(len(blob_shared) - pred_unique) / pred_unique
    branch = "FULL-LOGICAL" if d_full < d_uniq else "UNIQUE-ONLY"
    emit(
        "unified_blob",
        n_past=n_past_shared,
        suffix_len=len(suffix),
        blob_bytes=len(blob_shared),
        pred_full_bytes=int(pred_full),
        pred_unique_bytes=int(pred_unique),
        closer_to=branch,
    )
    backend.close()

    # restorability WITHOUT the holder: fresh backend, state_set, continue
    backend3 = make_backend_for(args)
    restorable = False
    err = ""
    try:
        seq_set(backend3, 0, blob_shared)
        out = backend3.decode(
            [
                BatchEntry(
                    seq_id=0,
                    tokens=[ref_shared[0]],
                    start_pos=n_past_shared,
                    wants_logits=True,
                )
            ]
        )
        cont = [ref_shared[0]] + _continue(
            backend3, 0, out[0], n_past_shared + 1, len(ref_shared) - 1
        )
        restorable = cont == ref_shared
    except Exception as exc:  # noqa: BLE001 - the FAILURE branch is data
        err = repr(exc)
    backend3.close()
    activated = (
        "FULL-LOGICAL"
        if (branch == "FULL-LOGICAL" and restorable)
        else "UNIQUE-ONLY"
        if restorable
        else "FAILURE"
    )
    result["q2"] = emit(
        "unified_restore",
        restorable_without_holder=restorable,
        error=err,
        size_branch=branch,
        activated_branch=activated,
    )
    print("PROBE JSON:", json.dumps(result), flush=True)


# ── backend / state helpers (probe uses a bare backend, no scheduler) ─────


def make_backend_for(args: argparse.Namespace):
    class _A:
        model = args.model
        n_ctx = args.n_ctx
        n_seq_max = args.n_seq_max
        n_gpu_layers = args.n_gpu_layers
        kv_unified = args.kv_unified

    return make_backend(_A())


def state_blob(backend, seq_id: int) -> bytes:
    return backend.state_get(seq_id)


def seq_set(backend, seq_id: int, blob: bytes) -> None:
    backend.state_set(seq_id, blob)


# ── modes: resume / reprefill (one grid point) ─────────────────────────────


def _run_batched(scheduler, seq_ids: list[int], t0: float) -> dict:
    """Drive the scheduler's batched step loop across seq_ids until every
    slot's turn finishes; return per-session TTFT (first token, from t0)
    and completion. This mirrors the server's continuous batching so the
    M-concurrent walls are comparable — a slot generating alone would make
    the native arm pay M sequential generations vs the server's one batch.
    """
    ttft: dict[int, float] = {}
    done: dict[int, float] = {}
    live = set(seq_ids)
    while live:
        produced = scheduler.step()
        for st in produced:
            if st.seq_id not in ttft:
                ttft[st.seq_id] = _now() - t0
            if st.done:
                done[st.seq_id] = _now() - t0
                live.discard(st.seq_id)
    return {
        "ttft": [ttft[s] for s in seq_ids],
        "done_at": [done.get(s, -1.0) for s in seq_ids],
    }


def run_point(args: argparse.Namespace) -> None:
    from palimpsests.providers.native.scheduler import Scheduler

    backend = make_backend_for(args)
    mem_snapshot("after_load")
    per_sess_toks = [_prefix_tokens(backend, args.prefix_tokens, i) for i in range(args.sessions)]
    n_past = [len(t) for t in per_sess_toks]
    cont_first = backend.tokenize(" Continue.", add_special=False)[:1]

    blob_dir = tempfile.mkdtemp(prefix="bench-persist-")
    blobs_mem: list[bytes] = []
    blob_paths: list[str] = []
    write_times: list[float] = []
    if args.mode == "resume":
        # Pre-produce one saved blob per session on a scratch scheduler.
        # NOT timed as resume; write time is the separate "checkpoint" cost.
        for i, toks in enumerate(per_sess_toks):
            _prefill(backend, 0, toks)
            blob = state_blob(backend, 0)
            backend.seq_remove(0)
            blobs_mem.append(blob)
            path = os.path.join(blob_dir, f"s{i}.bin")
            t = _now()
            with open(path, "wb") as fh:
                fh.write(blob)
                fh.flush()
                os.fsync(fh.fileno())
            write_times.append(_now() - t)
            blob_paths.append(path)

    def one_repeat_resume() -> dict:
        scheduler = Scheduler(backend, max_active=args.sessions)
        read_s, set_s = [], []
        t0 = _now()
        seq_ids = []
        for i in range(args.sessions):
            seq = scheduler.open_slot()
            seq_ids.append(seq)
            tr = _now()
            blob = blobs_mem[i] if args.resume_path == "memory" else _read_unbuffered(blob_paths[i])
            read_s.append(_now() - tr)
            ts = _now()
            # load_slot_state = backend.state_set + seed_n_past (the product
            # path). Blobs here are raw backend payloads (no NativeSession
            # frame), so hand them straight to the scheduler.
            scheduler.load_slot_state(seq, blob, n_past[i])
            set_s.append(_now() - ts)
            # Seed generation: feed the continuation token at n_past so the
            # batched loop produces GEN tokens (state carries no logits).
            scheduler.feed(seq, cont_first, max_tokens=GEN_TOKENS)
        batched = _run_batched(scheduler, seq_ids, t0)
        wall = _now() - t0
        for seq in seq_ids:
            scheduler.close_slot(seq)
        return {"wall": wall, "read_s": read_s, "set_s": set_s, **batched}

    def one_repeat_reprefill() -> dict:
        scheduler = Scheduler(backend, max_active=args.sessions)
        t0 = _now()
        seq_ids = []
        for i in range(args.sessions):
            seq = scheduler.open_slot()
            seq_ids.append(seq)
            # Feed the full prefix as the turn input: the scheduler prefills
            # it and generates GEN tokens — prefill(P) is exactly the cost
            # KV Persistence avoids.
            scheduler.feed(seq, per_sess_toks[i], max_tokens=GEN_TOKENS)
        batched = _run_batched(scheduler, seq_ids, t0)
        wall = _now() - t0
        for seq in seq_ids:
            scheduler.close_slot(seq)
        return {"wall": wall, **batched}

    fn = one_repeat_resume if args.mode == "resume" else one_repeat_reprefill
    fn()  # warmup
    reps = [fn() for _ in range(args.repeats)]
    mem_snapshot("after_repeats")

    walls = [r["wall"] for r in reps]
    summary = {
        "label": f"persist_{args.mode}_{args.resume_path if args.mode == 'resume' else 'na'}",
        "prefix_tokens_measured": n_past[0],
        "sessions": args.sessions,
        "repeats": args.repeats,
        "wall_seconds_median": statistics.median(walls),
        "wall_seconds_min": min(walls),
        "wall_seconds_max": max(walls),
        "ttft_first_session_median": statistics.median([r["ttft"][0] for r in reps]),
        "blob_bytes": len(blobs_mem[0]) if blobs_mem else None,
        "write_seconds_median": statistics.median(write_times) if write_times else None,
        "read_seconds_median": statistics.median([s for r in reps for s in r.get("read_s", [])])
        if args.mode == "resume"
        else None,
        "state_set_seconds_median": statistics.median([s for r in reps for s in r.get("set_s", [])])
        if args.mode == "resume"
        else None,
    }
    env = {
        "python": platform.python_version(),
        "mode": args.mode,
        "resume_path": args.resume_path if args.mode == "resume" else None,
        "model": args.model,
        "n_ctx": args.n_ctx,
        "n_seq_max": args.n_seq_max,
        "kv_unified": bool(args.kv_unified),
        "gen_tokens": GEN_TOKENS,
        "sampling": "greedy (argmax)",
    }
    print(f"\n=== KV Persistence {args.mode} ({env['resume_path']}) ===")
    print(f"environment: {json.dumps(env)}")
    print(
        f"{args.mode}: median {summary['wall_seconds_median']:.4f}s "
        f"[{summary['wall_seconds_min']:.4f}-{summary['wall_seconds_max']:.4f}]"
    )
    print("\nJSON:")
    print(json.dumps({"env": env, "summary": summary, "per_repeat": reps}, indent=2))
    backend.close()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", required=True, choices=["probe", "resume", "reprefill"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--n-ctx", type=int, default=32768)
    ap.add_argument("--n-seq-max", type=int, default=8)
    ap.add_argument("--n-gpu-layers", type=int, default=999)
    ap.add_argument("--kv-unified", type=int, default=1)
    ap.add_argument("--prefix-tokens", type=int, default=1500)
    ap.add_argument("--sessions", type=int, default=1)
    ap.add_argument("--resume-path", choices=["memory", "disk"], default="disk")
    ap.add_argument("--repeats", type=int, default=5)
    args = ap.parse_args()
    if args.mode == "probe":
        run_probe(args)
    else:
        run_point(args)


if __name__ == "__main__":
    main()
