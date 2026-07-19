"""N4 shared-prefix benchmark — native arms (ours + mechanism) and memory probe.

Three things live here, selected by ``--mode``:

- ``probe`` — the Run 3 step-0 MEMORY-PROBE: does ``seq_copy``
  (``llama_memory_seq_cp``) physically COPY the prefix KV cells into the
  destination sequence, or SHARE them (ref/COW)? Protocol: warm a prefix
  into a holder sequence, copy it into K slots, snapshot memory after
  every copy, then decode a few tokens in some copied slots and re-measure
  (a COW copy may materialize on first write — "shares until first decode"
  is copying in practice). The decisive indirect evidence is
  capacity-to-failure: with a fixed cell budget, K copies of an L-token
  prefix either fit (shared, ~L cells total) or exhaust the pool at
  ~K x L cells (copied). Process RSS cannot decide this alone because
  llama.cpp preallocates the whole KV buffer at context creation.
- ``ours`` — the N4 treatment arm: one prefix holder is warmed once
  (``warm_prefix``), every session's slot is seeded from it
  (``copy_prefix_to_slot`` = ``seq_copy`` + ``seed_n_past``), then the
  session decodes its short unique suffix and generates. Sessions beyond
  ``--max-active`` wait for a freed slot; a freed slot is re-seeded by
  another copy from the holder — never by re-prefill.
- ``mech`` — the mechanism baseline: identical scheduler, identical
  context configuration, but NO holder — every session prefills
  prefix+suffix from scratch. The ours/mech ratio isolates
  reuse-vs-recompute on our own stack (the clean mechanism signal; the
  competitive number lives in ``bench_shared_prefix_server.py``).

Faithfulness rules (one variable at a time):
- workload content comes from ``_workload`` (never copied): the big
  system prefix, the per-session suffix, generation length;
- turn formatting mirrors ``NativeSession`` verbatim (``system: {sp}\\n``,
  ``user: {msg}\\nassistant:``) so the server arm can drive byte-identical
  content;
- ``ours`` and ``mech`` construct the SAME backend (same n_ctx,
  n_seq_max, ngl); the mechanism arm simply never uses the holder APIs.

``--kv-unified`` (probe + arms): the pinned ``LlamaCppBackend`` does not
expose llama.cpp's ``kv_unified`` context flag (its contexts are created
with the default, non-unified per-sequence KV streams). To measure both
memory modes WITHOUT forking the measured code, this harness briefly wraps
``llama_context_default_params`` so the backend's own unchanged
``__init__`` sees ``kv_unified=True``; every other parameter path is the
backend's own. The report's config block must state which mode each
number was measured in.

Usage (one invocation = one grid point or one probe scenario; prints a
human summary plus a JSON blob):

    python benchmarks/bench_shared_prefix.py --mode probe \
        --model models/M.gguf --n-gpu-layers 999 --n-ctx 8192 \
        --n-seq-max 9 --prefix-tokens 1500 --copies 8 --decode-slots 3

    python benchmarks/bench_shared_prefix.py --mode ours \
        --model models/M.gguf --n-gpu-layers 999 --n-ctx 36864 \
        --n-seq-max 9 --max-active 8 --prefix-tokens 1500 --sessions 8 \
        --repeats 5
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import json
import os
import platform
import statistics
import time
from _workload import GEN_TOKENS_N4, big_system_prompt, session_suffix

# Turn formatting mirrored from palimpsests.providers.native.session (the
# native session's single source of formatting) — same constants as
# bench_tool_loop_server.py; the server arm reuses them for byte-identity.
SYSTEM_FMT = "system: {sp}\n"
USER_FMT = "user: {msg}\nassistant:"


def _now() -> float:
    return time.perf_counter()


# ── memory instrumentation (self process + system) ────────────────────────


class _PMC(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.wintypes.DWORD),
        ("PageFaultCount", ctypes.wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


class _MEMSTATUS(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.wintypes.DWORD),
        ("dwMemoryLoad", ctypes.wintypes.DWORD),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


def mem_snapshot(tag: str) -> dict:
    """One honest memory reading, printed immediately (crash-safe).

    Reports the benchmark process's working set and commit (psapi) plus
    system-wide available physical memory (GlobalMemoryStatusEx). On this
    UMA iGPU, Vulkan device-local allocations live in system RAM; whether
    the driver charges them to the process or not, the system-available
    counter moves — both are recorded, neither alone is claimed as "GPU
    memory". Cell-level accounting (the probe's real question) comes from
    capacity-to-failure, not from these numbers.
    """
    # OpenProcess on our own pid rather than the GetCurrentProcess pseudo
    # handle: through bare ctypes.windll the pseudo handle truncates to a
    # 32-bit int and GetProcessMemoryInfo silently fails (the Run 1 native
    # RSS artifact); the real-handle path is the one the Run 1 server arm
    # already proved out.
    pmc = _PMC()
    pmc.cb = ctypes.sizeof(_PMC)
    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, os.getpid())
    if handle:
        try:
            ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb)
        finally:
            ctypes.windll.kernel32.CloseHandle(handle)
    ms = _MEMSTATUS()
    ms.dwLength = ctypes.sizeof(_MEMSTATUS)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms))
    snap = {
        "tag": tag,
        "ws_mb": pmc.WorkingSetSize / 2**20,
        "peak_ws_mb": pmc.PeakWorkingSetSize / 2**20,
        "commit_mb": pmc.PagefileUsage / 2**20,
        "peak_commit_mb": pmc.PeakPagefileUsage / 2**20,
        "sys_avail_phys_mb": ms.ullAvailPhys / 2**20,
    }
    print(f"MEMSNAP {json.dumps(snap)}", flush=True)
    return snap


# ── backend construction (with the kv_unified wrapper) ────────────────────


def make_backend(args: argparse.Namespace):
    """Construct the pinned ``LlamaCppBackend`` exactly as the campaign
    measures it, optionally flipping llama.cpp's ``kv_unified`` context
    flag via a scoped wrapper around ``llama_context_default_params`` (the
    backend itself has no such knob — see module docstring)."""
    from palimpsests.providers.native.llamacpp_backend import LlamaCppBackend

    if not args.kv_unified:
        return LlamaCppBackend(
            args.model,
            n_ctx=args.n_ctx,
            n_seq_max=args.n_seq_max,
            n_gpu_layers=args.n_gpu_layers,
        )
    from llama_cpp import llama_cpp as lib

    orig = lib.llama_context_default_params

    def patched():
        p = orig()
        p.kv_unified = True
        return p

    lib.llama_context_default_params = patched
    try:
        return LlamaCppBackend(
            args.model,
            n_ctx=args.n_ctx,
            n_seq_max=args.n_seq_max,
            n_gpu_layers=args.n_gpu_layers,
        )
    finally:
        lib.llama_context_default_params = orig


def _seq_pos_max(backend, seq_id: int) -> int:
    """Highest KV position of a sequence (verifies a copy landed)."""
    lib = backend._lib
    mem = lib.llama_get_memory(backend._ctx)
    return int(lib.llama_memory_seq_pos_max(mem, seq_id))


def _state_seq_size(backend, seq_id: int) -> int:
    """Serialized size of one sequence's KV — LOGICAL size (a shared cell
    serializes into every sequence that references it), so this cannot
    distinguish share from copy; recorded as supporting data only."""
    return int(backend._lib.llama_state_seq_get_size(backend._ctx, seq_id))


# ── mode: probe ───────────────────────────────────────────────────────────


def run_probe(args: argparse.Namespace) -> None:
    """Step-0 memory probe. One scenario per process invocation, because a
    failed llama_decode may be a hard GGML abort (no Python recovery) —
    every observation is printed the moment it exists."""
    from palimpsests.providers.native.backend import BatchEntry

    print(
        f"PROBE start: n_ctx={args.n_ctx} n_seq_max={args.n_seq_max} "
        f"kv_unified={bool(args.kv_unified)} prefix~{args.prefix_tokens} "
        f"copies={args.copies} decode_slots={args.decode_slots}",
        flush=True,
    )
    t0 = _now()
    backend = make_backend(args)
    print(f"backend constructed in {_now() - t0:.1f}s", flush=True)
    mem_snapshot("after_load")

    prefix_text = SYSTEM_FMT.format(sp=big_system_prompt(args.prefix_tokens))
    toks = backend.tokenize(prefix_text, add_special=True)
    print(f"measured prefix tokens: {len(toks)}", flush=True)

    result: dict = {
        "scenario": {
            "n_ctx": args.n_ctx,
            "n_seq_max": args.n_seq_max,
            "kv_unified": bool(args.kv_unified),
            "prefix_tokens_measured": len(toks),
            "copies": args.copies,
        },
        "events": [],
    }

    def event(name: str, **kw) -> None:
        e = {"event": name, **kw}
        result["events"].append(e)
        print(f"EVENT {json.dumps(e)}", flush=True)

    # 1) warm the prefix into the holder sequence (seq 0).
    try:
        t = _now()
        backend.decode([BatchEntry(seq_id=0, tokens=toks, start_pos=0)])
        event("warm_ok", seconds=round(_now() - t, 3))
    except RuntimeError as exc:
        event("warm_failed", error=str(exc))
        mem_snapshot("after_warm_failed")
        print("PROBE JSON:", json.dumps(result), flush=True)
        backend.close()
        return
    mem_snapshot("after_warm")
    event(
        "holder_state",
        pos_max=_seq_pos_max(backend, 0),
        state_seq_bytes=_state_seq_size(backend, 0),
    )

    # 2) copy into K slots, memory after every copy.
    copied: list[int] = []
    for k in range(1, args.copies + 1):
        try:
            t = _now()
            backend.seq_copy(0, k)
            dt = _now() - t
        except RuntimeError as exc:
            event("copy_failed", dst=k, error=str(exc))
            break
        copied.append(k)
        event("copy_ok", dst=k, seconds=round(dt, 4), pos_max=_seq_pos_max(backend, k))
        if k in (1, 2, 4, 8) or k == args.copies:
            mem_snapshot(f"after_copy_{k}")

    # 3) the COW question: decode a short burst in a few copied slots —
    #    if the copy was lazy, the first write materializes it.
    plen = len(toks)
    burst = backend.tokenize(" The next step is ready.", add_special=False)
    for k in copied[: args.decode_slots]:
        try:
            t = _now()
            backend.decode([BatchEntry(seq_id=k, tokens=burst, start_pos=plen)])
            event("decode_ok", seq=k, tokens=len(burst), seconds=round(_now() - t, 3))
        except RuntimeError as exc:
            event("decode_failed", seq=k, error=str(exc))
            break
        mem_snapshot(f"after_decode_seq{k}")

    # 4) capacity-to-failure: how many more prefix copies + writes fit?
    #    (only when asked — this deliberately drives into decode failure)
    if args.capacity_push:
        for k in range(len(copied) + 1, args.n_seq_max):
            try:
                backend.seq_copy(0, k)
                backend.decode([BatchEntry(seq_id=k, tokens=burst, start_pos=plen)])
                event("capacity_seq_ok", seq=k)
            except RuntimeError as exc:
                event("capacity_exhausted", seq=k, error=str(exc))
                break
        mem_snapshot("after_capacity_push")

    print("PROBE JSON:", json.dumps(result), flush=True)
    backend.close()


# ── modes: ours / mech (one grid point) ───────────────────────────────────


def run_point(args: argparse.Namespace) -> None:
    """One (prefix x sessions) point of the N4 grid, one arm.

    All M sessions "arrive" at t0 (concurrent workload): up to
    ``--max-active`` run batched; the rest queue and are admitted into
    freed slots. Per-session TTFT is measured from t0, so queue wait is
    part of TTFT — that IS the contention signal at M > P.
    """
    from palimpsests.providers.native.scheduler import Scheduler

    backend = make_backend(args)
    mem_snapshot("after_load")
    prefix_text = SYSTEM_FMT.format(sp=big_system_prompt(args.prefix_tokens))
    prefix_toks = backend.tokenize(prefix_text, add_special=True)
    suffix_toks = [
        backend.tokenize(USER_FMT.format(msg=session_suffix(i)), add_special=False)
        for i in range(args.sessions)
    ]
    # The mechanism arm prefills prefix+suffix as ONE prompt, tokenized
    # whole (same text the treatment splits into prefix/suffix; the split
    # point falls on the same "\n" boundary NativeSession uses, so the
    # token streams are identical — verified by the measured counts).
    full_toks = [
        backend.tokenize(prefix_text + USER_FMT.format(msg=session_suffix(i)), add_special=True)
        for i in range(args.sessions)
    ]

    def one_repeat() -> dict:
        scheduler = Scheduler(backend, max_active=args.max_active)
        t0 = _now()
        warm_s = 0.0
        holder = None
        plen = 0
        if args.mode == "ours":
            holder = scheduler.reserve_prefix_holder()
            t = _now()
            plen = scheduler.warm_prefix(holder, prefix_toks)
            warm_s = _now() - t
        queue = list(range(args.sessions))
        active: dict[int, int] = {}  # seq_id -> session index
        ttft: dict[int, float] = {}
        done_at: dict[int, float] = {}
        copy_s: list[float] = []
        while queue or active:
            while queue and len(active) < args.max_active:
                i = queue.pop(0)
                seq = scheduler.open_slot()
                if args.mode == "ours":
                    t = _now()
                    scheduler.copy_prefix_to_slot(holder, seq, plen)
                    copy_s.append(_now() - t)
                    scheduler.feed(seq, suffix_toks[i], max_tokens=args.gen_tokens)
                else:
                    scheduler.feed(seq, full_toks[i], max_tokens=args.gen_tokens)
                active[seq] = i
            for st in scheduler.step():
                i = active.get(st.seq_id)
                if i is None:
                    continue
                if i not in ttft:
                    ttft[i] = _now() - t0
                if st.done:
                    done_at[i] = _now() - t0
                    scheduler.close_slot(st.seq_id)
                    del active[st.seq_id]
        wall = _now() - t0
        if holder is not None:
            scheduler.release_prefix_holder(holder)
        return {
            "wall_seconds": wall,
            "warm_seconds": warm_s,
            "copy_seconds": copy_s,
            "ttft_per_session": [ttft[i] for i in sorted(ttft)],
            "done_at_per_session": [done_at[i] for i in sorted(done_at)],
        }

    one_repeat()  # warmup, discarded
    repeats = [one_repeat() for _ in range(args.repeats)]
    mem_snapshot("after_repeats")

    walls = [r["wall_seconds"] for r in repeats]
    ttft_medians = [statistics.median(r["ttft_per_session"]) for r in repeats]
    ttft_firsts = [r["ttft_per_session"][0] for r in repeats]
    summary = {
        "label": f"n4_{args.mode}",
        "prefix_tokens_measured": len(prefix_toks),
        "suffix_tokens": [len(t) for t in suffix_toks],
        "full_prompt_tokens": [len(t) for t in full_toks],
        "sessions": args.sessions,
        "max_active": args.max_active,
        "repeats": args.repeats,
        "wall_seconds_median": statistics.median(walls),
        "wall_seconds_min": min(walls),
        "wall_seconds_max": max(walls),
        "ttft_first_session_median": statistics.median(ttft_firsts),
        "ttft_session_median_of_medians": statistics.median(ttft_medians),
        "warm_seconds_median": statistics.median([r["warm_seconds"] for r in repeats]),
        "copy_seconds_all": [s for r in repeats for s in r["copy_seconds"]],
    }
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "model": args.model,
        "mode": args.mode,
        "n_ctx": args.n_ctx,
        "n_seq_max": args.n_seq_max,
        "kv_unified": bool(args.kv_unified),
        "n_gpu_layers": args.n_gpu_layers,
        "gen_tokens": args.gen_tokens,
        "sampling": "greedy (argmax), stop_tokens=()",
    }
    print(f"\n=== N4 {args.mode} arm ===")
    print(f"environment: {json.dumps(env)}")
    print(
        f"{args.mode}: median {summary['wall_seconds_median']:.3f}s "
        f"[{summary['wall_seconds_min']:.3f}-{summary['wall_seconds_max']:.3f}], "
        f"TTFT(first) {summary['ttft_first_session_median']:.3f}s"
    )
    print("\nJSON:")
    print(json.dumps({"env": env, "summary": summary, "per_repeat": repeats}, indent=2))
    backend.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=["probe", "ours", "mech"])
    parser.add_argument("--model", required=True)
    parser.add_argument("--n-ctx", type=int, default=8192)
    parser.add_argument("--n-seq-max", type=int, default=9)
    parser.add_argument("--n-gpu-layers", type=int, default=999)
    parser.add_argument("--kv-unified", type=int, default=0)
    parser.add_argument("--prefix-tokens", type=int, default=1500)
    # probe knobs
    parser.add_argument("--copies", type=int, default=8)
    parser.add_argument("--decode-slots", type=int, default=3)
    parser.add_argument("--capacity-push", type=int, default=0)
    # grid knobs
    parser.add_argument("--sessions", type=int, default=1)
    parser.add_argument("--max-active", type=int, default=8)
    parser.add_argument("--gen-tokens", type=int, default=GEN_TOKENS_N4)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()

    if args.mode == "probe":
        run_probe(args)
    else:
        run_point(args)


if __name__ == "__main__":
    main()
