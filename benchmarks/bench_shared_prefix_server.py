"""N4 honest-baseline arm: shared-prefix sessions against llama-server.

Two modes:

- ``characterize`` — the Run 3 step-1 protocol: on the pinned server,
  drive M sessions (same big system prefix, unique short suffixes)
  SEQUENTIALLY and log, per request, ``prompt_n`` / ``cache_n`` / the slot
  that served it. This answers: (a) does the server reuse the shared
  prefix ACROSS slots or only within a slot; (b) what happens beyond the
  slot budget (eviction -> re-prefill, or prefix-preserving reuse via
  longest-prefix slot selection); (c) what ``--parallel P`` does to
  per-slot context and server memory. The answers pick the honest server
  config for the grid (the strongest opponent for this workload).
- ``grid`` — one (prefix x sessions) point: M sessions fired
  CONCURRENTLY (one thread per session, all released at t0, matching the
  native arms' everything-arrives-at-t0 workload); per-session TTFT is
  measured from t0 so queue wait is part of TTFT, exactly as in
  ``bench_shared_prefix.py``. All slots are erased between repeats
  (self-verified: the repeat's first request must report ``cache_n == 0``)
  so every repeat pays its own prefix prefills, symmetrically to the
  native arms' fresh-scheduler repeats.

Workload content and formatting are imported from ``_workload`` /
mirrored from ``NativeSession`` — byte-identical to the native arms
(one variable at a time).
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes
import httpx
import json
import platform
import statistics
import subprocess
import tempfile
import threading
import time
from _workload import GEN_TOKENS_N4, big_system_prompt, session_suffix
from dataclasses import dataclass

SYSTEM_FMT = "system: {sp}\n"
USER_FMT = "user: {msg}\nassistant:"


def _now() -> float:
    return time.perf_counter()


def _peak_rss_mb(pid: int) -> float | None:
    """Peak working set of a live process, via psapi (no extra deps)."""

    class PMC(ctypes.Structure):
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

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if not handle:
        return None
    try:
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(
            handle, ctypes.byref(pmc), pmc.cb
        )
        return pmc.PeakWorkingSetSize / 2**20 if ok else None
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


@dataclass
class SessionTiming:
    session: int
    seconds: float
    ttft_seconds: float
    prompt_n: int
    cache_n: int
    predicted_n: int
    id_slot: int


class ServerArm:
    """Owns the llama-server lifecycle for one configuration."""

    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base = f"http://127.0.0.1:{args.port}"
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        slot_dir = tempfile.mkdtemp(prefix="bench-n4-slots-")
        cmd = [
            self.args.server_bin,
            "-m",
            self.args.model,
            "--n-gpu-layers",
            str(self.args.n_gpu_layers),
            "--ctx-size",
            str(self.args.n_ctx),
            "--parallel",
            str(self.args.parallel),
            "--port",
            str(self.args.port),
            "--slot-save-path",
            slot_dir,
        ]
        if self.args.kv_unified:
            cmd.append("--kv-unified")
        if self.args.cache_reuse:
            cmd += ["--cache-reuse", str(self.args.cache_reuse)]
        self.proc = subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        deadline = _now() + 180
        with httpx.Client() as client:
            while _now() < deadline:
                try:
                    if client.get(self.base + "/health", timeout=2).status_code == 200:
                        self._session_warm_request()
                        return
                except httpx.HTTPError:
                    time.sleep(0.5)
        raise RuntimeError("llama-server did not become healthy in 180 s")

    def _session_warm_request(self) -> None:
        """One untimed request per server session (Run 0.3 finding) —
        brings allocator/driver to steady state; never caches."""
        httpx.post(
            self.base + "/completion",
            json={
                "prompt": "warm",
                "n_predict": 8,
                "temperature": 0,
                "cache_prompt": False,
            },
            timeout=180,
        )

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.kill()
            self.proc.wait(timeout=30)
            self.proc = None

    def erase_all_slots(self) -> bool:
        ok = True
        for i in range(self.args.parallel):
            try:
                r = httpx.post(self.base + f"/slots/{i}?action=erase", timeout=30)
                ok = ok and r.status_code == 200
            except httpx.HTTPError:
                ok = False
        return ok

    def slots_info(self) -> list | dict | None:
        try:
            return httpx.get(self.base + "/slots", timeout=10).json()
        except (httpx.HTTPError, ValueError):
            return None

    # ── one session = one /completion request ─────────────────────────────

    def run_session(
        self, i: int, prompt: str, t0: float, gen_tokens: int
    ) -> SessionTiming:
        payload = {
            "prompt": prompt,
            "n_predict": gen_tokens,
            "temperature": 0,
            "top_k": 1,
            "ignore_eos": True,
            "cache_prompt": True,
            "stream": True,
        }
        ttft = 0.0
        timings: dict = {}
        id_slot = -1
        with (
            httpx.Client() as client,
            client.stream(
                "POST", self.base + "/completion", json=payload, timeout=1200
            ) as resp,
        ):
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = json.loads(line[len("data: ") :])
                if chunk.get("content") and ttft == 0.0:
                    ttft = _now() - t0
                if "id_slot" in chunk:
                    id_slot = int(chunk["id_slot"])
                if chunk.get("timings"):
                    timings = chunk["timings"]
        return SessionTiming(
            session=i,
            seconds=_now() - t0,
            ttft_seconds=ttft,
            prompt_n=int(timings.get("prompt_n", -1)),
            cache_n=int(timings.get("cache_n", -1)),
            predicted_n=int(timings.get("predicted_n", -1)),
            id_slot=id_slot,
        )


def _prompts(args: argparse.Namespace) -> list[str]:
    prefix = SYSTEM_FMT.format(sp=big_system_prompt(args.prefix_tokens))
    return [
        prefix + USER_FMT.format(msg=session_suffix(i))
        for i in range(args.sessions)
    ]


def run_characterize(args: argparse.Namespace, arm: ServerArm) -> None:
    """Step-1 protocol: sequential sessions, per-request cache accounting."""
    prompts = _prompts(args)
    print(f"slots info at start: {json.dumps(arm.slots_info())[:400]}", flush=True)
    rows = []
    for i, p in enumerate(prompts):
        t0 = _now()
        st = arm.run_session(i, p, t0, args.gen_tokens)
        rows.append(vars(st))
        print(
            f"seq session {i}: slot={st.id_slot} prompt_n={st.prompt_n} "
            f"cache_n={st.cache_n} wall={st.seconds:.3f}s ttft={st.ttft_seconds:.3f}s",
            flush=True,
        )
    print("\nJSON:")
    print(
        json.dumps(
            {
                "mode": "characterize",
                "parallel": args.parallel,
                "n_ctx": args.n_ctx,
                "kv_unified": bool(args.kv_unified),
                "cache_reuse": args.cache_reuse,
                "sessions": rows,
                "server_peak_rss_mb": _peak_rss_mb(arm.proc.pid) if arm.proc else None,
            },
            indent=2,
        )
    )


def run_grid(args: argparse.Namespace, arm: ServerArm) -> None:
    """One grid point: M concurrent sessions, warmup + N timed repeats."""
    prompts = _prompts(args)

    def one_repeat() -> dict:
        results: list[SessionTiming | None] = [None] * len(prompts)
        t0 = _now()

        def worker(i: int) -> None:
            results[i] = arm.run_session(i, prompts[i], t0, args.gen_tokens)

        threads = [
            threading.Thread(target=worker, args=(i,)) for i in range(len(prompts))
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        wall = _now() - t0
        done = [r for r in results if r is not None]
        return {
            "wall_seconds": wall,
            "ttft_per_session": [r.ttft_seconds for r in done],
            "session_walls": [r.seconds for r in done],
            "cache_n": [r.cache_n for r in done],
            "prompt_n": [r.prompt_n for r in done],
            "slots": [r.id_slot for r in done],
        }

    one_repeat()  # warmup repeat, discarded
    repeats = []
    cache_reset_verified = True
    for _ in range(args.repeats):
        arm.erase_all_slots()
        rep = one_repeat()
        if 0 not in rep["cache_n"] and -1 not in rep["cache_n"]:
            cache_reset_verified = False
        repeats.append(rep)

    walls = [r["wall_seconds"] for r in repeats]
    summary = {
        "label": "n4_server",
        "sessions": args.sessions,
        "parallel": args.parallel,
        "repeats": args.repeats,
        "wall_seconds_median": statistics.median(walls),
        "wall_seconds_min": min(walls),
        "wall_seconds_max": max(walls),
        "ttft_first_session_median": statistics.median(
            [min(r["ttft_per_session"]) for r in repeats]
        ),
        "ttft_session_median_of_medians": statistics.median(
            [statistics.median(r["ttft_per_session"]) for r in repeats]
        ),
        "cache_reset_verified": cache_reset_verified,
        "server_peak_rss_mb": _peak_rss_mb(arm.proc.pid) if arm.proc else None,
    }
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "model": args.model,
        "n_ctx": args.n_ctx,
        "parallel": args.parallel,
        "kv_unified": bool(args.kv_unified),
        "cache_reuse": args.cache_reuse,
        "gen_tokens": args.gen_tokens,
        "prefix_tokens_requested": args.prefix_tokens,
        "sampling": "greedy (temperature 0, top_k 1, ignore_eos)",
    }
    print("\n=== N4 server arm ===")
    print(f"environment: {json.dumps(env)}")
    print(
        f"server: median {summary['wall_seconds_median']:.3f}s "
        f"[{summary['wall_seconds_min']:.3f}-{summary['wall_seconds_max']:.3f}], "
        f"cache reset verified: {cache_reset_verified}"
    )
    print("\nJSON:")
    print(
        json.dumps(
            {"env": env, "summary": summary, "per_repeat": repeats}, indent=2
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=["characterize", "grid"])
    parser.add_argument("--model", required=True)
    parser.add_argument("--server-bin", required=True)
    parser.add_argument("--n-ctx", type=int, default=32768)
    parser.add_argument("--parallel", type=int, default=8)
    parser.add_argument("--kv-unified", type=int, default=0)
    parser.add_argument("--cache-reuse", type=int, default=0)
    parser.add_argument("--n-gpu-layers", type=int, default=999)
    parser.add_argument("--prefix-tokens", type=int, default=1500)
    parser.add_argument("--sessions", type=int, default=8)
    parser.add_argument("--gen-tokens", type=int, default=GEN_TOKENS_N4)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()

    arm = ServerArm(args)
    arm.start()
    try:
        if args.mode == "characterize":
            run_characterize(args, arm)
        else:
            run_grid(args, arm)
    finally:
        arm.stop()


if __name__ == "__main__":
    main()
