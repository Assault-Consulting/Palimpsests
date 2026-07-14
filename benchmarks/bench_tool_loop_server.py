"""N5 honest-baseline arm: the tool loop against llama-server slot reuse.

This drives the SAME workload as ``bench_tool_loop.py`` (imported from
``_workload.py`` — never copied) through a tuned ``llama-server``: the client
re-sends the growing conversation each hop with ``cache_prompt: true`` and a
fixed ``id_slot``, so the server reuses the slot's KV for the common prefix
and evaluates only the new suffix. Per BENCHMARKING.md §1 this is the honest
baseline for N5: what llama.cpp's own serving already gives you.

Faithfulness to the in-process arms (one variable at a time):

- identical workload content: system prompt, opening user message, tool
  results — all from ``_workload``;
- identical turn formatting, mirroring ``NativeSession`` verbatim
  (``session.py``): ``system: {sp}\\n``, ``user: {msg}\\nassistant:``,
  ``tool_result[{id}]: {result}\\nassistant:``;
- identical generation length per hop: ``GEN_TOKENS`` with ``ignore_eos`` so
  every hop generates exactly the same token count as the native arms
  (which run with ``stop_tokens=()``);
- greedy sampling (``temperature 0, top_k 1``);
- the conversation GROWS exactly as the live-KV treatment's KV does: each
  hop appends the model's generated text plus the next tool result, so the
  slot's cached prefix always matches and only the new suffix is evaluated.

The script owns the server lifecycle: it starts ``llama-server``, waits for
health, runs 1 warmup + N timed repeats, and RESETS the slot between repeats
(``POST /slots/0?action=erase``, self-verified: the next request must report
``cache_n == 0``; if erase is unavailable the server is restarted instead) so
every repeat pays the initial prefix prefill exactly like a fresh native
session does.

Usage:
    python benchmarks/bench_tool_loop_server.py \
        --model models/M.gguf --server-bin path/to/llama-server.exe \
        --prefix-tokens 2000 --hops 8 --repeats 5 --n-gpu-layers 999

Prints a human summary plus a JSON blob, same shape as bench_tool_loop.py.
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
import time
from _workload import BEGIN_MESSAGE, GEN_TOKENS, big_system_prompt, tool_call_id, tool_result
from dataclasses import dataclass, field

# Turn formatting mirrored from palimpsests.providers.native.session (the
# native arms' single source of formatting). If session.py changes, these
# must change with it — checked by the measured-prefix comparison in reports.
SYSTEM_FMT = "system: {sp}\n"
USER_FMT = "user: {msg}\nassistant:"
TOOL_FMT = "tool_result[{tid}]: {result}\nassistant:"


@dataclass
class HopTiming:
    hop: int
    seconds: float
    ttft_seconds: float
    prompt_n: int
    cache_n: int
    predicted_n: int


@dataclass
class RepeatResult:
    total_seconds: float
    ttft_seconds: float
    hops: list[HopTiming] = field(default_factory=list)


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
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb)
        return pmc.PeakWorkingSetSize / (1024 * 1024) if ok else None
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


class ServerArm:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base = f"http://127.0.0.1:{args.port}"
        self.proc: subprocess.Popen | None = None
        self.erase_supported: bool | None = None

    # ── server lifecycle ──────────────────────────────────────────────────

    def start(self) -> None:
        # --slot-save-path enables the /slots/{id}?action=... endpoints; the
        # erase action is how the slot cache is reset between repeats WITHOUT
        # restarting the server (keeping it long-lived and its graphs warm is
        # the stronger, fairer baseline). Nothing is ever saved to the path.
        slot_dir = tempfile.mkdtemp(prefix="bench-slots-")
        self.proc = subprocess.Popen(
            [
                self.args.server_bin,
                "-m",
                self.args.model,
                "--n-gpu-layers",
                str(self.args.n_gpu_layers),
                "--ctx-size",
                str(self.args.n_ctx),
                "--parallel",
                "1",
                "--port",
                str(self.args.port),
                "--slot-save-path",
                slot_dir,
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = _now() + 120
        with httpx.Client() as client:
            while _now() < deadline:
                try:
                    if client.get(self.base + "/health", timeout=2).status_code == 200:
                        self._session_warm_request()
                        return
                except httpx.HTTPError:
                    time.sleep(0.5)
        raise RuntimeError("llama-server did not become healthy in 120 s")

    def _session_warm_request(self) -> None:
        """One untimed warm request per server session (bench Run 0.3 finding).

        The very first requests of a fresh server session run ~10% slower
        than steady state (allocator/driver warm-up beyond graph warm-up),
        which at tiny sweep points moves pairwise ratios across the control
        band. This single throwaway request — symmetric to the native arms'
        warmup — brings the session to steady state before anything is
        timed. It never touches slot 0's cache (cache_prompt false).
        """
        httpx.post(
            self.base + "/completion",
            json={
                "prompt": "warm",
                "n_predict": 8,
                "temperature": 0,
                "cache_prompt": False,
            },
            timeout=120,
        )

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.kill()
            self.proc.wait(timeout=30)
            self.proc = None

    def reset_slot(self) -> None:
        """Erase slot 0 KV between repeats; restart the server if unsupported.

        Self-verified: after a reset, the next request's ``cache_n`` must be
        0 — checked by the caller via the recorded hop timings.
        """
        if self.erase_supported is not False:
            try:
                r = httpx.post(self.base + "/slots/0?action=erase", timeout=30)
                if r.status_code == 200:
                    self.erase_supported = True
                    return
            except httpx.HTTPError:
                pass
            self.erase_supported = False
        self.stop()
        self.start()

    # ── one hop over HTTP ─────────────────────────────────────────────────

    def run_hop(self, hop: int, prompt: str) -> tuple[HopTiming, str]:
        payload = {
            "prompt": prompt,
            "n_predict": GEN_TOKENS,
            "temperature": 0,
            "top_k": 1,
            "ignore_eos": True,
            "cache_prompt": True,
            "id_slot": 0,
            "stream": True,
        }
        text_parts: list[str] = []
        ttft = 0.0
        timings: dict = {}
        t0 = _now()
        with (
            httpx.Client() as client,
            client.stream("POST", self.base + "/completion", json=payload, timeout=600) as resp,
        ):
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = json.loads(line[len("data: ") :])
                if chunk.get("content"):
                    if not text_parts:
                        ttft = _now() - t0
                    text_parts.append(chunk["content"])
                if chunk.get("timings"):
                    timings = chunk["timings"]
        wall = _now() - t0
        return (
            HopTiming(
                hop=hop,
                seconds=wall,
                ttft_seconds=ttft,
                prompt_n=int(timings.get("prompt_n", -1)),
                cache_n=int(timings.get("cache_n", -1)),
                predicted_n=int(timings.get("predicted_n", -1)),
            ),
            "".join(text_parts),
        )

    # ── one repeat = the full tool loop ───────────────────────────────────

    def run_repeat(self, system_prompt: str, hops: int) -> RepeatResult:
        prompt = SYSTEM_FMT.format(sp=system_prompt) + USER_FMT.format(msg=BEGIN_MESSAGE)
        hop_timings: list[HopTiming] = []
        t0 = _now()
        timing, generated = self.run_hop(0, prompt)
        hop_timings.append(timing)
        for hop in range(1, hops + 1):
            prompt = (
                prompt + generated + TOOL_FMT.format(tid=tool_call_id(hop), result=tool_result(hop))
            )
            timing, generated = self.run_hop(hop, prompt)
            hop_timings.append(timing)
        return RepeatResult(
            total_seconds=_now() - t0,
            ttft_seconds=hop_timings[0].ttft_seconds,
            hops=hop_timings,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True)
    parser.add_argument("--server-bin", required=True, help="path to llama-server")
    parser.add_argument("--hops", type=int, default=8)
    parser.add_argument("--prefix-tokens", type=int, default=2000)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--n-ctx", type=int, default=8192)
    parser.add_argument("--n-gpu-layers", type=int, default=999)
    parser.add_argument("--port", type=int, default=8089)
    args = parser.parse_args()

    system_prompt = big_system_prompt(args.prefix_tokens)
    arm = ServerArm(args)
    arm.start()
    try:
        # Warmup repeat (discarded), then timed repeats, slot reset between.
        arm.run_repeat(system_prompt, args.hops)
        repeats: list[RepeatResult] = []
        cache_reset_verified = True
        for _ in range(args.repeats):
            arm.reset_slot()
            rep = arm.run_repeat(system_prompt, args.hops)
            if rep.hops[0].cache_n not in (0, -1):
                cache_reset_verified = False
            repeats.append(rep)
        peak_rss = _peak_rss_mb(arm.proc.pid) if arm.proc else None
    finally:
        arm.stop()

    totals = [r.total_seconds for r in repeats]
    ttfts = [r.ttft_seconds for r in repeats]
    summary = {
        "label": "baseline_server_slot_reuse",
        "repeats": len(repeats),
        "total_seconds_median": statistics.median(totals),
        "total_seconds_min": min(totals),
        "total_seconds_max": max(totals),
        "ttft_seconds_median": statistics.median(ttfts),
        "server_peak_rss_mb": peak_rss,
        "cache_reset_verified": cache_reset_verified,
        "erase_endpoint_used": arm.erase_supported,
        "reused_cache_n_median_per_hop": statistics.median(
            h.cache_n for r in repeats for h in r.hops[1:]
        )
        if args.hops >= 1
        else None,
    }
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "model": args.model,
        "hops": args.hops,
        "prefix_tokens_requested": args.prefix_tokens,
        "n_ctx": args.n_ctx,
        "n_gpu_layers": args.n_gpu_layers,
        "repeats": args.repeats,
        "sampling": "greedy (temperature 0, top_k 1, ignore_eos)",
        "gen_tokens_per_hop": GEN_TOKENS,
    }
    print("\n=== tool loop: llama-server slot-reuse arm ===")
    print(f"environment: {json.dumps(env)}")
    print(
        f"server arm: median {summary['total_seconds_median']:.3f}s "
        f"[{summary['total_seconds_min']:.3f}-{summary['total_seconds_max']:.3f}], "
        f"TTFT {summary['ttft_seconds_median']:.3f}s, "
        f"cache reset verified: {cache_reset_verified}"
    )
    print("\nJSON:")
    print(
        json.dumps(
            {
                "env": env,
                "server_arm": summary,
                "per_repeat": [
                    {
                        "total_seconds": r.total_seconds,
                        "ttft_seconds": r.ttft_seconds,
                        "hops": [vars(h) for h in r.hops],
                    }
                    for r in repeats
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
