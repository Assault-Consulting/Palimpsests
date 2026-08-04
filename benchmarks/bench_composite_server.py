# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Composite rung-0 arm: the tuned llama-server doing the full agentic
workload — the external competitive anchor for Run 7.

The server does the composite the way a tuned deployment would:
- Shared Prefix  → cache_prompt reuses the slot's cached system prompt.
- Tool Loop      → each hop re-sends the growing conversation with
                   cache_prompt, so the server evaluates only the new suffix
                   (its own slot-KV tool loop).
- KV Persistence → resumed sessions restore a pre-saved slot file
                   (/slots/{id}?action=restore) instead of re-prefilling.

M sessions run concurrently (one thread each); a resume-fraction restore
pre-saved state. --parallel P is the tuned slot budget (P-tuned baseline).
Content is byte-identical to the native arms via ``_workload`` /
``bench_composite`` (one variable = who runs the loop).
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
from _workload import big_system_prompt, session_suffix
from bench_composite import GEN, HOPS, PRIOR_HOPS, _hop_text
from bench_shared_prefix import SYSTEM_FMT, USER_FMT


def _now() -> float:
    return time.perf_counter()


def _peak_rss_mb(pid: int) -> float | None:
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

    h = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not h:
        return None
    try:
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb)
        return pmc.PeakWorkingSetSize / 2**20 if ok else None
    finally:
        ctypes.windll.kernel32.CloseHandle(h)


def _conversation_text(prefix_tokens: int, sess: int, up_to_hop: int) -> str:
    text = SYSTEM_FMT.format(sp=big_system_prompt(prefix_tokens)) + USER_FMT.format(
        msg=session_suffix(sess)
    )
    for hop in range(up_to_hop):
        text += _hop_text(hop)
    return text


class ServerArm:
    def __init__(self, args):
        self.args = args
        self.base = f"http://127.0.0.1:{args.port}"
        self.proc = None
        self.slot_dir = tempfile.mkdtemp(prefix="bench-composite-slots-")

    def start(self):
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
            self.slot_dir,
        ]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = _now() + 180
        with httpx.Client() as c:
            while _now() < deadline:
                try:
                    if c.get(self.base + "/health", timeout=2).status_code == 200:
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
                        return
                except httpx.HTTPError:
                    time.sleep(0.5)
        raise RuntimeError("llama-server did not become healthy in 180 s")

    def stop(self):
        if self.proc is not None:
            self.proc.kill()
            self.proc.wait(timeout=30)
            self.proc = None

    def _completion(self, prompt, slot, n_predict):
        r = httpx.post(
            self.base + "/completion",
            json={
                "prompt": prompt,
                "n_predict": n_predict,
                "temperature": 0,
                "top_k": 1,
                "ignore_eos": True,
                "cache_prompt": True,
                "id_slot": slot,
            },
            timeout=1200,
        )
        r.raise_for_status()

    def prime_resumed(self, sess, slot, prefix_tokens):
        """Prefill system+user+PRIOR hops on the slot and save it (the
        persisted checkpoint a resumed session restores). Returns nothing;
        the slot file is s{slot}.bin."""
        self._completion(_conversation_text(prefix_tokens, sess, PRIOR_HOPS), slot, 1)
        httpx.post(
            self.base + f"/slots/{slot}?action=save", json={"filename": f"s{slot}.bin"}, timeout=120
        )
        httpx.post(self.base + f"/slots/{slot}?action=erase", timeout=30)

    def run_session(self, sess, slot, resumed, prefix_tokens):
        if resumed:
            httpx.post(
                self.base + f"/slots/{slot}?action=restore",
                json={"filename": f"s{slot}.bin"},
                timeout=120,
            )
            start_hop = PRIOR_HOPS
        else:
            self._completion(
                SYSTEM_FMT.format(sp=big_system_prompt(prefix_tokens))
                + USER_FMT.format(msg=session_suffix(sess)),
                slot,
                GEN,
            )
            start_hop = 0
        for hop in range(start_hop, HOPS):
            # Tool loop: send the growing conversation; cache_prompt reuses the
            # slot's cached prefix and evaluates only the new suffix.
            self._completion(_conversation_text(prefix_tokens, sess, hop + 1), slot, GEN)


def run_point(args, arm):
    n_resumed = int(round(args.sessions * args.resume_fraction))
    resumed_ids = set(range(n_resumed))
    # Pre-save the resumed sessions' checkpoints (not timed as the resume).
    for sess in sorted(resumed_ids):
        arm.prime_resumed(sess, sess % args.parallel, args.prefix_tokens)

    def one_repeat():
        results = [None] * args.sessions
        t0 = _now()

        def worker(sess):
            slot = sess % args.parallel
            arm.run_session(sess, slot, sess in resumed_ids, args.prefix_tokens)
            results[sess] = _now() - t0

        threads = [threading.Thread(target=worker, args=(s,)) for s in range(args.sessions)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return _now() - t0

    one_repeat()  # warmup
    walls = [one_repeat() for _ in range(args.repeats)]
    summary = {
        "rung": 0,
        "sessions": args.sessions,
        "parallel": args.parallel,
        "resume_fraction": args.resume_fraction,
        "wall_seconds_median": statistics.median(walls),
        "wall_seconds_min": min(walls),
        "wall_seconds_max": max(walls),
        "server_peak_rss_mb": _peak_rss_mb(arm.proc.pid) if arm.proc else None,
    }
    env = {
        "python": platform.python_version(),
        "model": args.model,
        "arm": "rung0_tuned_server",
        "n_ctx": args.n_ctx,
        "parallel": args.parallel,
        "sampling": "greedy (temperature 0, top_k 1, ignore_eos)",
    }
    print("\n=== composite rung 0 (tuned server) ===")
    print(f"environment: {json.dumps(env)}")
    print(f"rung 0: median {summary['wall_seconds_median']:.3f}s")
    print("\nJSON:")
    print(json.dumps({"env": env, "summary": summary}, indent=2))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--n-ctx", type=int, default=32768)
    ap.add_argument("--parallel", type=int, default=8)
    ap.add_argument("--n-gpu-layers", type=int, default=999)
    ap.add_argument("--prefix-tokens", type=int, default=1500)
    ap.add_argument("--sessions", type=int, default=8)
    ap.add_argument("--resume-fraction", type=float, default=0.5)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--port", type=int, default=8097)
    args = ap.parse_args()
    arm = ServerArm(args)
    arm.start()
    try:
        run_point(args, arm)
    finally:
        arm.stop()


if __name__ == "__main__":
    main()
