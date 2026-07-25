"""KV Persistence honest-baseline arm: llama-server slot save/restore.

Strong-opponent result (step 0.5, verified on the pinned b9874): the
server EXPOSES a real, disk-backed slot save/restore
(``--slot-save-path`` + ``POST /slots/{id}?action=save|restore`` with a
``{"filename": ...}`` body). That makes it a FAIR comparator — the server
arm here restores a previously-saved slot file and continues, symmetric
to our disk resume, NOT a cache_prompt re-prefill. Its save/restore file
is on the same NVMe as ours; the server's own ``restore_ms`` /
``save_ms`` timings are recorded from the endpoint response alongside the
client wall.

Grid point: pre-save one slot file per session, then time restore +
continuation (``n_predict`` = GEN_TOKENS) fired concurrently across M
sessions. Slots are cleared between repeats so every repeat pays its own
restore.
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
from dataclasses import dataclass

SYSTEM_FMT = "system: {sp}\n"
USER_FMT = "user: {msg}\nassistant:"
GEN_TOKENS = 64


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

    handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
    if not handle:
        return None
    try:
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        ok = ctypes.windll.psapi.GetProcessMemoryInfo(handle, ctypes.byref(pmc), pmc.cb)
        return pmc.PeakWorkingSetSize / 2**20 if ok else None
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


@dataclass
class SessionTiming:
    session: int
    seconds: float
    ttft_seconds: float
    restore_ms: float
    prompt_n: int


class ServerArm:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.base = f"http://127.0.0.1:{args.port}"
        self.proc: subprocess.Popen | None = None
        self.slot_dir = tempfile.mkdtemp(prefix="bench-persist-slots-")

    def start(self) -> None:
        cmd = [
            self.args.server_bin,
            "-m",
            self.args.model,
            "--n-gpu-layers",
            str(self.args.n_gpu_layers),
            "--ctx-size",
            str(self.args.n_ctx),
            "--parallel",
            str(self.args.sessions),
            "--port",
            str(self.args.port),
            "--slot-save-path",
            self.slot_dir,
        ]
        self.proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = _now() + 180
        with httpx.Client() as client:
            while _now() < deadline:
                try:
                    if client.get(self.base + "/health", timeout=2).status_code == 200:
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

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.kill()
            self.proc.wait(timeout=30)
            self.proc = None

    def prime_and_save(self, i: int, prompt: str) -> tuple[int, float]:
        """Prefill slot i with the prefix, save it to a file. Returns
        (prompt_n, save_ms) — the checkpoint cost, reported separately."""
        r = httpx.post(
            self.base + "/completion",
            json={
                "prompt": prompt,
                "n_predict": 1,
                "temperature": 0,
                "cache_prompt": True,
                "id_slot": i,
            },
            timeout=600,
        )
        prompt_n = int(r.json().get("timings", {}).get("prompt_n", -1))
        r = httpx.post(
            self.base + f"/slots/{i}?action=save",
            json={"filename": f"s{i}.bin"},
            timeout=120,
        )
        save_ms = float(r.json().get("timings", {}).get("save_ms", -1))
        # clear the slot so the timed restore does real work
        httpx.post(self.base + f"/slots/{i}?action=erase", timeout=30)
        return prompt_n, save_ms

    def restore_and_continue(self, i: int, t0: float) -> SessionTiming:
        tr = _now()
        r = httpx.post(
            self.base + f"/slots/{i}?action=restore",
            json={"filename": f"s{i}.bin"},
            timeout=120,
        )
        restore_ms = float(r.json().get("timings", {}).get("restore_ms", -1))
        payload = {
            "prompt": " Continue.",
            "n_predict": GEN_TOKENS,
            "temperature": 0,
            "top_k": 1,
            "ignore_eos": True,
            "cache_prompt": True,
            "id_slot": i,
            "stream": True,
        }
        ttft = 0.0
        prompt_n = -1
        with (
            httpx.Client() as client,
            client.stream("POST", self.base + "/completion", json=payload, timeout=600) as resp,
        ):
            resp.raise_for_status()
            for line in resp.iter_lines():
                if not line.startswith("data: "):
                    continue
                chunk = json.loads(line[len("data: ") :])
                if chunk.get("content") and ttft == 0.0:
                    ttft = _now() - t0
                if chunk.get("timings"):
                    prompt_n = int(chunk["timings"].get("prompt_n", -1))
        return SessionTiming(i, _now() - tr, ttft, restore_ms, prompt_n)


def run_grid(args: argparse.Namespace, arm: ServerArm) -> None:
    prefix = SYSTEM_FMT.format(sp=big_system_prompt(args.prefix_tokens))
    prompts = [prefix + USER_FMT.format(msg=session_suffix(i)) for i in range(args.sessions)]
    save_ms, prompt_ns = [], []
    for i, p in enumerate(prompts):
        pn, sms = arm.prime_and_save(i, p)
        prompt_ns.append(pn)
        save_ms.append(sms)

    def one_repeat() -> dict:
        res: list[SessionTiming | None] = [None] * args.sessions
        t0 = _now()

        def worker(i: int) -> None:
            res[i] = arm.restore_and_continue(i, t0)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(args.sessions)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        done = [r for r in res if r is not None]
        return {
            "wall": _now() - t0,
            "ttft": [r.ttft_seconds for r in done],
            "restore_ms": [r.restore_ms for r in done],
        }

    one_repeat()  # warmup
    reps = [one_repeat() for _ in range(args.repeats)]
    walls = [r["wall"] for r in reps]
    summary = {
        "label": "persist_server_slot_restore",
        "prefix_tokens_measured": prompt_ns[0],
        "sessions": args.sessions,
        "repeats": args.repeats,
        "wall_seconds_median": statistics.median(walls),
        "wall_seconds_min": min(walls),
        "wall_seconds_max": max(walls),
        "ttft_first_session_median": statistics.median([min(r["ttft"]) for r in reps]),
        "server_save_ms_median": statistics.median(save_ms),
        "server_restore_ms_median": statistics.median([m for r in reps for m in r["restore_ms"]]),
        "server_peak_rss_mb": _peak_rss_mb(arm.proc.pid) if arm.proc else None,
    }
    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "model": args.model,
        "arm": "server_slot_restore",
        "n_ctx": args.n_ctx,
        "parallel": args.sessions,
        "prefix_tokens_requested": args.prefix_tokens,
        "gen_tokens": GEN_TOKENS,
        "sampling": "greedy (temperature 0, top_k 1, ignore_eos)",
    }
    print("\n=== KV Persistence server (slot restore) ===")
    print(f"environment: {json.dumps(env)}")
    print(
        f"server: median {summary['wall_seconds_median']:.4f}s "
        f"[{summary['wall_seconds_min']:.4f}-{summary['wall_seconds_max']:.4f}], "
        f"restore_ms {summary['server_restore_ms_median']:.3f}"
    )
    print("\nJSON:")
    print(json.dumps({"env": env, "summary": summary, "per_repeat": reps}, indent=2))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--n-ctx", type=int, default=8192)
    ap.add_argument("--n-gpu-layers", type=int, default=999)
    ap.add_argument("--prefix-tokens", type=int, default=1500)
    ap.add_argument("--sessions", type=int, default=1)
    ap.add_argument("--repeats", type=int, default=5)
    ap.add_argument("--port", type=int, default=8095)
    args = ap.parse_args()
    arm = ServerArm(args)
    arm.start()
    try:
        run_grid(args, arm)
    finally:
        arm.stop()


if __name__ == "__main__":
    main()
