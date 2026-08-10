"""Point 1 — a single timed workload run in an isolated process. Arg: 'on'|'off'.
Model load + one throwaway session are an UNTIMED warm-up; the timed region is
the realistic agentic workload. audit=on -> real PalaWriter; audit=off -> None
(engine path identical, hooks guarded — honest no-op). Prints one JSON line."""

import ctypes
import json
import os
import sys
import tempfile
import time
from ctypes import wintypes
from palimpsests.providers.native import NativeEngine, PalaWriter

MODEL = r"D:\Palimpsests\Palimpsests-vulkan\models\qwen2.5-1.5b-instruct-q4_k_m.gguf"
SYS = "You are terse. Answer in one short sentence."
PROMPTS = ["Name a primary color.", "What is 2 plus 2?", "Say a common greeting."]
N_SESSIONS = 8
MAX_TOKENS = 48


class PMC(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def mem_mb():
    c = PMC()
    c.cb = ctypes.sizeof(c)
    k32 = ctypes.windll.kernel32
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    psapi = ctypes.WinDLL("psapi")
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    ok = psapi.GetProcessMemoryInfo(k32.GetCurrentProcess(), ctypes.byref(c), c.cb)
    if not ok:
        return None, None
    return c.PeakWorkingSetSize / 1e6, c.WorkingSetSize / 1e6


def timed_workload(eng, mid):
    tokens = 0
    saved = None
    for _ in range(N_SESSIONS):
        s = eng.open_session(model=mid, system_prompt=SYS)
        for p in PROMPTS:
            for _chunk in s.send(p):
                tokens += 1
        saved = s.save_state()
        s.close()
    s = eng.open_session(model=mid, system_prompt=SYS)
    s.load_state(saved)
    for _chunk in s.send(PROMPTS[0]):
        tokens += 1
    s.close()
    s = eng.open_session(model=mid, system_prompt=SYS)
    try:
        s.load_state(b"not a valid kv state blob")
    except Exception:
        pass
    s.close()
    return tokens


def main():
    arm = sys.argv[1]
    writer = None
    if arm == "on":
        p = os.path.join(tempfile.gettempdir(), "p1_on.pala")
        if os.path.exists(p):
            os.remove(p)
        writer = PalaWriter(p)
    eng = NativeEngine(
        model_path=MODEL, max_tokens=MAX_TOKENS, max_sessions=4, share_prefixes=True, audit=writer
    )
    mid = eng.list_models()[0].name

    # untimed warm-up: triggers model load + warms pipeline (1 session)
    s = eng.open_session(model=mid, system_prompt=SYS)
    for _chunk in s.send(PROMPTS[0]):
        pass
    s.close()

    t0 = time.perf_counter()
    tokens = timed_workload(eng, mid)
    wall = time.perf_counter() - t0

    peak, wss = mem_mb()
    eng.close()
    if writer is not None:
        writer.anchor()
        writer.close()

    print(
        json.dumps(
            {
                "arm": arm,
                "wall_s": wall,
                "tokens": tokens,
                "tokens_per_s": tokens / wall,
                "peak_rss_mb": round(peak, 1) if peak is not None else None,
                "wss_mb": round(wss, 1) if wss is not None else None,
            }
        )
    )


if __name__ == "__main__":
    main()
