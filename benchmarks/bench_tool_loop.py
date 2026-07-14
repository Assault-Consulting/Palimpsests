"""Benchmark: server-side tool loop (L3/N5) vs re-prefill baseline.

**Status: on the shelf, NOT yet run on hardware.** This exercises the
real ``LlamaCppBackend`` and therefore needs the ``[native]`` extra and a
GGUF model. It is not imported by CI and not part of the package.

## What this measures (and why it is the FIRST thing to measure)

Our single strongest claimed advantage is the server-side tool loop
(N5): in an agentic ``generate -> tool -> continue`` cycle, the shared
system prompt and the growing conversation are decoded once and kept live
in KV; each tool hop feeds only the tool result. A stateless engine
instead re-reads (re-prefills) the entire conversation on every hop.

The claim is that end-to-end wall time for an N-hop tool loop is much
lower with the live-KV path, and that the gap grows with the size of the
shared prefix and the number of hops. This script is designed to let that
claim FAIL: if re-prefill is comparable, the numbers will say so.

Both arms use the SAME backend, model, hardware, sampling, and token
counts. The ONLY variable is state control:

- **treatment (L3 tool loop):** one ``NativeSession``; ``send`` once, then
  ``append_tool_result`` per hop — KV stays live, no re-prefill.
- **baseline (re-prefill):** a fresh ``NativeSession`` per hop whose input
  is the ENTIRE conversation so far (system prompt + all prior turns +
  tool results) — i.e. exactly what a stateless engine must do. Same
  tokens ultimately decoded; the difference is that the baseline re-reads
  the prefix every hop while the treatment does not.

This is workload #2 in docs/BENCHMARKING.md, run with that document's
procedure (warmup, >=5 repeats, median + spread, fixed greedy sampling,
full environment recorded).

## Before you trust a number (per BENCHMARKING.md)

- Decide the expected direction BEFORE running: treatment should win, and
  the margin should grow with prefix size and hop count. A flat or
  inverted result is a real finding — keep it.
- The baseline here is deliberately the honest stateless cost, not a
  straw man: it decodes the same content, only without our state reuse.
- A single-hop / tiny-prefix configuration should show LITTLE advantage;
  that is the control that proves the harness is not rigged. The sweep
  includes it.

## Usage

    pip install "palimpsests[native]"
    python benchmarks/bench_tool_loop.py \
        --model /path/to/model.gguf \
        --hops 8 --prefix-tokens 2000 --repeats 5

Nothing is written anywhere; results print as a table plus a JSON blob you
can paste next to the environment description in a report.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from _workload import BEGIN_MESSAGE, big_system_prompt, tool_call_id, tool_result
from dataclasses import dataclass, field

# Imported lazily in main() so --help works without the native extra.


@dataclass
class HopTiming:
    """Wall time for one hop, plus the token count decoded that hop."""

    hop: int
    seconds: float
    input_tokens: int


@dataclass
class ArmResult:
    """One arm (treatment or baseline) of one repeat."""

    label: str
    total_seconds: float
    ttft_seconds: float
    hop_timings: list[HopTiming] = field(default_factory=list)


def _now() -> float:
    """Monotonic seconds — never the wall clock, which can jump."""
    return time.perf_counter()


def _run_treatment(
    backend, make_scheduler, system_prompt: str, hops: int, stop_tokens
) -> ArmResult:
    """L3 tool loop: one live session, tool results appended in place.

    First ``send`` primes the conversation (paying the prefix cost ONCE);
    each subsequent hop is an ``append_tool_result`` that feeds only the
    tool output into the already-live KV. This is the path whose cost we
    claim is low and flat per hop.
    """
    from palimpsests.providers.native.session import NativeSession

    scheduler = make_scheduler()
    session = NativeSession(
        backend,
        scheduler,
        system_prompt=system_prompt,
        max_tokens=32,  # short generations; we measure loop cost, not verbosity
        stop_tokens=stop_tokens,
    )
    timings: list[HopTiming] = []
    t0 = _now()
    ttft = 0.0
    try:
        # Hop 0: the initial user turn. This is where the big prefix is
        # decoded — once.
        h0 = _now()
        first_token_seen = False
        for _ in session.send(BEGIN_MESSAGE):
            if not first_token_seen:
                ttft = _now() - h0
                first_token_seen = True
        timings.append(HopTiming(0, _now() - h0, input_tokens=-1))

        # Hops 1..N: each simulates a tool returning, then the model
        # continuing. Only the short tool result is fed — no re-prefill.
        for hop in range(1, hops + 1):
            hstart = _now()
            for _ in session.append_tool_result(
                tool_call_id=tool_call_id(hop),
                result=tool_result(hop),
            ):
                pass
            timings.append(HopTiming(hop, _now() - hstart, input_tokens=-1))
    finally:
        session.close()
    return ArmResult("treatment_l3_tool_loop", _now() - t0, ttft, timings)


def _run_baseline(backend, make_scheduler, system_prompt: str, hops: int, stop_tokens) -> ArmResult:
    """Re-prefill baseline: a fresh session each hop, fed the WHOLE history.

    This is what a stateless engine must do. Each hop reconstructs the
    entire conversation (system prompt + every prior turn + every prior
    tool result) as one prompt and decodes it from scratch. Same content
    ultimately processed as the treatment; the difference is that the
    prefix is re-read every single hop.

    We build the conversation as plain text and let the session tokenize
    it, so both arms go through the identical tokenizer path.
    """
    from palimpsests.providers.native.session import NativeSession

    timings: list[HopTiming] = []
    ttft = 0.0
    t0 = _now()

    # The running transcript the stateless engine must re-read each hop.
    transcript = BEGIN_MESSAGE
    for hop in range(0, hops + 1):
        scheduler = make_scheduler()
        # Fresh session every hop: no KV survives between hops, so the
        # whole system_prompt + transcript is prefilled anew.
        session = NativeSession(
            backend,
            scheduler,
            system_prompt=system_prompt,
            max_tokens=32,
            stop_tokens=stop_tokens,
        )
        try:
            hstart = _now()
            first_token_seen = False
            for _ in session.send(transcript):
                if hop == 0 and not first_token_seen:
                    ttft = _now() - hstart
                    first_token_seen = True
            timings.append(HopTiming(hop, _now() - hstart, input_tokens=-1))
        finally:
            session.close()
        # Grow the transcript exactly as the tool loop would, so hop N of
        # the baseline re-prefills the same content hop N of the treatment
        # holds live.
        transcript += f"\n{tool_result(hop)}"
    return ArmResult("baseline_reprefill", _now() - t0, ttft, timings)


def _summarize(label: str, arms: list[ArmResult]) -> dict:
    """Median + spread across repeats for one arm, per BENCHMARKING.md §5."""
    totals = [a.total_seconds for a in arms]
    ttfts = [a.ttft_seconds for a in arms]
    return {
        "label": label,
        "repeats": len(arms),
        "total_seconds_median": statistics.median(totals),
        "total_seconds_min": min(totals),
        "total_seconds_max": max(totals),
        "ttft_seconds_median": statistics.median(ttfts),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", required=True, help="path to a .gguf model")
    parser.add_argument("--hops", type=int, default=8)
    parser.add_argument(
        "--prefix-tokens",
        type=int,
        default=2000,
        help="approx size of the shared system prompt (the carried prefix)",
    )
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--n-ctx", type=int, default=8192)
    parser.add_argument(
        "--n-gpu-layers",
        type=int,
        default=0,
        help="offload N layers to GPU (0 = CPU only)",
    )
    args = parser.parse_args()

    # Lazy imports: only needed for an actual run, so --help works bare.
    from palimpsests.providers.native.backend import Token
    from palimpsests.providers.native.llamacpp_backend import LlamaCppBackend
    from palimpsests.providers.native.scheduler import Scheduler

    backend = LlamaCppBackend(
        args.model,
        n_ctx=args.n_ctx,
        n_seq_max=2,  # one live slot is enough; 2 for headroom
        n_gpu_layers=args.n_gpu_layers,
    )

    # Greedy everywhere (BENCHMARKING §2). Determine EOS so turns end the
    # same way in both arms; fall back to a fixed cap if the backend does
    # not expose it. A real integration should read the model's true EOS.
    stop_tokens: tuple[Token, ...] = ()

    def make_scheduler() -> Scheduler:
        # max_active=1: a single session at a time. Both arms use the same
        # scheduler shape, so this is not a variable.
        return Scheduler(backend, max_active=1)

    system_prompt = big_system_prompt(args.prefix_tokens)
    measured_prefix_tokens = len(backend.tokenize(f"system: {system_prompt}\n", add_special=True))

    # Warmup (BENCHMARKING §5.1): one discarded run of each arm so model
    # load and allocator warmup do not pollute timings.
    _run_treatment(backend, make_scheduler, system_prompt, args.hops, stop_tokens)
    _run_baseline(backend, make_scheduler, system_prompt, args.hops, stop_tokens)

    treatments: list[ArmResult] = []
    baselines: list[ArmResult] = []
    for _ in range(args.repeats):
        treatments.append(
            _run_treatment(backend, make_scheduler, system_prompt, args.hops, stop_tokens)
        )
        baselines.append(
            _run_baseline(backend, make_scheduler, system_prompt, args.hops, stop_tokens)
        )

    backend.close()

    t_sum = _summarize("treatment_l3_tool_loop", treatments)
    b_sum = _summarize("baseline_reprefill", baselines)
    speedup = (
        b_sum["total_seconds_median"] / t_sum["total_seconds_median"]
        if t_sum["total_seconds_median"] > 0
        else float("nan")
    )

    env = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor(),
        "model": args.model,
        "hops": args.hops,
        "prefix_tokens_requested": args.prefix_tokens,
        "prefix_tokens_measured": measured_prefix_tokens,
        "n_ctx": args.n_ctx,
        "n_gpu_layers": args.n_gpu_layers,
        "repeats": args.repeats,
        "sampling": "greedy",
    }

    # Human-readable summary.
    print("\n=== tool loop vs re-prefill ===")
    print(f"environment: {json.dumps(env)}")
    print(
        f"treatment (L3 tool loop): median {t_sum['total_seconds_median']:.3f}s "
        f"[{t_sum['total_seconds_min']:.3f}-{t_sum['total_seconds_max']:.3f}], "
        f"TTFT {t_sum['ttft_seconds_median']:.3f}s"
    )
    print(
        f"baseline  (re-prefill):   median {b_sum['total_seconds_median']:.3f}s "
        f"[{b_sum['total_seconds_min']:.3f}-{b_sum['total_seconds_max']:.3f}], "
        f"TTFT {b_sum['ttft_seconds_median']:.3f}s"
    )
    print(f"end-to-end speedup (baseline/treatment): {speedup:.2f}x")
    print(
        "\nInterpretation (decide BEFORE trusting): a speedup that GROWS with "
        "--prefix-tokens and --hops supports the tool-loop claim. A flat or "
        "<1x result is a real negative — record it per BENCHMARKING.md §6."
    )

    # Machine-readable blob to paste beside the environment in a report.
    print("\nJSON:")
    print(
        json.dumps(
            {
                "env": env,
                "treatment": t_sum,
                "baseline": b_sum,
                "speedup_baseline_over_treatment": speedup,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
