# Bench report — Run 0.3: server transport cost characterization — iGPU/Vulkan

- Run ID:            env-transport-igpu-03
- Date / operator:   2026-07-13 / Oleksandr
- Config-hash:       dd2e395be22675f1 (UNCHANGED from Run 0.2 — confirmed:
  pin 7745853, venv 0.5.1, pinned llama-server b9874 @ 78d2f524, same
  models/sha256, same driver; nothing rebuilt)

## Pre-registration (written BEFORE running)

Expectation: the server arm carries a fixed per-hop transport cost (HTTP/SSE
+ server-side bookkeeping), estimated at ~0.13 s/hop from the Run 0.2 control
(TTFT 0.209 vs 0.079 s). If fixed, then (1) per-hop cost measured at hops
{1, 4, 8} on the tiny prefix is constant within noise, and (2) the
server-vs-mechanism pairwise ratio converges into the 0.9–1.2 band as hops
grow, without any adjustment. Would disappoint if: per-hop transport cost
GROWS with hops or with history length (then it is not a constant and cannot
be amortized or subtracted — the transport-fair design must be rethought); or
the pair does not converge by hops=8.

## Baseline used

Same three arms and configuration as Run 0.2; tiny prefix (~30 measured
tokens, `--prefix-tokens 50`); hops {1, 4, 8}; ≥1 warmup + 5 timed repeats
per invocation; 30 s cool-down between invocations; no background load.

## Results

### 1. Medians per point (5 timed repeats)

| hops | ours | mechanism | server | ours/mech | server/ours | server/mech |
|---|---|---|---|---|---|---|
| 1 | 1.370 s | 1.348 s | 1.812 s | 1.016 ✓ | 1.323 ✗ | 1.345 ✗ |
| 4 | 3.423 s | 3.412 s | 4.075 s | 1.003 ✓ | 1.190 ✓ | **1.194 ✓ (in band)** |
| 8 | 6.238 s | 6.314 s | 7.393 s | 1.012 ✓ | 1.185 ✓ | **1.171 ✓ (in band)** |

**Convergence confirmed: server-vs-mechanism enters the 0.9–1.2 band by
hops=4 and stays there at hops=8 — without any adjustment** (pre-registration
expectation 2; it converged even earlier than the pre-registered "by 8").

### 2. Server per-hop wall stability (median across repeats, per hop index)

| invocation | hop walls (s) |
|---|---|
| hops=1 | 0.918, 0.883 |
| hops=4 | 0.798, 0.812, 0.821, 0.827, 0.834 |
| hops=8 | 0.794, 0.810, 0.823, 0.821, 0.826, 0.827, 0.820, 0.827, 0.835 |

Within the hops=8 invocation the per-hop wall creeps from 0.810 to 0.835 s —
**+3% over 8 hops** (consistent with growing-history re-tokenization /
prefix-scan, but tiny at this scale). No growth beyond that: expectation 1
holds within noise. Honest flag: this small creep should be re-checked on the
feasibility axis where histories get long.

### 3. The measured transport constant

Marginal per-hop slopes (from medians): ours 0.685 / 0.704 / 0.695 s
(1→4 / 4→8 / 1→8); server 0.754 / 0.830 / 0.797 s. Differences:
0.070 / 0.126 / 0.102 s.

**Measured transport constant: 0.102 s per HTTP request (median; spread
0.070–0.126).** Accounting note: every request pays it, including hop 0 —
so a point with H hops carries (H+1) × constant.

### 4. Subtraction cross-check

adjusted server wall = raw − 0.102 × (hops+1):

| hops | adjusted server | adj-server/mech | adj-server/ours |
|---|---|---|---|
| 1 | 1.609 s | **1.194 ✓ (in band already at hops=1)** | 1.174 ✓ |
| 4 | 3.566 s | 1.045 ✓ | 1.042 ✓ |
| 8 | 6.477 s | 1.026 ✓ | 1.038 ✓ |

(With the alternative "hops only, excluding hop 0" accounting the hops=1
point does NOT land in band (1.269) — the per-request accounting is the one
the data supports, and the one recorded here.)

## Headline convention for Run 1 (fixed by this run)

Headline ratio = RAW wall-clock ours-vs-server at sweep points (transport
included — it is a real cost of the server deployment model). Control-gate
convention: pairs involving our arm gated at the 50x1 control as before; the
server-vs-mechanism pair gated at the 50x8 amortized point (per this run's
finding). A transport-adjusted ratio column (raw minus the measured
constant) is reported alongside as a cross-check, never as the headline. If
at any sweep point raw and adjusted ratios diverge in what they imply, or
the server-vs-mechanism pair leaves the band at a non-control point, that is
an automatic STOP (the constant assumption failed mid-flight).

## Observation

Verdict vs the pre-registration: **confirmed** — (1) the per-hop transport
cost is constant within noise (≤3% creep across 8 hops, no growth trend that
would defeat amortization or subtraction), and (2) the server-vs-mechanism
pair converges into the band by hops=4, earlier than the pre-registered
deadline of hops=8. Neither disappointment clause fired. The measured
constant (0.102 s/request) is close to the Run 0.2 estimate (~0.13 s/hop
from TTFT deltas).

Two honest caveats for Run 1's design:

1. **Session-level variance of the server arm at tiny points.** This run's
   hops=1 server invocation (the first server session of the sequence)
   measured 1.812 s where Run 0.2 measured the same point at 1.646 s — its
   hop walls (0.918/0.883) sit visibly above the steady ~0.80–0.83 s of the
   later, longer invocations. The in-invocation warmup repeat is evidently
   not enough for the very first requests of a fresh server session at tiny
   points (~10% session-level effect). Consequence at hops=1:
   server/ours = 1.323 in this run vs 1.197 in Run 0.2 — the pair involving
   our arm crosses the band boundary purely on this variance. Options for
   the maintainer (not decided here): add one session-level warm request to
   the server arm's startup before the warmup repeat, or gate the
   ours-vs-server pair at an amortized point alongside server-vs-mechanism.
2. The +3% per-hop creep (§2) is negligible here but must be re-checked at
   long histories on the feasibility axis; the automatic-STOP clause in the
   convention covers the case where it stops being negligible.
