"""Composite benchmark — do the three level-3 mechanisms COMPOSE (Run 7).

Public names: Shared Prefix (SP), Tool Loop (TL), KV Persistence (KP).
Internal: N4 / N5 / N6. Everything below drives the native backend with the
NATIVE ``kv_unified=True`` param (shipped first-class on main after #81) and
the enforced ``PrefixHolderInUseError`` guard.

The campaign so far isolated one mechanism at a time. This asks whether they
ADD or OVERLAP under a realistic agentic workload: M parallel sessions that
share a system prompt, each running a few tool hops, a fraction resumed from
persisted KV. The rungs are incremental-cumulative — each delta is measured
against the PREVIOUS rung, never a cherry-picked isolated best:

  rung 1  none          stateless re-prefill everywhere            (ours floor)
  rung 2  +SP           shared system prompt decoded once, copied
  rung 3  +KP           resumed fraction loads KV, no re-prefill   ← sub-additivity heart
  rung 4  +TL           hops feed only the tool result (live KV)

Sub-additivity hypothesis (pre-registered, from Run 5 probe Q2): a persisted
blob is FULL-LOGICAL — it re-persists the shared prefix — so SP (saves the
cold sessions' prefix decode) and KP (saves the resumed sessions' history
decode) save prefill for DIFFERENT session subsets. The rung-3 marginal
delta should therefore be much smaller than KP's isolated ratio.

Mechanism gating per rung: SP∈{2,3,4}, KP∈{3,4}, TL∈{4}.

Modes:
- ``gate``  — the blocking corruption gate (§ step 0): a single session run
  with the FULL stack must reach a first-token-logits state within the
  calibrated epsilon of the SAME session re-prefilled statelessly (its own
  cells → bit-identical expected). Also asserts the guard never raises during
  a concurrent composite run. A divergence is a DEFECT, not a slow number.
- ``rung``  — one rung × one point (M, resume-fraction): wall (headline),
  peak KV cells / RSS, eviction/admission-failure events, guard raises (must
  be 0), errors with codes.
"""

from __future__ import annotations

import argparse
import json
import platform
import statistics
import time
from _workload import big_system_prompt, session_suffix, tool_result
from bench_shared_prefix import SYSTEM_FMT, USER_FMT, make_backend, mem_snapshot

HOPS = 4  # tool hops per session
PRIOR_HOPS = 2  # a resumed session already has this many hops persisted
GEN = 24  # tokens produced per hop (fixed short — the win is avoided prefill)


def _now() -> float:
    return time.perf_counter()


def _argmax(logits) -> int:
    import numpy as np

    return int(np.argmax(logits))


# ── conversation content (shared byte-identically across rungs) ────────────


def _hop_text(hop: int) -> str:
    """The text appended for tool hop ``hop`` (tool result + turn cue)."""
    return f"\ntool_result[{hop}]: {tool_result(hop)}\nassistant:"


def conversation_tokens(backend, prefix_tokens: int, sess: int, up_to_hop: int) -> list[int]:
    """Full token stream of one session's conversation through ``up_to_hop``
    hops: system prompt + user opener + that many tool-result turns. This is
    what a STATELESS engine must re-prefill (the mechanism baseline path)."""
    text = SYSTEM_FMT.format(sp=big_system_prompt(prefix_tokens)) + USER_FMT.format(
        msg=session_suffix(sess)
    )
    for hop in range(up_to_hop):
        text += _hop_text(hop)
    return backend.tokenize(text, add_special=True)


# ── low-level decode helpers ───────────────────────────────────────────────


def _prefill(backend, seq, toks, start=0):
    from palimpsests.providers.native.backend import BatchEntry

    return backend.decode(
        [BatchEntry(seq_id=seq, tokens=toks, start_pos=start, wants_logits=True)]
    )[seq]


def _generate(backend, seq, first_logits, start_pos, n):
    """Greedy-generate n tokens; return (tokens, next_pos)."""
    from palimpsests.providers.native.backend import BatchEntry

    toks = [_argmax(first_logits)]
    pos = start_pos
    for _ in range(n - 1):
        res = backend.decode(
            [BatchEntry(seq_id=seq, tokens=[toks[-1]], start_pos=pos, wants_logits=True)]
        )
        toks.append(_argmax(res[seq]))
        pos += 1
    # ``pos`` is now the next free position: n-1 tokens were decoded at
    # start_pos..start_pos+n-2 (toks[-1] was sampled, not decoded).
    return toks, pos


def first_token_logits(backend, seq, n_past):
    """First-token logits at position n_past (seed a fixed token, roll back)."""
    from palimpsests.providers.native.backend import BatchEntry

    seed = backend.tokenize(".", add_special=False)[0]
    res = backend.decode(
        [BatchEntry(seq_id=seq, tokens=[seed], start_pos=n_past, wants_logits=True)]
    )
    import numpy as np

    out = res[seq].astype(np.float64).copy()
    backend.seq_remove(seq, n_past, -1)
    return out


def logits_l2(a, b) -> float:
    import numpy as np

    return float(np.linalg.norm(np.asarray(a) - np.asarray(b)))


# ── one session under a given rung's mechanisms ────────────────────────────


def run_session(
    backend,
    scheduler,
    holder,
    plen,
    seq,
    *,
    sp,
    kp,
    tl,
    resumed,
    prior_blob,
    prior_len,
    sess,
    prefix_tokens,
):
    """Execute one session to completion under the given mechanism flags.
    Returns the final n_past (KV length) so callers can measure/inspect."""

    # ── establish the base state ──────────────────────────────────────────
    if resumed and kp:
        # KV Persistence: load the persisted (full-logical) blob — no prefill.
        scheduler.load_slot_state(seq, prior_blob, prior_len)
        n_past = prior_len
        start_hop = PRIOR_HOPS
    elif resumed and not kp:
        # No persistence: re-prefill the prior conversation from scratch.
        toks = conversation_tokens(backend, prefix_tokens, sess, PRIOR_HOPS)
        last = _prefill(backend, seq, toks)
        n_past = len(toks)
        start_hop = PRIOR_HOPS
    elif sp:
        # Shared Prefix: copy the holder's system prompt, then feed the user.
        scheduler.copy_prefix_to_slot(holder, seq, plen)
        user = backend.tokenize(USER_FMT.format(msg=session_suffix(sess)), add_special=False)
        last = _prefill(backend, seq, user, start=plen)
        n_past = plen + len(user)
        start_hop = 0
    else:
        # No shared prefix: prefill system prompt + user fresh.
        toks = backend.tokenize(
            SYSTEM_FMT.format(sp=big_system_prompt(prefix_tokens))
            + USER_FMT.format(msg=session_suffix(sess)),
            add_special=True,
        )
        last = _prefill(backend, seq, toks)
        n_past = len(toks)
        start_hop = 0

    # For the resume+kp path we have no fresh logits; seed the first hop from
    # a one-token decode at n_past.
    if resumed and kp:
        last = _prefill(
            backend, seq, backend.tokenize("assistant:", add_special=False), start=n_past
        )
        n_past += len(backend.tokenize("assistant:", add_special=False))

    # ── run the remaining hops ────────────────────────────────────────────
    for hop in range(start_hop, HOPS):
        if tl:
            # Tool Loop: produce the model's turn live, then feed only the
            # new tool result — no conversation re-prefill.
            _gen, n_past = _generate(backend, seq, last, n_past, GEN)
            new = backend.tokenize(_hop_text(hop), add_special=False)
            last = _prefill(backend, seq, new, start=n_past)
            n_past += len(new)
        else:
            # Stateless: re-prefill the ENTIRE conversation so far, generate.
            backend.seq_remove(seq)
            toks = conversation_tokens(backend, prefix_tokens, sess, hop + 1)
            last = _prefill(backend, seq, toks)
            n_past = len(toks)
            _gen, n_past = _generate(backend, seq, last, n_past, GEN)
    return n_past


def _rung_flags(rung: int):
    return {
        1: dict(sp=False, kp=False, tl=False),
        2: dict(sp=True, kp=False, tl=False),
        3: dict(sp=True, kp=True, tl=False),
        4: dict(sp=True, kp=True, tl=True),
    }[rung]


def _make_prior_blobs(backend, scheduler, holder, plen, resumed_ids, prefix_tokens):
    """Pre-produce a persisted blob per resumed session (system + user +
    PRIOR_HOPS hops), returning {sess: (blob, prior_len)}. Uses a scratch
    slot; the write time is a checkpoint cost, not part of the resume wall."""
    blobs = {}
    for sess in resumed_ids:
        seq = scheduler.open_slot()
        toks = conversation_tokens(backend, prefix_tokens, sess, PRIOR_HOPS)
        _prefill(backend, seq, toks)
        blobs[sess] = (scheduler.save_slot_state(seq), len(toks))
        scheduler.close_slot(seq)
    return blobs


# ── mode: corruption gate (blocking) ───────────────────────────────────────


def _feed_slice(backend, seq, toks, start):
    """Decode a slice of a pre-tokenized stream at ``start``; return end pos."""
    if toks:
        _prefill(backend, seq, toks, start=start)
    return start + len(toks)


def run_gate(args):
    """Blocking self-session integrity gate.

    Method (one variable = state control): tokenize the whole conversation
    ONCE into ``full``, then reach position N two ways per session type and
    compare first-token logits. Because both paths decode the SAME token list
    (just sliced at different indices), the KV they build is content- and
    position-identical — any logits difference is KV-state-control corruption,
    NOT a tokenisation artifact. Slice indices are arbitrary; they only need
    to exercise the SP-copy and KP-restore paths.

    Two session types, because SP and KP are ALTERNATIVES for establishing a
    session's base (a cold session uses SP; a resumed session uses KP — never
    both), so the composite is verified on each:
      cold      = Shared Prefix copy  + Tool-Loop live feed
      resumed   = KV Persistence load + Tool-Loop live feed
    Plus: the guard must never raise on a correct-order teardown.
    """
    from palimpsests.providers.native.scheduler import PrefixHolderInUseError, Scheduler

    backend = make_backend_for(args)
    result = {"kv_unified": True, "checks": [], "guard_raises": 0}

    def emit(**kw):
        result["checks"].append(kw)
        print(f"GATE {json.dumps(kw)}", flush=True)

    full = conversation_tokens(backend, args.prefix_tokens, 0, HOPS)
    n = len(full)
    p_share = n // 4  # arbitrary shared-prefix boundary (SP holder slice)
    p_prior = n // 2  # arbitrary resume boundary (KP blob slice)

    # Reference: the whole stream decoded in one clean sequence.
    _prefill(backend, 0, full)
    ref = first_token_logits(backend, 0, n)
    backend.seq_remove(0)

    sch = Scheduler(backend, max_active=args.n_seq_max)

    # ── cold session: SP copy(full[:p_share]) + TL feed(full[p_share:]) ────
    holder = sch.reserve_prefix_holder()
    sch.warm_prefix(holder, full[:p_share])
    s_cold = sch.open_slot()
    sch.copy_prefix_to_slot(holder, s_cold, p_share)
    end = _feed_slice(backend, s_cold, full[p_share:], p_share)  # TL live feed
    l2_cold = logits_l2(ref, first_token_logits(backend, s_cold, end))
    emit(check="cold_SP_TL", l2=l2_cold, token_identical=l2_cold < args.epsilon)

    # ── resumed session: KP load(full[:p_prior]) + TL feed(full[p_prior:]) ─
    scratch = sch.open_slot()
    _prefill(backend, scratch, full[:p_prior])
    blob = sch.save_slot_state(scratch)
    sch.close_slot(scratch)
    s_res = sch.open_slot()
    sch.load_slot_state(s_res, blob, p_prior)
    end = _feed_slice(backend, s_res, full[p_prior:], p_prior)  # TL live feed
    l2_res = logits_l2(ref, first_token_logits(backend, s_res, end))
    emit(check="resumed_KP_TL", l2=l2_res, token_identical=l2_res < args.epsilon)

    # ── guard: correct-order teardown must not raise ──────────────────────
    sch.close_slot(s_cold)
    sch.close_slot(s_res)
    try:
        sch.release_prefix_holder(holder)
    except PrefixHolderInUseError as exc:
        result["guard_raises"] += 1
        emit(check="guard_raised_on_release", error=str(exc))

    backend.close()
    ok = l2_cold < args.epsilon and l2_res < args.epsilon and result["guard_raises"] == 0
    gr = result["guard_raises"]
    print(
        f"GATE_RESULT {'PASS' if ok else 'FAIL'}  cold_L2={l2_cold:.6g}  "
        f"resumed_L2={l2_res:.6g}  guard_raises={gr}"
    )
    print("GATE JSON:", json.dumps(result), flush=True)


# ── memory instrumentation ─────────────────────────────────────────────────


def make_backend_for(args):
    class _A:
        model = args.model
        n_ctx = args.n_ctx
        n_seq_max = args.n_seq_max
        n_gpu_layers = args.n_gpu_layers
        kv_unified = 1

    return make_backend(_A())


# ── mode: one rung × one point ─────────────────────────────────────────────


def _pool_pressure_probe(backend, args, flags, resumed_ids, prefix_tokens):
    """Admit and HOLD every session's base state concurrently to surface pool
    pressure that the timed (sequential) rung would not: resumed sessions load
    FULL-LOGICAL blobs (their own cells, not shared), cold sessions copy the
    holder's shared prefix. Records peak KV cells resident and any admission
    failure (cell budget exhausted) / slot exhaustion (M > n_seq_max)."""
    from palimpsests.providers.native.scheduler import Scheduler

    sch = Scheduler(backend, max_active=args.n_seq_max)
    holder = None
    plen = 0
    if flags["sp"]:
        holder = sch.reserve_prefix_holder()
        sys_toks = backend.tokenize(
            SYSTEM_FMT.format(sp=big_system_prompt(prefix_tokens)), add_special=True
        )
        plen = sch.warm_prefix(holder, sys_toks)
    blobs = (
        _make_prior_blobs(backend, sch, holder, plen, sorted(resumed_ids), prefix_tokens)
        if flags["kp"]
        else {}
    )
    held = []
    admission_failures = 0
    slot_exhaustion = 0
    for sess in range(args.sessions):
        try:
            seq = sch.open_slot()
        except RuntimeError:
            slot_exhaustion += 1  # M exceeded the concurrent slot budget
            break
        try:
            if sess in resumed_ids and flags["kp"]:
                blob, prior_len = blobs[sess]
                sch.load_slot_state(seq, blob, prior_len)
            elif flags["sp"]:
                sch.copy_prefix_to_slot(holder, seq, plen)
            else:
                _prefill(backend, seq, conversation_tokens(backend, prefix_tokens, sess, 0))
            held.append(seq)
        except RuntimeError as exc:
            admission_failures += 1 if "llama_decode" in str(exc) else 0
            break
    lib = backend._lib
    mem = lib.llama_get_memory(backend._ctx)
    peak_cells = 0
    for seq in held:
        pm = int(lib.llama_memory_seq_pos_max(mem, seq))
        if pm >= 0:
            peak_cells += pm + 1
    for seq in held:
        sch.close_slot(seq)
    if holder is not None:
        sch.release_prefix_holder(holder)
    return {
        "held_concurrent": len(held),
        "peak_kv_cells": peak_cells,
        "admission_failures": admission_failures,
        "slot_exhaustion": slot_exhaustion,
    }


def run_rung(args):
    from palimpsests.providers.native.scheduler import PrefixHolderInUseError, Scheduler

    flags = _rung_flags(args.rung)
    backend = make_backend_for(args)
    mem_snapshot("after_load")
    prefix_tokens = args.prefix_tokens
    n_resumed = int(round(args.sessions * args.resume_fraction))
    resumed_ids = set(range(n_resumed))

    guard_raises = 0

    # Pool-pressure probe (concurrent residency) — separate from the timed
    # wall so the sub-additivity signal (per-mechanism decode work) is not
    # confounded by scheduling.
    pressure = _pool_pressure_probe(backend, args, flags, resumed_ids, prefix_tokens)

    def one_repeat():
        nonlocal guard_raises
        scheduler = Scheduler(backend, max_active=args.n_seq_max)
        holder = None
        plen = 0
        if flags["sp"]:
            holder = scheduler.reserve_prefix_holder()
            plen = scheduler.warm_prefix(
                holder,
                backend.tokenize(
                    SYSTEM_FMT.format(sp=big_system_prompt(prefix_tokens)), add_special=True
                ),
            )
        blobs = (
            _make_prior_blobs(backend, scheduler, holder, plen, sorted(resumed_ids), prefix_tokens)
            if flags["kp"]
            else {}
        )
        t0 = _now()
        # Sequential per-session execution: each session establishes its base
        # (copy / load / prefill) and runs its hops, then frees its slot. This
        # measures the TOTAL decode work of the rung (the sub-additivity
        # signal); concurrency would batch every rung uniformly, so the
        # rung-to-rung deltas are preserved. (The absolute wall vs the
        # server's continuous batching is caveated in the report.)
        for sess in range(args.sessions):
            seq = scheduler.open_slot()
            resumed = sess in resumed_ids
            blob, prior_len = blobs.get(sess, (None, 0))
            run_session(
                backend,
                scheduler,
                holder,
                plen,
                seq,
                sp=flags["sp"],
                kp=flags["kp"],
                tl=flags["tl"],
                resumed=resumed,
                prior_blob=blob,
                prior_len=prior_len,
                sess=sess,
                prefix_tokens=prefix_tokens,
            )
            scheduler.close_slot(seq)
        wall = _now() - t0
        if holder is not None:
            try:
                scheduler.release_prefix_holder(holder)
            except PrefixHolderInUseError:
                guard_raises += 1
        return wall

    one_repeat()  # warmup
    walls = [one_repeat() for _ in range(args.repeats)]
    mem_snapshot("after_repeats")

    summary = {
        "rung": args.rung,
        "flags": flags,
        "sessions": args.sessions,
        "resume_fraction": args.resume_fraction,
        "n_resumed": n_resumed,
        "prefix_tokens_requested": prefix_tokens,
        "hops": HOPS,
        "gen": GEN,
        "repeats": args.repeats,
        "wall_seconds_median": statistics.median(walls),
        "wall_seconds_min": min(walls),
        "wall_seconds_max": max(walls),
        "guard_raises": guard_raises,
        "pool_pressure": pressure,
    }
    env = {
        "python": platform.python_version(),
        "model": args.model,
        "n_ctx": args.n_ctx,
        "n_seq_max": args.n_seq_max,
        "kv_unified": True,
        "sampling": "greedy (argmax)",
    }
    print(f"\n=== composite rung {args.rung} M{args.sessions} resume{args.resume_fraction} ===")
    print(f"environment: {json.dumps(env)}")
    print(
        f"rung {args.rung}: median {summary['wall_seconds_median']:.3f}s "
        f"[{summary['wall_seconds_min']:.3f}-{summary['wall_seconds_max']:.3f}] "
        f"guard_raises={guard_raises} pool_pressure={pressure}"
    )
    print("\nJSON:")
    print(json.dumps({"env": env, "summary": summary}, indent=2))
    backend.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", required=True, choices=["gate", "rung"])
    ap.add_argument("--model", required=True)
    ap.add_argument("--n-ctx", type=int, default=32768)
    ap.add_argument("--n-seq-max", type=int, default=13)
    ap.add_argument("--n-gpu-layers", type=int, default=999)
    ap.add_argument("--prefix-tokens", type=int, default=1500)
    ap.add_argument("--rung", type=int, default=4, choices=[1, 2, 3, 4])
    ap.add_argument("--sessions", type=int, default=8)
    ap.add_argument("--resume-fraction", type=float, default=0.5)
    ap.add_argument("--epsilon", type=float, default=1e-6)
    ap.add_argument("--repeats", type=int, default=5)
    args = ap.parse_args()
    if args.mode == "gate":
        run_gate(args)
    else:
        run_rung(args)


if __name__ == "__main__":
    main()
