# Fuzzing

## What is fuzzed, and why this target

`NativeSession.load_state` — the frame validator that stands between
arbitrary bytes and `NativeBackend.state_set`.

That boundary is the one worth attacking. For the real backend,
`state_set` is `llama_state_seq_set_data`: a parser written in C, where a
malformed blob is undefined behavior rather than a Python exception. Every
check our validator makes happens on the Python side of that line, and it
either holds for all inputs or it does not.

The 2026-07 internal audit ([`docs/security/AUDIT-2026-07.md`](../docs/security/AUDIT-2026-07.md))
is the reason this harness exists, and also the reason it is aimed here
rather than where fuzzing was first proposed. Its recommendation, quoted
in substance: fuzzing the pure-Python surfaces (`_canonical`,
`content_key`) has little to find, because there is barely a parser there;
the boundary worth fuzzing is the state parsing fed by `state_set`, or at
minimum the size/version header validation on our side before the bytes
cross into C. The header validation now exists, and this is what attacks
it.

## The invariant

For **any** input, exactly one of these must be true:

1. `load_state` raises `StateBlobError` and the backend was **never
   called** — no byte crossed into C; or
2. `load_state` returns and the backend was called **exactly once**.

Anything else is a finding:

| Observed | What it means |
|---|---|
| `IndexError`, `OverflowError`, `struct.error`, an unrelated `ValueError` | an input reached code that did not expect it |
| any exception raised **after** `state_set` was called | bytes crossed the boundary before the validator finished deciding |

The second row is the serious one, and it is why the harness asserts on the
**call count**, not merely on the exception type. "It raised" is half the
requirement.

## What this proves — and, more importantly, what it does not

**It proves** that our validator rejects what it should reject, and that
rejection always happens before the hand-off.

**It does not prove anything about llama.cpp's state parser.** Reaching
that code needs the `[native]` extra, a GGUF model, and an inference build
— none of which exist in CI. This harness says nothing about what
llama.cpp does with the bytes we *do* let through. Fuzzing that surface is
a separate exercise, with a model loaded, outside this workflow.

**It is not authentication.** A fuzzer that stumbles onto a well-formed
frame has, in effect, forged one — and the validator will accept it, which
is correct. A blob you did not produce is a trust problem, not a parsing
problem. It is solved by a MAC (HMAC-SHA256 under a keychain-derived key)
over persisted blobs, which lands together with the disk-backed KV store —
the point at which blobs first arrive from outside the process. Until
then: do not pass `load_state` a blob you did not produce. See
[`SECURITY.md`](../SECURITY.md), "Accepted risks".

## Why the harness shapes its own inputs

Purely random bytes essentially never carry the six-byte magic, so an
unbiased harness would spend its entire budget re-proving that the first
branch works. `_build_blob` therefore draws one of three shapes from the
fuzzer:

- **raw bytes** — the adversarial baseline;
- **a well-formed frame** over a fuzzer-chosen payload and position —
  exercises the `n_past` ceiling and the success path;
- **a near-miss** — every field independently fuzzed, so the version
  check, the declared-vs-actual length check, and the empty-payload check
  each see both sides.

Frame constants are read from `session.py` rather than copied here. A
rename then breaks the harness loudly, instead of quietly degrading it into
a magic-check fuzzer that never explores past the first branch.

## Running it

```bash
pip install atheris                     # Linux, CPython 3.11
pip install -e .                        # base package is enough
python fuzz/fuzz_state_blob.py -atheris_runs=100000 -max_len=512
```

A crash writes a reproducer file. Replay it:

```bash
python fuzz/fuzz_state_blob.py path/to/crash-<sha>
```

## In CI

[`.github/workflows/fuzz.yml`](../.github/workflows/fuzz.yml):

- **every push and PR** — 25 000 runs. Not exploration; a regression gate,
  so a crash once found cannot come back unnoticed.
- **nightly** — 15 minutes of real exploration.

Linux only, Python 3.11 pinned: Atheris bundles libFuzzer, ships wheels for
Linux alone, and trails CPython releases. The job sits outside the CI
matrix precisely so those constraints do not leak into it.
