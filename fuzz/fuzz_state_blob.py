"""Atheris harness for the KV state-blob validator.

What this fuzzes
----------------
``NativeSession.load_state`` — the frame parser standing between arbitrary
bytes and ``NativeBackend.state_set``. For the real backend that call is
``llama_state_seq_set_data``, a **C parser**, where a malformed blob is
undefined behavior rather than an exception. Everything the validator does
happens on the Python side of that line, and this harness attacks it there.

The invariant, stated as code
-----------------------------
For *any* input, exactly one of two things must be true:

1. ``load_state`` raises ``StateBlobError`` and the backend was **never
   called** — no byte crossed into C; or
2. ``load_state`` returns and the backend was called **exactly once**.

Anything else is a finding:

- a different exception type (``IndexError``, ``OverflowError``,
  ``struct.error``, ``ValueError`` from somewhere else) means an input
  reached code that did not expect it;
- an exception raised *after* the backend was called means bytes crossed
  the boundary before the validator finished deciding.

The second is the one worth losing sleep over, which is why the harness
checks the call count and not merely the exception type. "It raised" is
half the requirement.

What this does **not** fuzz — stated so the claim stays honest
--------------------------------------------------------------
llama.cpp's own state parser. Reaching it needs the ``[native]`` extra, a
GGUF model, and a GPU-or-CPU inference build — none of which exist in CI.
This harness proves our validator rejects what it should; it proves
*nothing* about what llama.cpp does with the bytes we do let through.
That surface is fuzzed, if at all, in a separate nightly job with a model
loaded. See ``fuzz/README.md``.

Nor is this authentication. A fuzzer that stumbles onto a well-formed
frame has "forged" one, and the validator will accept it — correctly. A
blob you did not produce is a trust problem, not a parsing problem, and it
is solved by a MAC, not by more validation.

Running locally
---------------
    pip install atheris
    python fuzz/fuzz_state_blob.py -atheris_runs=100000 -max_len=512
"""
from __future__ import annotations

import atheris
import sys

with atheris.instrument_imports():
    from collections.abc import Sequence  # noqa: E402
    from palimpsests.providers.native import session as pal_session  # noqa: E402
    from palimpsests.providers.native.scheduler import Scheduler  # noqa: E402

# Frame constants are read from the module rather than copied, so a rename
# breaks this harness loudly instead of quietly reducing it to a magic-check
# fuzzer that never explores past the first branch.
_MAGIC = pal_session._MAGIC
_FORMAT_VERSION = pal_session._FORMAT_VERSION

_U16 = 0xFFFF
_U32 = 0xFFFF_FFFF
_U64 = 0xFFFF_FFFF_FFFF_FFFF

_MAX_PAYLOAD = 128


class RecordingBackend:
    """A NativeBackend that records whether bytes ever crossed to it.

    Deliberately does nothing with the payload: this harness asks whether
    ``state_set`` was reached, not what a real backend would make of what
    reached it.
    """

    def __init__(self) -> None:
        self.set_calls: list[tuple[int, bytes]] = []

    def tokenize(self, text: str, *, add_special: bool = True) -> list[int]:
        return [1]

    def detokenize(self, tokens: Sequence[int]) -> str:
        return ""

    def decode(self, entries: Sequence[object]) -> dict[int, list[float]]:
        return {}

    def seq_copy(self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1) -> None:
        return None

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        return None

    def state_get(self, seq_id: int) -> bytes:
        return b""

    def state_set(self, seq_id: int, state: bytes) -> None:
        self.set_calls.append((seq_id, state))

    def n_seq_max(self) -> int:
        return 4

    def close(self) -> None:
        return None


_backend = RecordingBackend()
_session = pal_session.NativeSession(_backend, Scheduler(_backend, max_active=1))


def _fixed(fdp: atheris.FuzzedDataProvider, n: int) -> bytes:
    """Exactly ``n`` bytes, zero-padded when the fuzzer runs out."""
    raw = fdp.ConsumeBytes(n)
    return raw + b"\x00" * (n - len(raw))


def _build_blob(fdp: atheris.FuzzedDataProvider) -> bytes:
    """Produce an input, biased so the fuzzer gets past the magic check.

    Purely random bytes essentially never carry the six-byte magic, so an
    unbiased harness would spend its entire budget re-proving that the first
    branch works. Three modes keep every later branch reachable:

    0. raw bytes — the adversarial baseline;
    1. a well-formed frame over a fuzzer-chosen payload, with a
       fuzzer-chosen position (exercises the n_past ceiling and the success
       path);
    2. a near-miss — every field independently fuzzed, so the version check,
       the declared-vs-actual length check, and the empty-payload check each
       see both sides.
    """
    mode = fdp.ConsumeIntInRange(0, 2)

    if mode == 0:
        return fdp.ConsumeBytes(512)

    if mode == 1:
        payload = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, _MAX_PAYLOAD))
        n_past = fdp.ConsumeIntInRange(0, _U32)
        return b"".join(
            (
                _MAGIC,
                _FORMAT_VERSION.to_bytes(2, "big"),
                n_past.to_bytes(4, "big"),
                len(payload).to_bytes(8, "big"),
                payload,
            )
        )

    magic = _MAGIC if fdp.ConsumeBool() else _fixed(fdp, len(_MAGIC))
    version = fdp.ConsumeIntInRange(0, _U16)
    n_past = fdp.ConsumeIntInRange(0, _U32)
    payload = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, _MAX_PAYLOAD))
    declared = len(payload) if fdp.ConsumeBool() else fdp.ConsumeIntInRange(0, _U64)
    return b"".join(
        (
            magic,
            version.to_bytes(2, "big"),
            n_past.to_bytes(4, "big"),
            declared.to_bytes(8, "big"),
            payload,
        )
    )


def TestOneInput(data: bytes) -> None:  # noqa: N802 — atheris's required name
    fdp = atheris.FuzzedDataProvider(data)
    blob = _build_blob(fdp)

    _backend.set_calls.clear()

    try:
        _session.load_state(blob)
    except pal_session.StateBlobError:
        # Rejected. The whole point: rejection happens before the hand-off.
        if _backend.set_calls:
            raise AssertionError(
                "load_state rejected a blob AFTER passing it to the backend: "
                f"{blob[:32].hex()}"
            ) from None
        return

    # Accepted. It must have reached the backend exactly once.
    if len(_backend.set_calls) != 1:
        raise AssertionError(
            f"load_state accepted a blob but called state_set "
            f"{len(_backend.set_calls)} times: {blob[:32].hex()}"
        )


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
