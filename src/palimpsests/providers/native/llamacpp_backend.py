"""The real level-3 backend: a thin ctypes mapping onto llama.cpp.

**Status: written on the shelf, NOT yet run on hardware.** This module
maps ``NativeBackend`` (the ADR-0002 seam) onto the low-level
``llama_cpp`` ctypes API. It is deliberately isolated behind the
``[native]`` extra and is *never* imported in CI: the scheduler, session,
and engine are verified against ``FakeBackend`` (pure Python, no model),
and this class is the separately-validated shim that runs only on real
hardware with a GGUF model.

Because it has not yet executed against a real ``libllama``, treat every
method as a *hypothesis to verify*, not proven code. The design choice
that makes that safe: each method is a single, named, isolated step that
maps to exactly one documented ``llama_cpp`` call, with a comment stating
which call and what can go wrong on first contact with hardware. When the
first real run fails (it will — the ctypes batch boundary is the classic
trap), the traceback should point at one specific call, not a tangled
batch builder.

What this maps (confirmed in ADR-0001):

- ``decode``     → build a ``llama_batch``, one ``llama_decode`` over many
                   sequences (continuous batching). THE hard part.
- ``seq_copy``   → ``llama_memory_seq_cp`` (shared-prefix broadcast).
- ``seq_remove`` → ``llama_memory_seq_rm`` (recycle a slot).
- ``state_get``  → ``llama_state_seq_get_data`` (tool loop + persistence).
- ``state_set``  → ``llama_state_seq_set_data``.
- ``tokenize`` / ``detokenize`` → ``llama_tokenize`` / ``llama_token_to_piece``.
- ``n_seq_max``  → the ``n_seq_max`` the context was created with.

The scheduler owns *when* and *in what combination* these run; this file
owns only the faithful C mapping. Keeping the two apart is the whole point
of the seam — the value (batching, prefix sharing, the tool loop,
persistence policy) is tested without a toolchain, and only this thin
layer needs a GPU to validate.

References to keep open while validating on hardware:
- llama.cpp ``llama.h`` (the authoritative signatures; they DO shift
  between releases — pin a known llama-cpp-python and note it below).
- ``examples/parallel/parallel.cpp`` (the multi-sequence batch + shared
  prefix pattern this mirrors).
- ``examples/save-load-state`` (the ``state_seq`` round-trip).

Validated against: (fill in once run) llama-cpp-python ==X.Y.Z,
llama.cpp commit ..., model ...gguf, on <hardware>.
"""
from __future__ import annotations

import ctypes
from collections.abc import Sequence
from palimpsests.providers.native.backend import BatchEntry, Token

# llama-cpp-python exposes the raw C API under llama_cpp.llama_cpp. It is
# imported lazily inside __init__ so that merely importing this module (or
# the package) never requires the native build to be present — the import
# error is raised only when someone actually constructs the backend.
_IMPORT_ERROR_HINT = (
    "LlamaCppBackend needs the [native] extra: pip install 'palimpsests[native]'. "
    "It pulls llama-cpp-python, which requires a C toolchain or a prebuilt wheel."
)


class LlamaCppBackend:
    """``NativeBackend`` over llama.cpp's low-level ctypes API.

    One instance owns one model and one context. The context is created
    with ``n_seq_max`` sequences — that number is the scheduler's slot
    budget (sessions + prefix holders together).

    Parameters mirror the knobs that actually matter for the level-3
    workload; everything else is left at llama.cpp defaults until a
    benchmark shows a reason to expose it.

    NOTE (unverified): the exact keyword names on ``llama_context_params``
    and the module layout (``llama_cpp.llama_cpp`` vs ``llama_cpp``) have
    varied across llama-cpp-python versions. The first hardware run must
    confirm these against the installed version and pin it in the module
    docstring.
    """

    def __init__(
        self,
        model_path: str,
        *,
        n_ctx: int = 4096,
        n_seq_max: int = 4,
        n_threads: int | None = None,
        n_gpu_layers: int = 0,
    ) -> None:
        try:
            # The low-level ctypes surface. Kept as ``_lib`` so every call
            # site below reads ``self._lib.llama_<x>`` — a 1:1 echo of the
            # C name, so a reader can grep llama.h for the signature.
            from llama_cpp import llama_cpp as _lib
        except ImportError as exc:  # pragma: no cover - hardware-only path
            raise ImportError(_IMPORT_ERROR_HINT) from exc

        self._lib = _lib
        self._n_seq_max = n_seq_max
        self._model = None
        self._ctx = None
        self._vocab = None

        # ── load the model ────────────────────────────────────────────────
        # Maps to llama_load_model_from_file(path, model_params).
        # Risk on first run: model_params must be built via
        # llama_model_default_params() and mutated, not constructed bare;
        # n_gpu_layers lives on model params, not context params.
        _lib.llama_backend_init()
        model_params = _lib.llama_model_default_params()
        model_params.n_gpu_layers = n_gpu_layers
        self._model = _lib.llama_load_model_from_file(
            model_path.encode("utf-8"), model_params
        )
        if not self._model:
            raise RuntimeError(f"llama_load_model_from_file failed for {model_path!r}")

        # ── create the context ────────────────────────────────────────────
        # Maps to llama_new_context_with_model(model, ctx_params).
        # Risk: the sequence-count field name. Older headers call it
        # n_seq_max; some bindings surface it differently. This is the
        # single most likely first-run AttributeError — isolated here.
        ctx_params = _lib.llama_context_default_params()
        ctx_params.n_ctx = n_ctx
        # First-run fix: llama.cpp asserts n_tokens_all <= n_batch inside
        # llama_decode. The default logical batch (2048) is smaller than a
        # large single-call prefill (e.g. a 4000-token prefix), which
        # aborts the process. The logical batch must admit the largest
        # prefill we can ever pass, which is bounded by n_ctx.
        ctx_params.n_batch = n_ctx
        ctx_params.n_seq_max = n_seq_max
        if n_threads is not None:
            ctx_params.n_threads = n_threads
        self._ctx = _lib.llama_new_context_with_model(self._model, ctx_params)
        if not self._ctx:
            raise RuntimeError("llama_new_context_with_model failed")

        # The vocab handle tokenize/detokenize need. In newer llama.cpp
        # the vocab is a separate object obtained from the model; in older
        # ones the model handle is passed directly. Resolved once here so
        # the token methods below don't each have to branch.
        self._vocab = self._resolve_vocab()

    # ─── vocab resolution (version shim) ──────────────────────────────────

    def _resolve_vocab(self):
        """Return the handle the tokenize calls expect.

        Newer llama.cpp: llama_model_get_vocab(model) -> vocab, and the
        tokenize/token_to_piece calls take the vocab. Older: they take the
        model. Try the new path, fall back to the model handle. Verify on
        hardware which branch the pinned version takes.
        """
        getter = getattr(self._lib, "llama_model_get_vocab", None)
        if getter is not None:
            return getter(self._model)
        return self._model

    # ─── model / vocab ────────────────────────────────────────────────────

    def tokenize(self, text: str, *, add_special: bool = True) -> list[Token]:
        """Text -> token ids. Maps to ``llama_tokenize``.

        Two-call idiom: call once with a zero/negative buffer to learn the
        length (llama_tokenize returns -needed when the buffer is too
        small), then once with the right-sized buffer. Doing it in one
        pass with a guessed buffer is the usual source of silent
        truncation — hence the explicit size negotiation.

        ``add_special`` adds the model's BOS/special tokens (the scheduler
        passes True for a prompt's first chunk, False for continuations).
        """
        raw = text.encode("utf-8")
        n_max = len(raw) + 16  # generous upper bound; tokens <= bytes + specials
        buf = (ctypes.c_int32 * n_max)()
        n = self._lib.llama_tokenize(
            self._vocab,
            raw,
            len(raw),
            buf,
            n_max,
            add_special,   # add_special
            True,          # parse_special (interpret control tokens in text)
        )
        if n < 0:
            # Buffer too small: llama_tokenize returns the negative of the
            # required length. Retry once at the exact size.
            need = -n
            buf = (ctypes.c_int32 * need)()
            n = self._lib.llama_tokenize(
                self._vocab, raw, len(raw), buf, need, add_special, True
            )
            if n < 0:
                raise RuntimeError("llama_tokenize failed to size its buffer")
        return [int(buf[i]) for i in range(n)]

    def detokenize(self, tokens: Sequence[Token]) -> str:
        """Token ids -> text. Maps to ``llama_token_to_piece`` per token.

        Each token is rendered to its piece and the pieces are joined.
        Risk: token_to_piece writes raw bytes (may be a partial UTF-8
        sequence for multi-byte glyphs), so bytes are accumulated and
        decoded once at the end with errors='replace' rather than decoded
        per token.
        """
        out = bytearray()
        piece = (ctypes.c_char * 64)()  # 64 bytes is ample for one piece
        for tok in tokens:
            n = self._lib.llama_token_to_piece(
                self._vocab, int(tok), piece, len(piece), 0, True
            )
            if n < 0:
                # Piece longer than the buffer: retry at the needed size.
                need = -n
                piece_big = (ctypes.c_char * need)()
                n = self._lib.llama_token_to_piece(
                    self._vocab, int(tok), piece_big, need, 0, True
                )
                out.extend(piece_big[:n])
            else:
                out.extend(piece[:n])
        return out.decode("utf-8", errors="replace")

    # ─── decode: THE batching primitive (highest-risk method) ─────────────

    def decode(self, entries: Sequence[BatchEntry]) -> dict[int, list[float]]:
        """One forward pass over a multi-sequence batch.

        This is the method the whole level exists for, and the one most
        likely to be wrong on first contact with hardware. It maps to:

            1. llama_batch_init(total_tokens, 0, 1)
            2. for each entry, for each token: fill batch.token[i],
               batch.pos[i] = start_pos + offset, batch.n_seq_id[i] = 1,
               batch.seq_id[i][0] = entry.seq_id, and batch.logits[i] = 1
               ONLY for the LAST token of an entry that wants logits.
            3. batch.n_tokens = total
            4. llama_decode(ctx, batch)
            5. for each entry that wanted logits: read the logits row for
               its last token via llama_get_logits_ith(ctx, last_index),
               copy n_vocab floats out.
            6. llama_batch_free(batch)

        Critical, easy-to-get-wrong invariants (verify each on hardware):

        - **logits flag placement.** The scheduler samples ONLY the last
          position of each sequence. Setting logits=1 on every token both
          wastes compute and, more importantly, changes which row
          llama_get_logits_ith must read. Exactly one logits=1 per
          logits-wanting entry, on its final token.
        - **pos correctness.** Each token's pos must be start_pos+offset.
          A copied/restored KV means start_pos > 0; getting this wrong
          silently corrupts attention (no error, just garbage output) —
          the single worst failure mode because it looks like the model,
          not the harness, is broken.
        - **seq_id array shape.** batch.seq_id[i] is itself a pointer; the
          [0] element is the sequence. n_seq_id[i] must be 1.
        - **index bookkeeping.** llama_get_logits_ith takes the ABSOLUTE
          index into the batch of the token whose logits you want, i.e.
          the running position of that entry's last token — not a
          per-sequence index. Track it while filling.

        Returns {seq_id: logits_vector} for entries that wanted logits.
        """
        lib = self._lib
        total = sum(len(e.tokens) for e in entries)
        if total == 0:
            return {}

        n_vocab = lib.llama_n_vocab(self._vocab)

        # 1) allocate a batch big enough for every token this step.
        batch = lib.llama_batch_init(total, 0, 1)
        try:
            # 2) fill it, tracking the absolute index of each entry's last
            #    token so we can read its logits row afterwards.
            last_index_for: dict[int, int] = {}
            i = 0
            for e in entries:
                n = len(e.tokens)
                for offset, tok in enumerate(e.tokens):
                    batch.token[i] = int(tok)
                    batch.pos[i] = e.start_pos + offset
                    batch.n_seq_id[i] = 1
                    batch.seq_id[i][0] = e.seq_id
                    # logits only on the final token, and only if wanted.
                    is_last = offset == n - 1
                    batch.logits[i] = 1 if (is_last and e.wants_logits) else 0
                    if is_last and e.wants_logits:
                        last_index_for[e.seq_id] = i
                    i += 1
            batch.n_tokens = total

            # 3) the single forward pass. Nonzero return is an error
            #    (1 = could not find a KV slot for the batch, etc.).
            rc = lib.llama_decode(self._ctx, batch)
            if rc != 0:
                raise RuntimeError(f"llama_decode returned {rc}")

            # 4) copy out the logits row for each entry that asked.
            out: dict[int, list[float]] = {}
            for seq_id, idx in last_index_for.items():
                ptr = lib.llama_get_logits_ith(self._ctx, idx)
                # ptr is a float* to n_vocab contiguous floats. Slice via
                # ctypes into a Python list (the scheduler wants a list).
                out[seq_id] = [float(ptr[j]) for j in range(n_vocab)]
            return out
        finally:
            # 6) always free the batch, even if decode raised.
            lib.llama_batch_free(batch)

    # ─── prefix sharing ───────────────────────────────────────────────────

    def seq_copy(
        self, src_seq: int, dst_seq: int, p0: int = -1, p1: int = -1
    ) -> None:
        """Copy KV cells src->dst over [p0, p1). Maps to
        ``llama_memory_seq_cp`` (older: ``llama_kv_cache_seq_cp``).

        The memory handle comes from llama_get_memory(ctx) in newer
        llama.cpp; older versions call the kv_cache function directly on
        the context. Resolved via _memory() so the call site stays one
        line. -1 bounds mean the whole sequence (the shared-prefix
        broadcast).
        """
        self._seq_op("cp", src_seq, dst_seq, p0, p1)

    def seq_remove(self, seq_id: int, p0: int = -1, p1: int = -1) -> None:
        """Drop KV cells of seq_id over [p0, p1). Maps to
        ``llama_memory_seq_rm`` (older: ``llama_kv_cache_seq_rm``)."""
        self._seq_op("rm", seq_id, seq_id, p0, p1)

    # ─── per-sequence state: tool loop + persistence ──────────────────────

    def state_get(self, seq_id: int) -> bytes:
        """Serialize one sequence's KV to bytes.

        Two-call idiom like tokenize: llama_state_seq_get_size(ctx, seq)
        for the byte count, then llama_state_seq_get_data(ctx, buf, size,
        seq) to fill a buffer of that size. Getting the size from the
        second call's return rather than pre-sizing is the usual bug.
        """
        lib = self._lib
        size = lib.llama_state_seq_get_size(self._ctx, seq_id)
        buf = (ctypes.c_uint8 * size)()
        written = lib.llama_state_seq_get_data(self._ctx, buf, size, seq_id)
        # Newer signatures take (ctx, dst, size, seq) and return bytes
        # written; older ones (ctx, dst, seq). If this raises a TypeError
        # on first run, drop the size arg — noted here so the fix is obvious.
        return bytes(buf[:written]) if written else bytes(buf)

    def state_set(self, seq_id: int, state: bytes) -> None:
        """Restore a sequence's KV from bytes. Maps to
        ``llama_state_seq_set_data(ctx, src, size, seq)``.

        The inverse of state_get. Same signature caveat: newer takes the
        size argument, older does not.
        """
        lib = self._lib
        buf = (ctypes.c_uint8 * len(state)).from_buffer_copy(state)
        lib.llama_state_seq_set_data(self._ctx, buf, len(state), seq_id)

    # ─── lifecycle ────────────────────────────────────────────────────────

    def n_seq_max(self) -> int:
        """Maximum concurrent sequences — the scheduler's slot count."""
        return self._n_seq_max

    def close(self) -> None:
        """Free context and model. Idempotent."""
        if self._ctx is not None:
            self._lib.llama_free(self._ctx)
            self._ctx = None
        if self._model is not None:
            self._lib.llama_free_model(self._model)
            self._model = None

    # ─── internal version shims ───────────────────────────────────────────

    def _memory(self):
        """Return the handle the seq_cp / seq_rm calls operate on.

        Newer llama.cpp routes KV ops through llama_get_memory(ctx) and
        llama_memory_seq_*; older ones call llama_kv_cache_seq_* on the
        context directly. This resolver lets _seq_op pick the pair that
        exists in the pinned build.
        """
        getter = getattr(self._lib, "llama_get_memory", None)
        if getter is not None:
            return getter(self._ctx)
        return self._ctx

    def _seq_op(self, op: str, a: int, b: int, p0: int, p1: int) -> None:
        """Dispatch a seq copy/remove across the two API generations.

        Isolated so both version branches live in one place. On the first
        hardware run, whichever pair of names resolves is the one the
        pinned llama-cpp-python ships; the other is dead. Note which in
        the module docstring once known.
        """
        lib = self._lib
        mem = self._memory()
        if op == "cp":
            fn = getattr(lib, "llama_memory_seq_cp", None) or getattr(
                lib, "llama_kv_cache_seq_cp"
            )
            fn(mem, a, b, p0, p1)
        elif op == "rm":
            fn = getattr(lib, "llama_memory_seq_rm", None) or getattr(
                lib, "llama_kv_cache_seq_rm"
            )
            fn(mem, a, p0, p1)
        else:  # pragma: no cover - internal misuse
            raise ValueError(f"unknown seq op {op!r}")
