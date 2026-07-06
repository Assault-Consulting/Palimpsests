"""llama.cpp adapter — level 2 (embedded engine via a managed subprocess).

Level 2 is the first *control* level. Unlike level 1, where the daemon
owns loading and we only translate wire formats, here we own the
process: we spawn ``llama-server`` with the flags that
``EngineMemoryConfig`` maps to, so KV-cache quantization, flash
attention, GPU offload, and mmap are actually applied by our process.
That is the whole point of the level — ``EngineMemoryConfig`` stops
being advisory and starts being enforced.

Two modes:

- **spawn (default):** given a ``model_path``, we start and own a
  ``llama-server``, applying the memory config as launch flags. This is
  the mode that makes L2 a control level.
- **attach:** given a ``base_url``, we talk to a server the user already
  started (like level 1). The memory config can't be applied then — the
  user chose the flags at launch — so we don't pretend to; attach is a
  convenience, not the headline.

The subprocess lifecycle (spawn, readiness, shutdown) lives in
``process.py``; this adapter decides *what* flags to pass and *how* to
translate the wire protocol, staying parallel in shape to the Ollama
adapter so callers see one contract.

llama-server exposes an OpenAI-compatible ``/v1/chat/completions`` which
we use for chat, streaming Server-Sent Events.
"""
from __future__ import annotations

import httpx
import json
from collections.abc import Iterator, Sequence
from palimpsests.engine import (
    BaseInferenceEngine,
    ChatChunk,
    EngineCapabilities,
    EngineMemoryConfig,
    Message,
    ModelInfo,
)
from palimpsests.providers.errors import (
    EngineRequestError,
    EngineUnavailable,
    ModelNotFound,
)
from palimpsests.providers.process import LlamaServerProcess
from pathlib import Path

ENGINE_ID = "llamacpp"
DEFAULT_BINARY = "llama-server"


def memory_to_args(memory: EngineMemoryConfig | None) -> list[str]:
    """Translate EngineMemoryConfig into llama-server launch flags.

    This is where level 2 earns its name: every field that level 1 had
    to ignore becomes a real flag here. Pure function, so the mapping is
    tested without spawning anything.

    - context_size  -> -c N
    - gpu_layers    -> -ngl N        (offload N layers to GPU)
    - flash_attention -> --flash-attn
    - kv_cache_quant  -> --cache-type-k/-v TYPE (needs flash attention,
                         already enforced by EngineMemoryConfig)
    - use_mmap=False  -> --no-mmap   (mmap is the server default)
    - draft_model     -> --model-draft PATH (speculative decoding)
    """
    if memory is None:
        return []
    args: list[str] = []
    if memory.context_size is not None:
        args += ["-c", str(memory.context_size)]
    if memory.gpu_layers is not None:
        args += ["-ngl", str(memory.gpu_layers)]
    if memory.flash_attention:
        args += ["--flash-attn"]
    if memory.kv_cache_quant is not None:
        # EngineMemoryConfig has already validated flash_attention is on.
        args += [
            "--cache-type-k",
            memory.kv_cache_quant,
            "--cache-type-v",
            memory.kv_cache_quant,
        ]
    if not memory.use_mmap:
        args += ["--no-mmap"]
    if memory.draft_model is not None:
        args += ["--model-draft", memory.draft_model]
    return args


class LlamaCppEngine(BaseInferenceEngine):
    """A level-2 engine backed by a managed llama-server subprocess.

    In spawn mode (``model_path`` given) the engine owns the server
    process and applies ``memory`` as launch flags on first use. In
    attach mode (``base_url`` given) it talks to an already-running
    server and ignores ``memory`` at launch time.
    """

    def __init__(
        self,
        *,
        model_path: str | None = None,
        base_url: str | None = None,
        binary: str = DEFAULT_BINARY,
        memory: EngineMemoryConfig | None = None,
        readiness_timeout: float = 60.0,
        read_timeout: float = 300.0,
    ) -> None:
        if (model_path is None) == (base_url is None):
            raise ValueError(
                "provide exactly one of model_path (spawn) or base_url (attach)"
            )
        self._model_path = model_path
        self._binary = binary
        self._launch_memory = memory
        self._readiness_timeout = readiness_timeout
        self._timeout = httpx.Timeout(read_timeout, connect=5.0)

        self._process: LlamaServerProcess | None = None
        if base_url is not None:
            # Attach mode: no process ownership.
            self._base_url = base_url.rstrip("/")
            self._client = httpx.Client(base_url=self._base_url, timeout=self._timeout)
        else:
            # Spawn mode: the process is created lazily on first use so
            # constructing the engine is cheap and side-effect-free.
            self._base_url = None
            self._client = None

    # ─── identity ────────────────────────────────────────────────────────

    @property
    def engine_id(self) -> str:
        return ENGINE_ID

    @property
    def capabilities(self) -> EngineCapabilities:
        # Level 2: streaming yes; stateful/L3 features no. Same stateless
        # shape as L1 — the difference is control over memory, not a new
        # session model. open_session still raises CapabilityUnsupported.
        return EngineCapabilities(control_level=2, streaming=True)

    # ─── lifecycle ───────────────────────────────────────────────────────

    def _ensure_started(self) -> httpx.Client:
        """Start the managed server on first use (spawn mode) and return
        a client bound to it. In attach mode the client already exists."""
        if self._client is not None:
            return self._client
        # spawn mode
        extra = memory_to_args(self._launch_memory)
        self._process = LlamaServerProcess(
            binary=self._binary,
            model_path=self._model_path,  # type: ignore[arg-type]
            extra_args=extra,
            readiness_timeout=self._readiness_timeout,
        )
        self._process.start()
        self._base_url = self._process.base_url
        self._client = httpx.Client(base_url=self._base_url, timeout=self._timeout)
        return self._client

    def is_available(self) -> bool:
        """True if the server can be reached (attach) or started (spawn).

        In attach mode this pings the health endpoint. In spawn mode it
        reports whether a model file is present to launch — starting the
        process here would be too heavy for a availability probe, so we
        check the precondition instead.
        """
        if self._client is not None and self._process is None:
            # attach mode: real health check
            try:
                resp = self._client.get("/health", timeout=self._timeout)
                return resp.status_code == 200
            except httpx.HTTPError:
                return False
        # spawn mode: can we launch? (model present)
        return self._model_path is not None and Path(self._model_path).exists()

    # ─── models ──────────────────────────────────────────────────────────

    def list_models(self) -> Sequence[ModelInfo]:
        """List models the server reports via ``/v1/models``.

        A managed server serves exactly one model, but we read it from
        the API rather than assume, so attach mode reflects reality.
        """
        client = self._ensure_started()
        try:
            resp = client.get("/v1/models")
        except httpx.ConnectError as e:
            raise EngineUnavailable(
                f"cannot reach llama-server at {self._base_url}"
            ) from e
        except httpx.HTTPError as e:
            raise EngineRequestError(f"listing models failed: {e}") from e

        if resp.status_code != 200:
            raise EngineRequestError(
                "listing models failed",
                status=resp.status_code,
                body=resp.text[:500],
            )
        data = resp.json()
        models: list[ModelInfo] = []
        for entry in data.get("data", []):
            models.append(
                ModelInfo(name=entry.get("id", ""), engine_id=ENGINE_ID)
            )
        return models

    # ─── chat ────────────────────────────────────────────────────────────

    def chat_stream(
        self,
        *,
        model: str,
        messages: Sequence[Message],
        memory: EngineMemoryConfig | None = None,
    ) -> Iterator[ChatChunk]:
        """Stream a chat response via OpenAI-compatible SSE.

        Note ``memory`` here is a per-call hint; on level 2 the KV/quant/
        offload settings are fixed at server launch (they're process-wide
        flags), so a per-call memory config cannot change them. We accept
        the parameter for contract parity but do not restart the server
        mid-stream — the launch-time ``memory`` is what applied.
        """
        client = self._ensure_started()
        payload = {
            "model": model,
            "messages": list(messages),
            "stream": True,
        }
        try:
            with client.stream(
                "POST", "/v1/chat/completions", json=payload
            ) as resp:
                if resp.status_code == 404:
                    resp.read()
                    raise ModelNotFound(model, ENGINE_ID)
                if resp.status_code != 200:
                    resp.read()
                    raise EngineRequestError(
                        "chat request failed",
                        status=resp.status_code,
                        body=resp.text[:500],
                    )
                yield from self._iter_sse(resp)
        except httpx.ConnectError as e:
            raise EngineUnavailable(
                f"cannot reach llama-server at {self._base_url}"
            ) from e
        except httpx.HTTPError as e:
            raise EngineRequestError(f"chat request failed: {e}") from e

    def _iter_sse(self, resp: httpx.Response) -> Iterator[ChatChunk]:
        """Parse OpenAI-style Server-Sent Events into ChatChunks.

        Each event line is ``data: {json}``; the terminal event is
        ``data: [DONE]``. Deltas live in choices[0].delta.content;
        the finish reason in choices[0].finish_reason.
        """
        for line in resp.iter_lines():
            if not line or not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                return
            try:
                obj = json.loads(data)
            except json.JSONDecodeError as e:
                raise EngineRequestError(
                    f"malformed SSE line from llama-server: {data[:200]}"
                ) from e
            choices = obj.get("choices") or [{}]
            choice = choices[0]
            delta = choice.get("delta", {}).get("content", "") or ""
            finish = choice.get("finish_reason")
            if finish is not None:
                yield ChatChunk(delta=delta, done=True, finish_reason=finish)
            else:
                yield ChatChunk(delta=delta)

    # ─── lifecycle ───────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the HTTP client and, in spawn mode, stop the server."""
        if self._client is not None:
            self._client.close()
        if self._process is not None:
            self._process.stop()
            self._process = None
