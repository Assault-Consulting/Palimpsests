"""Ollama adapter — level 1 (thin HTTP client to an external daemon).

Level 1 is maximum compatibility, zero control: we speak Ollama's HTTP
API and translate its wire format into the engine contract, but we do
not manage loading, quantization, or batching — the daemon owns all of
that. What we get in return is that anything Ollama can run, we can run,
with no native build on our side.

Design choices
--------------
- **Plain httpx, no SDK, no retries.** We don't pull the ``ollama``
  Python package: it would hide the wire protocol and add a dependency
  for something that is a handful of HTTP calls. Retry policy is a
  caller concern, so the client is created with no retry layer.
- **Streaming is the primitive.** ``chat_stream`` reads Ollama's
  newline-delimited JSON stream; ``chat`` is inherited from the base
  and accumulates it. Adapters implement streaming only.
- **Memory config is best-effort.** Level 1 exposes only what Ollama
  actually accepts (``num_ctx`` from ``context_size``, ``num_gpu`` from
  ``gpu_layers``). Fields Ollama can't honor (KV-cache quant, flash
  attention) are silently ignored — ``capabilities`` already told the
  truth about what this level can do, so ignoring them is honest, not a
  surprise.
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

ENGINE_ID = "ollama"
DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaEngine(BaseInferenceEngine):
    """A level-1 engine backed by a running Ollama daemon."""

    def __init__(
        self,
        *,
        base_url: str = DEFAULT_BASE_URL,
        connect_timeout: float = 5.0,
        read_timeout: float = 300.0,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        # Separate connect vs read timeout: a stream can legitimately
        # run for minutes, but a dead daemon should fail fast on connect.
        self._timeout = httpx.Timeout(read_timeout, connect=connect_timeout)
        self._client = httpx.Client(base_url=self._base_url, timeout=self._timeout)

    # ─── identity ────────────────────────────────────────────────────────

    @property
    def engine_id(self) -> str:
        return ENGINE_ID

    @property
    def capabilities(self) -> EngineCapabilities:
        # Level 1: streaming yes, everything stateful/level-3 no. The
        # inherited open_session raises CapabilityUnsupported on the
        # strength of these flags.
        return EngineCapabilities(control_level=1, streaming=True)

    # ─── availability ────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """True if the daemon answers a lightweight request.

        Used by the registry to derive installed-state. Never raises —
        a down daemon is a normal, expected condition, reported as False.
        """
        try:
            resp = self._client.get("/api/tags", timeout=self._timeout)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    # ─── models ──────────────────────────────────────────────────────────

    def list_models(self) -> Sequence[ModelInfo]:
        """List models the daemon currently has, via ``/api/tags``."""
        try:
            resp = self._client.get("/api/tags")
        except httpx.ConnectError as e:
            raise EngineUnavailable(
                f"cannot reach Ollama at {self._base_url}"
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
        for entry in data.get("models", []):
            details = entry.get("details") or {}
            models.append(
                ModelInfo(
                    name=entry.get("name", ""),
                    engine_id=ENGINE_ID,
                    size_bytes=entry.get("size"),
                    quant=details.get("quantization_level"),
                    loaded=False,  # /api/tags lists on-disk, not loaded
                )
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
        """Stream a chat response from ``/api/chat`` (NDJSON).

        Each line of the response is a JSON object. Intermediate lines
        carry ``message.content`` deltas; the terminal line has
        ``done: true`` and a ``done_reason``.
        """
        payload: dict = {
            "model": model,
            "messages": list(messages),
            "stream": True,
        }
        options = self._memory_to_options(memory)
        if options:
            payload["options"] = options

        try:
            with self._client.stream(
                "POST", "/api/chat", json=payload
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
                yield from self._iter_chunks(resp)
        except httpx.ConnectError as e:
            raise EngineUnavailable(
                f"cannot reach Ollama at {self._base_url}"
            ) from e
        except httpx.HTTPError as e:
            raise EngineRequestError(f"chat request failed: {e}") from e

    def _iter_chunks(self, resp: httpx.Response) -> Iterator[ChatChunk]:
        """Translate Ollama's NDJSON lines into ChatChunks."""
        for line in resp.iter_lines():
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as e:
                raise EngineRequestError(
                    f"malformed stream line from Ollama: {line[:200]}"
                ) from e

            if obj.get("done"):
                yield ChatChunk(
                    delta=obj.get("message", {}).get("content", ""),
                    done=True,
                    finish_reason=obj.get("done_reason"),
                )
            else:
                yield ChatChunk(
                    delta=obj.get("message", {}).get("content", ""),
                )

    # ─── memory mapping ──────────────────────────────────────────────────

    @staticmethod
    def _memory_to_options(memory: EngineMemoryConfig | None) -> dict:
        """Map the subset of EngineMemoryConfig that Ollama accepts.

        Ollama's ``options`` understands ``num_ctx`` and ``num_gpu``.
        The rest of EngineMemoryConfig (KV-cache quant, flash attention,
        mmap, draft model) belongs to lower levels of control and is
        deliberately ignored here — level 1 never claimed it.
        """
        if memory is None:
            return {}
        options: dict = {}
        if memory.context_size is not None:
            options["num_ctx"] = memory.context_size
        if memory.gpu_layers is not None:
            options["num_gpu"] = memory.gpu_layers
        return options

    # ─── lifecycle ───────────────────────────────────────────────────────

    def close(self) -> None:
        self._client.close()
