"""Engine error taxonomy — shared across all adapters.

These are backend-agnostic on purpose. The orchestration layer catches
``ModelNotFound`` or ``EngineUnavailable`` without caring whether the
active engine is Ollama, llama.cpp, or the native service — the same
concept ("that model isn't here", "the backend is down") maps to the
same exception regardless of level. This keeps error handling in the
"behavior via capabilities, not isinstance" spirit: callers branch on
the failure kind, never on the adapter type.

Concrete adapters translate their backend's wire errors (HTTP status,
connection refused, subprocess exit) into these.
"""
from __future__ import annotations


class EngineError(Exception):
    """Base for every engine-level failure."""


class EngineUnavailable(EngineError):
    """The backend could not be reached at all.

    Connection refused, DNS failure, timeout on connect — the daemon or
    process isn't answering. Distinct from a request that reached the
    backend and came back an error.
    """


class ModelNotFound(EngineError):
    """The requested model is not available on this engine."""

    def __init__(self, model: str, engine_id: str) -> None:
        self.model = model
        self.engine_id = engine_id
        super().__init__(
            f"model {model!r} not found on engine {engine_id!r}"
        )


class EngineRequestError(EngineError):
    """The backend was reached but returned an error or malformed reply.

    Carries the HTTP status (when there is one) and a short body excerpt
    so the failure is diagnosable without re-running with a debugger.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        body: str | None = None,
    ) -> None:
        self.status = status
        self.body = body
        detail = message
        if status is not None:
            detail = f"{detail} (HTTP {status})"
        super().__init__(detail)
