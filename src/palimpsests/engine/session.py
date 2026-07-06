"""Stateful inference session — the level-3 contract.

A session holds live KV state on the server across multiple turns. It
exists only for engines whose ``stateful_sessions`` capability is set;
levels 1-2 never return one (their ``open_session`` raises
``CapabilityUnsupported``).

This is a ``Protocol``, not a base class: level-3 adapters will each
have their own session implementation tied to their serving process,
and structural typing lets the orchestrator depend on the shape without
inheriting from a shared class. The methods are defined by behavior:

- ``send`` streams a turn's response, reusing the session's existing KV
  instead of re-prefilling the whole conversation.
- ``append_tool_result`` continues generation after a server-side tool
  call, feeding the result back into the same KV.
- ``save_state`` / ``load_state`` move the KV to and from bytes — the
  substrate for KV-as-memory persistence. The bytes are opaque to the
  caller and specific to the engine that produced them.
- ``close`` releases the session's server-side resources.
"""
from __future__ import annotations

from collections.abc import Iterator
from palimpsests.engine.messages import ChatChunk
from typing import Protocol, runtime_checkable


@runtime_checkable
class InferenceSession(Protocol):
    """A live, stateful inference session (level 3 only)."""

    def send(self, content: str) -> Iterator[ChatChunk]:
        """Stream the response to one user turn, reusing session KV."""
        ...

    def append_tool_result(self, tool_call_id: str, result: str) -> Iterator[ChatChunk]:
        """Resume generation after a server-side tool call.

        Continues from the preserved KV, appending only the tool result
        rather than re-reading the conversation.
        """
        ...

    def save_state(self) -> bytes:
        """Serialize the session's KV state to opaque bytes."""
        ...

    def load_state(self, state: bytes) -> None:
        """Restore KV state previously produced by ``save_state``."""
        ...

    def close(self) -> None:
        """Release server-side resources held by the session."""
        ...
