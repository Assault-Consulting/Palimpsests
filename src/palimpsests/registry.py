"""Engine registry — which inference engines exist and which one is active.

Two distinct concepts, deliberately not conflated:

1. **Installed** — an engine adapter is present and usable (the daemon
   responds, the native library imported, the binary exists). This is
   a property of the environment.

2. **Active** — the one engine that ``local_chat`` and friends route
   to right now. This is a *radio*, not a checkbox: exactly one engine
   is active at a time, globally.

Why radio, not checkbox
-----------------------
Cloud-provider registries are checkboxes: several providers enabled at
once, each addressed explicitly by name. Inference engines are
different — the caller says "run this prompt locally" without naming an
engine, and the registry decides which one. Having two engines both
"active" would make that routing ambiguous. One radio keeps the
routing deterministic: there is always exactly one answer to "who runs
this."

Per-call routing (letting one call target Ollama and the next target
the native service) is a deliberate future extension. The contract
here — one active engine globally — covers the overwhelming common case
and keeps v1 simple.

Persistence
-----------
The active-engine choice is persisted to a small JSON file so it
survives restarts. Installed-state is *not* persisted — it's
re-derived from the environment on each run, because a daemon that was
up yesterday may be down today.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_ENGINE_ID = "ollama"


@dataclass
class EngineRecord:
    """Registry entry for one engine adapter.

    ``installed`` is a snapshot at registration/refresh time, not a
    live probe — callers that need certainty call the adapter's own
    ``is_available()``.
    """

    engine_id: str
    control_level: int
    installed: bool = False


@dataclass
class RegistryState:
    """The full registry: known engines + which one is active."""

    engines: dict[str, EngineRecord] = field(default_factory=dict)
    active_engine_id: str = DEFAULT_ENGINE_ID


class EngineRegistry:
    """Tracks known engines and the single active choice.

    Thread-safe. The active choice is persisted to ``config_path`` as
    JSON; the known-engines map is rebuilt at runtime via
    ``register`` and is not itself persisted.
    """

    def __init__(self, config_path: Path) -> None:
        self._path = Path(config_path)
        self._lock = threading.Lock()
        self._state = RegistryState()
        self._load_active()

    # ─── registration ───────────────────────────────────────────────────

    def register(
        self, engine_id: str, *, control_level: int, installed: bool
    ) -> None:
        """Add or update an engine record.

        Idempotent: re-registering the same engine_id updates its
        installed-state and control level (e.g. after a fresh
        availability probe).
        """
        with self._lock:
            self._state.engines[engine_id] = EngineRecord(
                engine_id=engine_id,
                control_level=control_level,
                installed=installed,
            )

    def known(self) -> list[EngineRecord]:
        """All registered engine records."""
        with self._lock:
            return list(self._state.engines.values())

    def is_installed(self, engine_id: str) -> bool:
        with self._lock:
            record = self._state.engines.get(engine_id)
            return record is not None and record.installed

    # ─── active selection (radio) ───────────────────────────────────────

    @property
    def active_engine_id(self) -> str:
        with self._lock:
            return self._state.active_engine_id

    def set_active(self, engine_id: str) -> None:
        """Make ``engine_id`` the single active engine and persist it.

        Does not require the engine to be installed — a user may select
        an engine before its daemon is up. Routing-time code checks
        installed-state and surfaces a clear error if it isn't ready.
        Raises ``KeyError`` only if the engine was never registered, to
        catch typos early.
        """
        with self._lock:
            if engine_id not in self._state.engines:
                raise KeyError(
                    f"unknown engine {engine_id!r}; register it first"
                )
            self._state.active_engine_id = engine_id
            self._persist_active_locked()

    # ─── persistence ────────────────────────────────────────────────────

    def _load_active(self) -> None:
        """Load the persisted active-engine choice, if any."""
        if not self._path.exists():
            return
        try:
            data = json.loads(self._path.read_text())
        except (json.JSONDecodeError, OSError):
            # A corrupt or unreadable config falls back to the default
            # rather than crashing startup. The next set_active rewrites
            # it cleanly.
            return
        active = data.get("active_engine_id")
        if isinstance(active, str):
            self._state.active_engine_id = active

    def _persist_active_locked(self) -> None:
        """Write the active choice. Caller must hold the lock."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps({"active_engine_id": self._state.active_engine_id})
        )


# ─── Process-wide singleton ──────────────────────────────────────────────

_instance: EngineRegistry | None = None
_singleton_lock = threading.Lock()


def get_registry() -> EngineRegistry | None:
    """Return the active registry, or None if none is installed.

    Like the audit log, this returns None rather than lazy-initializing:
    the registry needs a config path the application entrypoint
    supplies. Tests install a tmp_path-backed registry explicitly.
    """
    return _instance


def set_registry(registry: EngineRegistry | None) -> None:
    """Install (or clear) the process-wide registry."""
    global _instance
    _instance = registry
