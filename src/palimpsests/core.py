"""Orchestration — wires registry, audit, context, and engines together.

This is the layer the CLI (and any downstream embedder) calls. It owns
the decisions the individual pieces deliberately don't:

- **where the engine registration and ``@audited`` wrapping happen** —
  here, not in the adapter. ``OllamaEngine`` stays a clean HTTP client
  with no knowledge of our registry or audit log; this module is what
  knows about global state. A downstream product can embed the adapter
  directly and skip all of this.
- **how context management enters the chat flow** — ``chat`` runs the
  message list through a ``ContextWindowManager`` before handing it to
  the engine, so context fitting is automatic rather than every caller
  remembering to do it.

App state (config dir, registry, audit log) is initialized once via
``init_app`` and cached. Tests build their own ``AppContext`` with
tmp paths instead.
"""
from __future__ import annotations

import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from palimpsests.audit import (
    AuditLog,
    audited,
    generate_key,
    load_or_create_key,
    set_audit_log,
)
from palimpsests.context import ContextWindowManager
from palimpsests.engine import ChatChunk, Message, ModelInfo
from palimpsests.providers import OllamaEngine
from palimpsests.registry import DEFAULT_ENGINE_ID, EngineRegistry, set_registry
from pathlib import Path

APP_NAME = "palimpsests"


def default_config_dir() -> Path:
    """Return the per-user config directory, honoring XDG on Linux."""
    override = os.environ.get("PALIMPSESTS_CONFIG_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / APP_NAME


# ─── engine construction ─────────────────────────────────────────────────

# Known engine adapters and how to build one. Only Ollama exists today;
# llama.cpp and the native slot register here in later PRs. Keeping the
# factory in a table (not a chain of ifs) means adding an engine is a
# one-line change.
_ENGINE_FACTORIES = {
    "ollama": OllamaEngine,
}


@dataclass
class AppContext:
    """The initialized application state.

    Holds the registry and the constructed engines. Built by
    ``init_app`` for real use, or directly by tests with tmp paths.
    """

    config_dir: Path
    registry: EngineRegistry
    engines: dict[str, OllamaEngine]

    def active_engine(self) -> OllamaEngine:
        """Return the currently active engine instance.

        Raises KeyError if the active engine id has no constructed
        instance — which only happens if the config names an engine we
        don't know how to build.
        """
        engine_id = self.registry.active_engine_id
        return self.engines[engine_id]


def init_app(config_dir: Path | None = None) -> AppContext:
    """Initialize app state: config dir, registry, audit log, engines.

    Idempotent enough for a CLI invocation: safe to call once per run.
    Registers every known engine and probes availability so the
    registry's installed-state reflects reality this run.
    """
    cfg = config_dir or default_config_dir()
    cfg.mkdir(parents=True, exist_ok=True)

    # Audit log: encrypted, keyed from the OS keychain when available,
    # otherwise an ephemeral key so a headless run still audits (to a
    # fresh db) rather than crashing.
    try:
        key = load_or_create_key()
    except RuntimeError:
        key = generate_key()
    audit_log = AuditLog(cfg / "audit.db", key)
    set_audit_log(audit_log)

    registry = EngineRegistry(cfg / "registry.json")
    set_registry(registry)

    engines: dict[str, OllamaEngine] = {}
    for engine_id, factory in _ENGINE_FACTORIES.items():
        engine = factory()
        engines[engine_id] = engine
        installed = engine.is_available()
        registry.register(
            engine_id,
            control_level=engine.capabilities.control_level,
            installed=installed,
        )

    return AppContext(config_dir=cfg, registry=registry, engines=engines)


# ─── orchestrated operations (audited) ───────────────────────────────────


@audited("engine.list_models", model_locality="local")
def list_models(ctx: AppContext) -> Sequence[ModelInfo]:
    """List models on the active engine."""
    return ctx.active_engine().list_models()


@audited("engine.select")
def select_engine(ctx: AppContext, engine_id: str) -> None:
    """Make ``engine_id`` the active engine."""
    ctx.registry.set_active(engine_id)


def list_engines(ctx: AppContext) -> list[tuple[str, int, bool, bool]]:
    """Return (engine_id, control_level, installed, active) for each
    known engine. Not audited — it's a pure read of local state."""
    active = ctx.registry.active_engine_id
    rows: list[tuple[str, int, bool, bool]] = []
    for record in ctx.registry.known():
        rows.append(
            (
                record.engine_id,
                record.control_level,
                record.installed,
                record.engine_id == active,
            )
        )
    return rows


@audited("model.call", model_locality="local")
def chat(
    ctx: AppContext,
    *,
    model: str,
    messages: Sequence[Message],
    context_size: int = 8192,
) -> Iterator[ChatChunk]:
    """Stream a chat response through the active engine.

    The message list is fitted to a context budget first (sink/window/
    evict) so long conversations don't overflow. Context management is
    applied here, in orchestration, so no individual caller has to
    remember it.
    """
    manager = ContextWindowManager(context_size=context_size)
    fitted = manager.fit(messages)
    return ctx.active_engine().chat_stream(
        model=model, messages=fitted.messages
    )


__all__ = [
    "APP_NAME",
    "AppContext",
    "DEFAULT_ENGINE_ID",
    "chat",
    "default_config_dir",
    "init_app",
    "list_engines",
    "list_models",
    "select_engine",
]
