"""Orchestration — wires registry, audit, context, and engines together.

This is the layer the CLI (and any downstream embedder) calls. It owns
the decisions the individual pieces deliberately don't:

- **where the engine registration and ``@audited`` wrapping happen** —
  here, not in the adapter. ``OllamaEngine`` stays a clean HTTP client
  with no knowledge of our registry or audit log; this module is what
  knows about global state. A downstream product can embed the adapter
  directly and skip all of this.
- **how the context-memory layer enters the chat flow** — ``chat`` fits
  the message list (sink/window/evict), *stores what was evicted* in
  BlockMemory, and *retrieves relevant evicted blocks back* before
  handing off to the engine. Both halves of the palimpsest — scrape and
  bleed-through — happen here, automatically, so no caller wires them.

App state (config dir, registry, audit log, block memory) is
initialized once via ``init_app``. Tests build their own ``AppContext``
with tmp paths instead.
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
from palimpsests.context import (
    BlockMemory,
    ContextWindowManager,
    engine_embedder,
)
from palimpsests.engine import ChatChunk, InferenceEngine, Message, ModelInfo
from palimpsests.providers import LlamaCppEngine, NativeEngine, OllamaEngine
from palimpsests.registry import DEFAULT_ENGINE_ID, EngineRegistry, set_registry
from pathlib import Path

APP_NAME = "palimpsests"

# How many evicted blocks to pull back into context on a retrieval.
_RETRIEVAL_TOP_K = 3


def default_config_dir() -> Path:
    """Return the per-user config directory, honoring XDG on Linux."""
    override = os.environ.get("PALIMPSESTS_CONFIG_DIR")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / APP_NAME


# ─── engine construction ─────────────────────────────────────────────────

# Known engine adapters and how to build one. Ollama (L1) and pal-native
# (L3) construct with no arguments, so they live in the factory table.
# llama.cpp (L2) needs a model path, so it registers separately below via
# _maybe_llamacpp_engine. Keeping the zero-arg ones in a table (not a
# chain of ifs) means adding such an engine is a one-line change.
#
# pal-native registers here so the architecture is visible in `engine
# list`. A zero-arg NativeEngine has no backend configured, so its
# is_available() is False in a plain environment (the [native] extra and
# a model are needed) — it shows as known-but-not-installed until the
# native backend is present, at which point its streaming path activates.
_ENGINE_FACTORIES = {
    "ollama": OllamaEngine,
    "pal-native": NativeEngine,
}


@dataclass
class AppContext:
    """The initialized application state.

    Holds the registry, the constructed engines, and (when available)
    block memory. Built by ``init_app`` for real use, or directly by
    tests with tmp paths.
    """

    config_dir: Path
    registry: EngineRegistry
    engines: dict[str, InferenceEngine]
    block_memory: BlockMemory | None = None

    def active_engine(self) -> InferenceEngine:
        """Return the currently active engine instance.

        Raises KeyError if the active engine id has no constructed
        instance — which only happens if the config names an engine we
        don't know how to build.
        """
        engine_id = self.registry.active_engine_id
        return self.engines[engine_id]


def init_app(config_dir: Path | None = None) -> AppContext:
    """Initialize app state: config dir, registry, audit log, engines,
    and block memory.

    Idempotent enough for a CLI invocation: safe to call once per run.
    Registers every known engine and probes availability so the
    registry's installed-state reflects reality this run.

    Block memory is best-effort: it needs an engine that can embed and
    numpy (the ``embeddings`` extra). If either is missing, ``chat``
    still works — just without retrieval of evicted context.
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

    engines: dict[str, InferenceEngine] = {}
    for engine_id, factory in _ENGINE_FACTORIES.items():
        engine = factory()
        engines[engine_id] = engine
        installed = engine.is_available()
        registry.register(
            engine_id,
            control_level=engine.capabilities.control_level,
            installed=installed,
        )

    # Level 2 (llama.cpp) is opt-in: it needs a model file to spawn a
    # server against, so it registers only when PALIMPSESTS_LLAMACPP_MODEL
    # points at one. Unlike Ollama (a zero-arg daemon client), an L2
    # engine without a model has nothing to do, so we don't register a
    # dead one. PALIMPSESTS_LLAMACPP_BIN overrides the llama-server path.
    llama_engine = _maybe_llamacpp_engine()
    if llama_engine is not None:
        engines["llamacpp"] = llama_engine
        registry.register(
            "llamacpp",
            control_level=llama_engine.capabilities.control_level,
            installed=llama_engine.is_available(),
        )

    ctx = AppContext(config_dir=cfg, registry=registry, engines=engines)
    ctx.block_memory = _build_block_memory(cfg, ctx)
    return ctx


def _build_block_memory(
    config_dir: Path, ctx: AppContext
) -> BlockMemory | None:
    """Construct block memory if the active engine can embed.

    Routes embeddings through the active engine (Ollama's
    ``/api/embeddings``). If the engine has no ``embed`` method, or
    construction fails for any reason, returns None — retrieval is an
    enhancement, never a hard requirement of chat.
    """
    try:
        engine = ctx.active_engine()
    except KeyError:
        return None
    if not hasattr(engine, "embed"):
        return None
    try:
        embedder = engine_embedder(engine)
        return BlockMemory(workspace=config_dir, embedder=embedder)
    except Exception:
        # Never let a memory-layer failure break basic chat.
        return None


def _maybe_llamacpp_engine() -> LlamaCppEngine | None:
    """Build a level-2 engine if the environment points at a model.

    Reads ``PALIMPSESTS_LLAMACPP_MODEL`` (a .gguf path) and optionally
    ``PALIMPSESTS_LLAMACPP_BIN`` (the llama-server binary, default on
    PATH). Returns None when no model is configured — L2 is opt-in.
    Construction is side-effect-free (the server spawns lazily on first
    use), so this never launches anything.
    """
    model = os.environ.get("PALIMPSESTS_LLAMACPP_MODEL")
    if not model:
        return None
    binary = os.environ.get("PALIMPSESTS_LLAMACPP_BIN", "llama-server")
    try:
        return LlamaCppEngine(model_path=model, binary=binary)
    except Exception:
        return None


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


def _last_user_text(messages: Sequence[Message]) -> str | None:
    """The most recent user message's content — the retrieval query."""
    for msg in reversed(messages):
        if msg.get("role") == "user" and msg.get("content"):
            return msg["content"]
    return None


def _recall_block(ctx: AppContext, query: str) -> Message | None:
    """Retrieve relevant evicted blocks and fold them into one system
    message, or None if there's nothing useful to recall.

    Kept as a single system message so that next turn it lands in the
    sink (stable prefix, prefix-cache friendly), and so its role marks
    it clearly as recalled context rather than part of the live
    exchange.
    """
    if ctx.block_memory is None:
        return None
    try:
        hits = ctx.block_memory.retrieve(query, top_k=_RETRIEVAL_TOP_K)
    except Exception:
        return None  # retrieval is best-effort; never break the call
    if not hits:
        return None
    recalled = "\n\n".join(h.message.get("content", "") for h in hits)
    return {
        "role": "system",
        "content": (
            "Relevant earlier context, recalled from this conversation:\n\n"
            f"{recalled}"
        ),
    }


@audited("model.call", model_locality="local")
def chat(
    ctx: AppContext,
    *,
    model: str,
    messages: Sequence[Message],
    context_size: int = 8192,
) -> Iterator[ChatChunk]:
    """Stream a chat response through the active engine.

    The full context-memory flow lives here, in orchestration, so no
    caller wires it:

    1. Fit the messages to the budget (sink/window/evict).
    2. If anything was evicted, store it in block memory *and* retrieve
       the blocks most relevant to the latest user turn, folded into a
       single system message prepended to the context. Retrieval is
       lazy — skipped entirely when nothing was evicted, so a short
       conversation makes no extra embedding calls.
    3. Stream from the active engine.

    Block memory is optional: without it (no embed-capable engine or no
    numpy), steps 2's store/retrieve are simply skipped and chat behaves
    as a plain fitted call.
    """
    manager = ContextWindowManager(context_size=context_size)
    fitted = manager.fit(messages)
    outgoing = list(fitted.messages)

    # Only touch block memory when the window manager actually evicted
    # something — otherwise there's nothing new to remember and no reason
    # to spend embedding calls on retrieval.
    if fitted.evicted and ctx.block_memory is not None:
        try:
            ctx.block_memory.add(fitted.evicted)
        except Exception:
            pass  # storing is best-effort; a failure must not break chat
        query = _last_user_text(messages)
        if query:
            recall = _recall_block(ctx, query)
            if recall is not None:
                outgoing = [recall, *outgoing]

    return ctx.active_engine().chat_stream(model=model, messages=outgoing)


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
