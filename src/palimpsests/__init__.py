"""Palimpsests — a layered local-LLM inference engine.

Three levels of control over local inference behind a single abstraction:

- Level 1 (``ollama``)    — thin HTTP client to an external daemon.
- Level 2 (``llamacpp``)  — embedded engine via subprocess.
- Level 3 (``pal-native``) — own serving service with KV-state management.

Plus a context-memory layer that works the same on all three levels.

See ARCHITECTURE.md for the full design. Public API stabilizes at v1.0;
until then imports may move.
"""
from __future__ import annotations

__version__ = "0.0.0"

__all__ = ["__version__"]
