"""Tests for the pal-native engine's registration-facing behavior.

The detailed engine behavior (streaming, the scheduler path, backend
loading) lives in test_native_engine.py; the scheduler in
test_native_scheduler.py; sessions in test_native_session.py. This module
pins the small surface the rest of the app relies on: that a zero-arg
NativeEngine is a valid InferenceEngine that can be constructed and
registered, and that without a backend or model it degrades cleanly
(not-available, loud EngineUnavailable) rather than crashing or pretending
to work.
"""
from __future__ import annotations

import pytest
from palimpsests.engine import InferenceEngine
from palimpsests.providers import NativeEngine
from palimpsests.providers.errors import EngineUnavailable


def test_zero_arg_construction_is_valid_engine():
    """core.init_app builds this with no arguments; it must still be a
    structural InferenceEngine so it can live in the registry."""
    eng = NativeEngine()
    assert isinstance(eng, InferenceEngine)
    assert eng.engine_id == "pal-native"


def test_control_level_is_3():
    assert NativeEngine().capabilities.control_level == 3


def test_streaming_capability_is_on():
    """N1 shipped the stateless streaming path, so unlike the old
    placeholder this flag is now True."""
    assert NativeEngine().capabilities.streaming is True


def test_all_level3_capabilities_on():
    """The full level-3 skeleton has shipped: sessions (N3a), batching
    (N3b), tool loop (N5), shared prefix (N4), and KV persistence (N6) are
    all True."""
    c = NativeEngine().capabilities
    assert c.stateful_sessions is True
    assert c.continuous_batching is True
    assert c.server_side_tools is True
    assert c.shared_prefix is True
    assert c.kv_persistence is True


def test_not_available_without_backend_or_model():
    """No injected backend, no model, no [native] extra in CI → the
    registry sees it as not-installed."""
    assert NativeEngine().is_available() is False


def test_chat_without_backend_raises_unavailable():
    """A stateless call with nothing configured is a clear
    EngineUnavailable, not a crash or a fake answer."""
    eng = NativeEngine()
    with pytest.raises(EngineUnavailable):
        eng.chat(model="m", messages=[{"role": "user", "content": "hi"}])
