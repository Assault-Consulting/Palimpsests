"""Tests for the pal-native level-3 slot.

The slot is a placeholder: it must be *registerable* and satisfy the
engine contract, but every operation must refuse loudly rather than
return a fake answer. These tests pin exactly that — the honesty of the
placeholder — so a future real implementation can't silently regress
into a stateless shim without a test noticing.
"""
from __future__ import annotations

import pytest
from palimpsests.engine import CapabilityUnsupported, InferenceEngine
from palimpsests.providers import NativeEngine


@pytest.fixture
def engine():
    eng = NativeEngine()
    yield eng
    eng.close()


# ─── contract ─────────────────────────────────────────────────────────────


def test_satisfies_engine_protocol(engine: NativeEngine):
    """Must be a structural InferenceEngine so it can live in the
    registry and AppContext alongside the other adapters."""
    assert isinstance(engine, InferenceEngine)


def test_engine_id(engine: NativeEngine):
    assert engine.engine_id == "pal-native"


# ─── capabilities: level 3, nothing implemented ───────────────────────────


def test_capabilities_are_level_3(engine: NativeEngine):
    assert engine.capabilities.control_level == 3


def test_all_level_3_features_are_off(engine: NativeEngine):
    """The whole point of the placeholder: control_level says 3, but no
    feature flag is set, so the orchestrator never routes real work here.
    Each flag flips to True in the PR that ships that feature."""
    c = engine.capabilities
    assert c.streaming is False
    assert c.stateful_sessions is False
    assert c.shared_prefix is False
    assert c.server_side_tools is False
    assert c.continuous_batching is False
    assert c.kv_persistence is False


# ─── availability: known but not installed ────────────────────────────────


def test_is_not_available(engine: NativeEngine):
    """No serving service exists yet, so the registry sees it as
    not-installed."""
    assert engine.is_available() is False


# ─── every operation refuses loudly ───────────────────────────────────────


def test_list_models_refuses(engine: NativeEngine):
    with pytest.raises(CapabilityUnsupported, match="not implemented yet"):
        engine.list_models()


def test_chat_stream_refuses(engine: NativeEngine):
    with pytest.raises(CapabilityUnsupported, match="not implemented yet"):
        list(engine.chat_stream(model="m", messages=[]))


def test_chat_refuses(engine: NativeEngine):
    """chat is derived from chat_stream, so it refuses along with it —
    no accidental stateless answer."""
    with pytest.raises(CapabilityUnsupported):
        engine.chat(model="m", messages=[])


def test_open_session_refuses(engine: NativeEngine):
    """Inherited from the base: while stateful_sessions is False, opening
    a session is a loud refusal, not a fake stateless shim."""
    with pytest.raises(CapabilityUnsupported):
        engine.open_session(model="m")
