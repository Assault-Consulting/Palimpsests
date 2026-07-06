"""Tests for the llama-server subprocess lifecycle.

No real llama-server: Popen and the health poll are mocked, so we
exercise the state machine (build args, wait for readiness, detect early
death, shut down) without a binary or a GPU.
"""
from __future__ import annotations

import pytest
import subprocess
from palimpsests.providers.errors import EngineUnavailable
from palimpsests.providers.process import LlamaServerProcess, find_free_port

# ─── find_free_port ───────────────────────────────────────────────────────


def test_find_free_port_returns_usable_port():
    port = find_free_port()
    assert isinstance(port, int)
    assert 1024 <= port <= 65535


# ─── build_argv (pure) ────────────────────────────────────────────────────


def test_build_argv_has_core_flags(tmp_path):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"gguf")
    proc = LlamaServerProcess(
        binary="llama-server", model_path=str(model), port=9999
    )
    argv = proc.build_argv()
    assert argv[0] == "llama-server"
    assert "--model" in argv and str(model) in argv
    assert "--port" in argv and "9999" in argv
    assert "--host" in argv


def test_build_argv_includes_extra_args(tmp_path):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"gguf")
    proc = LlamaServerProcess(
        binary="llama-server",
        model_path=str(model),
        port=9999,
        extra_args=["--flash-attn", "-ngl", "20"],
    )
    argv = proc.build_argv()
    assert "--flash-attn" in argv
    assert "-ngl" in argv and "20" in argv


# ─── start: missing model / binary ────────────────────────────────────────


def test_start_missing_model_raises(tmp_path):
    proc = LlamaServerProcess(
        binary="llama-server", model_path=str(tmp_path / "absent.gguf")
    )
    with pytest.raises(EngineUnavailable, match="model file not found"):
        proc.start()


def test_start_missing_binary_raises(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"gguf")

    def boom(*a, **k):
        raise FileNotFoundError("no binary")

    monkeypatch.setattr(subprocess, "Popen", boom)
    proc = LlamaServerProcess(binary="nope-server", model_path=str(model))
    with pytest.raises(EngineUnavailable, match="binary not found"):
        proc.start()


# ─── start: readiness + early death (mocked Popen and health) ─────────────


class _FakePopen:
    """A stand-in for subprocess.Popen with a controllable exit state."""

    def __init__(self, *args, exits_with=None, **kwargs):
        self._exit = exits_with
        self.returncode = exits_with
        self.terminated = False
        self.killed = False

    def poll(self):
        return self._exit

    def terminate(self):
        self.terminated = True
        self._exit = 0
        self.returncode = 0

    def kill(self):
        self.killed = True
        self._exit = -9
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def test_start_succeeds_when_health_ok(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"gguf")
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: _FakePopen(exits_with=None)
    )

    # health returns 200 immediately
    class _Resp:
        status_code = 200

    import palimpsests.providers.process as procmod

    monkeypatch.setattr(procmod.httpx, "get", lambda *a, **k: _Resp())

    proc = LlamaServerProcess(binary="llama-server", model_path=str(model))
    proc.start()
    assert proc.is_running() is True
    proc.stop()
    assert proc.is_running() is False


def test_start_detects_early_death(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"gguf")
    # process is already dead (poll returns a code) on first check
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: _FakePopen(exits_with=1)
    )

    import palimpsests.providers.process as procmod

    # health never answers
    def _raise(*a, **k):
        raise procmod.httpx.ConnectError("down")

    monkeypatch.setattr(procmod.httpx, "get", _raise)

    proc = LlamaServerProcess(binary="llama-server", model_path=str(model))
    with pytest.raises(EngineUnavailable, match="exited during startup"):
        proc.start()


def test_start_times_out(tmp_path, monkeypatch):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"gguf")
    monkeypatch.setattr(
        subprocess, "Popen", lambda *a, **k: _FakePopen(exits_with=None)
    )

    import palimpsests.providers.process as procmod

    def _raise(*a, **k):
        raise procmod.httpx.ConnectError("down")

    monkeypatch.setattr(procmod.httpx, "get", _raise)
    # make the loop exit fast
    proc = LlamaServerProcess(
        binary="llama-server",
        model_path=str(model),
        readiness_timeout=0.5,
    )
    with pytest.raises(EngineUnavailable, match="not ready"):
        proc.start()


# ─── stop is idempotent ───────────────────────────────────────────────────


def test_stop_without_start_is_noop(tmp_path):
    model = tmp_path / "model.gguf"
    model.write_bytes(b"gguf")
    proc = LlamaServerProcess(binary="llama-server", model_path=str(model))
    proc.stop()  # should not raise
    assert proc.is_running() is False
