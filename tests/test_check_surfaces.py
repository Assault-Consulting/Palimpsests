# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The surface checker and the MCP proxy, launching clients and judging results.

Measured on Windows before a release: an npm-installed client is a ``.cmd``
shim, which ``shutil.which`` finds and ``subprocess`` cannot start by bare
name. The checker then crashed and reported the surface RED — a defect in
the checker presented as a change in the surface. These tests hold the
launch path (a shim on the Windows CI leg) and the line between RED, SKIP
and ERROR.
"""
from __future__ import annotations

import importlib.util
import io
import os
import pytest
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def cs():
    return _load("check_surfaces_under_test", REPO / "scripts" / "check_surfaces.py")


@pytest.fixture
def mcp_proxy():
    return _load("mcp_proxy_under_test", REPO / "integrations" / "mcp" / "palimpsests_audit_mcp.py")


@pytest.fixture
def shim(tmp_path, monkeypatch):
    """A client named ``fakeclient`` on a PATH of its own — a ``.cmd`` shim on
    Windows, as npm installs clients there; an executable script elsewhere."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if os.name == "nt":
        (bindir / "fakeclient.cmd").write_text("@echo off\r\necho fake 1.0\r\nexit /b 0\r\n")
    else:
        f = bindir / "fakeclient"
        f.write_text("#!/bin/sh\necho fake 1.0\nexit 0\n")
        f.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    return bindir


# ── launching ──────────────────────────────────────────────────────────────


def test_a_client_is_found_and_launched_by_its_full_path(cs, shim, tmp_path):
    exe = cs._resolve("fakeclient")
    assert exe is not None and Path(exe).parent == shim
    assert cs._version([exe, "--version"]) == "fake 1.0"
    assert cs._run_tree([exe], cwd=tmp_path, env=dict(os.environ), timeout=30) is True


@pytest.mark.skipif(os.name != "nt", reason="the .cmd launch rule is Windows'")
def test_on_windows_a_shim_does_not_start_by_bare_name(shim):
    """The defect itself, measured: found by name, not startable by name."""
    with pytest.raises(FileNotFoundError):
        subprocess.run(["fakeclient", "--version"], capture_output=True)


def test_a_client_that_cannot_be_started_is_a_launch_failure(cs, tmp_path):
    with pytest.raises(cs.LaunchFailed, match="could not launch"):
        cs._run_tree([str(tmp_path / "no-such-client")], cwd=tmp_path,
                     env=dict(os.environ), timeout=5)


# ── RED, SKIP and ERROR ────────────────────────────────────────────────────


def _probes(cs, monkeypatch, **probes):
    monkeypatch.setattr(cs, "PROBES", probes)


def test_a_launch_failure_is_skip(cs, monkeypatch, tmp_path):
    def probe(workdir):
        cs._run_tree([str(tmp_path / "gone")], cwd=workdir, env=dict(os.environ), timeout=5)

    _probes(cs, monkeypatch, x=probe)
    r = cs.run_probe("x")
    assert r.state == "SKIP" and "could not launch" in r.detail


def test_a_checker_failure_is_error_not_red(cs, monkeypatch):
    def probe(workdir):
        raise RuntimeError("the probe broke")

    _probes(cs, monkeypatch, x=probe)
    r = cs.run_probe("x")
    assert r.state == "ERROR"
    assert "the surface is unchecked" in r.detail and "the probe broke" in r.detail


def test_error_and_red_fail_the_run_skip_does_not(cs, monkeypatch, tmp_path):
    monkeypatch.setattr(cs, "_preflight", lambda: None)
    _probes(cs, monkeypatch, s=lambda w: cs.Result("s", "SKIP", detail="absent"))
    assert cs.main(["x", "s", "--report", str(tmp_path)]) == 0
    _probes(cs, monkeypatch, e=lambda w: (_ for _ in ()).throw(RuntimeError("x")))
    assert cs.main(["x", "e", "--report", str(tmp_path)]) == 1
    _probes(cs, monkeypatch, r=lambda w: cs.Result("r", "RED", detail="0 call(s)"))
    assert cs.main(["x", "r", "--report", str(tmp_path)]) == 1


def test_a_python_without_the_serve_extra_skips_every_probe(cs, monkeypatch, tmp_path):
    real = importlib.util.find_spec
    monkeypatch.setattr(importlib.util, "find_spec",
                        lambda name, *a: None if name == "uvicorn" else real(name, *a))
    called = []
    _probes(cs, monkeypatch, a=lambda w: called.append(1), b=lambda w: called.append(1))
    assert cs.main(["x", "--report", str(tmp_path)]) == 0
    report = next(tmp_path.glob("surfaces-*.md")).read_text(encoding="utf-8")
    assert called == []  # no probe ran without what every probe needs
    assert report.count("⚪ SKIP") == 2 and "[serve] extra" in report


# ── the report survives the console ────────────────────────────────────────


class _NarrowConsole(io.StringIO):
    """A console that cannot print the status marks and cannot be reconfigured."""

    def write(self, s):
        if any(ord(ch) > 127 for ch in s):
            raise UnicodeEncodeError("charmap", s, 0, 1, "character maps to <undefined>")
        return super().write(s)


def test_the_report_is_written_before_anything_is_printed(cs, monkeypatch, tmp_path):
    monkeypatch.setattr(cs, "_preflight", lambda: None)
    _probes(cs, monkeypatch, e=lambda w: (_ for _ in ()).throw(RuntimeError("x")))
    console = _NarrowConsole()
    monkeypatch.setattr(sys, "stdout", console)
    assert cs.main(["x", "--report", str(tmp_path)]) == 1  # finished, did not raise
    report = next(tmp_path.glob("surfaces-*.md")).read_text(encoding="utf-8")
    assert "🟠 ERROR" in report  # the file keeps the marks
    assert "ERROR" in console.getvalue()  # the console gets a readable fallback


# ── the MCP proxy starts its server the same way ───────────────────────────


def test_the_proxy_resolves_its_server_like_a_shell(mcp_proxy, shim):
    resolved = mcp_proxy.resolve_command(["fakeclient", "--flag"])
    assert resolved is not None and Path(resolved[0]).parent == shim
    assert resolved[1:] == ["--flag"]


def test_a_server_given_as_a_path_is_kept(mcp_proxy, tmp_path):
    path = str(tmp_path / "server")
    assert mcp_proxy.resolve_command([path, "a"]) == [path, "a"]


def test_a_missing_server_is_one_sentence_and_127(mcp_proxy, monkeypatch, capsys):
    monkeypatch.setenv("PATH", "")
    assert mcp_proxy.Proxy(["no-such-mcp-server"]).run() == 127
    assert "'no-such-mcp-server' is not on PATH" in capsys.readouterr().err
