# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Both ways of starting the serve take the key — and the fixes of 0.13.1.

In 0.13.0 ``palimpsests serve`` had no ``--api-key`` and ignored
``PALIMPSESTS_SERVE_API_KEY``: started as the documentation described, the
endpoint ran without authentication (real-traffic run R1, 0.14). Both entry
points now start through one function, and these tests hold that.
"""
from __future__ import annotations

import json
import logging
import pytest
import sys

fastapi = pytest.importorskip("fastapi")
pytest.importorskip("uvicorn")
from fastapi.testclient import TestClient  # noqa: E402


@pytest.fixture
def captured(monkeypatch, tmp_path):
    """Start a serve as the CLI would, with uvicorn replaced: the app it
    would have served is captured instead."""
    import uvicorn

    monkeypatch.setenv("PALIMPSESTS_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT", "1")
    monkeypatch.delenv("PALIMPSESTS_SERVE_API_KEY", raising=False)
    seen: dict = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(app=app, **kw))
    return seen


def _cli(args, env=None):
    from palimpsests.cli import app
    from typer.testing import CliRunner

    result = CliRunner().invoke(app, ["serve", *args], env=env or {})
    assert result.exit_code == 0, result.output
    return result


def _status(app, bearer=None):
    hdr = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    # an ingestion call needs no engine, so its status is about auth alone
    return TestClient(app).post("/v1/pala/events", json={"events": []}, headers=hdr).status_code


def test_the_subcommand_takes_the_key_from_the_environment(captured):
    _cli([], env={"PALIMPSESTS_SERVE_API_KEY": "k-env"})
    assert _status(captured["app"]) == 401
    assert _status(captured["app"], "k-env") == 400  # past auth; the body is empty


def test_the_subcommand_takes_the_key_as_an_option(captured):
    _cli(["--api-key", "k-opt"])
    assert _status(captured["app"]) == 401
    assert _status(captured["app"], "k-opt") == 400


def test_without_a_key_the_endpoint_is_open_and_says_so(captured):
    result = _cli([])
    assert _status(captured["app"]) == 400  # no auth configured
    assert "no key" in result.output


def test_both_entry_points_start_through_one_function(monkeypatch):
    import palimpsests.server.openai_api as api

    calls = []
    monkeypatch.setattr(api, "run_serve", lambda *a: calls.append(a))
    _cli(["--port", "12000", "--api-key", "k"])
    monkeypatch.setattr(sys, "argv", ["palimpsests-serve", "--port", "12000", "--api-key", "k"])
    api.main()
    assert calls == [("127.0.0.1", 12000, "k"), ("127.0.0.1", 12000, "k")]


def test_a_keyless_serve_off_localhost_is_warned_about(captured, capsys):
    from palimpsests.server.openai_api import run_serve

    run_serve("0.0.0.0", 12001, None)
    assert "without a key" in capsys.readouterr().err
    run_serve("127.0.0.1", 12002, None)
    assert "without a key" not in capsys.readouterr().err


def test_a_refused_hook_names_its_event_and_tool(tmp_path, caplog):
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.providers.native.audit import NativeAudit
    from palimpsests.server.openai_api import create_app

    audit = NativeAudit(PalaWriter(tmp_path / "h.pala"))
    client = TestClient(create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [],
                                   audit=audit, api_key="k"))
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_use_id": "toolu_9",
             "tool_input": {"command": "secret-arg"}}
    with caplog.at_level(logging.WARNING, logger="palimpsests.serve"):
        r = client.post("/v1/pala/hooks/claude", content=json.dumps(event),
                        headers={"Authorization": "Bearer ", "Content-Type": "application/json"})
    audit.writer.close()
    assert r.status_code == 401
    assert "event PreToolUse, tool Bash, id toolu_9" in caplog.text
    assert "secret-arg" not in caplog.text  # metadata only, never the input


def test_an_inverted_range_is_refused_by_the_verifier():
    """Bridge run B3, F4: the builder refused it; the verifier did not."""
    pytest.importorskip("cbor2")
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from palimpsests.audit.pala import scitt

    key = ed25519.Ed25519PrivateKey.generate()
    head = b"\x07" * 32
    import cbor2

    payload = cbor2.dumps({1: head, 2: 11, 3: 8, 4: scitt.FORMAT_ID, 5: b"\x00" * 32})
    stmt = scitt._cose_sign1(payload, key, alg=scitt.ALG_EDDSA,
                             content_type=scitt.CONTENT_TYPE_V3)
    with pytest.raises(ValueError, match="0 <= first_seq <= last_seq"):
        scitt.verify_statement(stmt, key.public_key(), head)
