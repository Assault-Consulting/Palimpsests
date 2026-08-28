# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""WS-E hardening of serve: bearer auth and the OpenCode config printer."""
from __future__ import annotations

import json
import pytest
from fastapi.testclient import TestClient
from palimpsests.server import openai_api
from palimpsests.server.openai_api import _opencode_config, create_app


def _app(key):
    return create_app(
        chat_fn=lambda req: {"role": "assistant", "content": "ok"},
        models_fn=lambda: ["m1"],
        api_key=key,
    )


def test_requests_without_the_key_get_openai_shaped_401():
    client = TestClient(_app("s3cret"))
    r = client.get("/v1/models")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_api_key"
    r = client.get("/v1/models", headers={"Authorization": "Bearer wrong"})
    assert r.status_code == 401


def test_the_right_key_passes_and_no_key_config_stays_open():
    client = TestClient(_app("s3cret"))
    r = client.get("/v1/models", headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 200 and r.json()["data"][0]["id"] == "m1"
    open_client = TestClient(_app(None))
    assert open_client.get("/v1/models").status_code == 200


def test_empty_api_key_is_refused_at_construction():
    with pytest.raises(ValueError, match="non-empty"):
        _app("")


def test_opencode_config_is_hardwired_and_carries_the_key():
    doc = json.loads(_opencode_config("127.0.0.1", 11435, "k1"))
    prov = doc["provider"]["palimpsests"]
    assert prov["npm"] == "@ai-sdk/openai-compatible"
    assert prov["options"]["baseURL"] == "http://127.0.0.1:11435/v1"
    assert prov["options"]["apiKey"] == "k1"
    assert prov["models"]  # engine unreachable here -> MODEL_ID placeholder
    doc2 = json.loads(_opencode_config("0.0.0.0", 9000, None))
    assert "apiKey" not in doc2["provider"]["palimpsests"]["options"]


def test_print_flag_prints_and_exits_without_serving(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv", ["palimpsests-serve", "--print-opencode-config", "--api-key", "k2"]
    )
    openai_api.main()  # returns instead of blocking in uvicorn
    out = capsys.readouterr()
    doc = json.loads(out.out)
    assert doc["provider"]["palimpsests"]["options"]["apiKey"] == "k2"
    assert "auth.json" in out.err
