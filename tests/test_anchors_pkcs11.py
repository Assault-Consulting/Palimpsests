# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Tier-B anchor against a hermetic SoftHSM2 token (ADR-0004).

The fixture initializes a fresh token in a private token directory, so
the tests neither read nor pollute any system SoftHSM state. Where
python-pkcs11 or a SoftHSM module is absent, everything here skips —
the mechanism is optional plumbing behind the [pkcs11] extra, and a
bare checkout stays green.
"""
from __future__ import annotations

import os
import pytest
import shutil
import subprocess
from palimpsests.audit.anchors import (
    AnchorSourceError,
    ChainedAnchorSource,
    ManualAnchor,
)

pkcs11 = pytest.importorskip("pkcs11", reason="[pkcs11] extra not installed")
from palimpsests.audit.anchors_pkcs11 import (  # noqa: E402
    Pkcs11Anchor,
    Pkcs11AnchorStore,
)

_MODULE_CANDIDATES = (
    "/usr/lib/softhsm/libsofthsm2.so",
    "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
    "/usr/local/lib/softhsm/libsofthsm2.so",
    "/opt/homebrew/lib/softhsm/libsofthsm2.so",
)
_PIN = "1234"
_TOKEN = "pala-ci"


def _module_path() -> str | None:
    for candidate in _MODULE_CANDIDATES:
        if os.path.exists(candidate):
            return candidate
    return None


@pytest.fixture(scope="session")
def softhsm(tmp_path_factory):
    """A fresh SoftHSM token in a private directory, or a clean skip."""
    module = _module_path()
    util = shutil.which("softhsm2-util")
    if module is None or util is None:
        pytest.skip("SoftHSM2 not installed")
    home = tmp_path_factory.mktemp("softhsm")
    (home / "tokens").mkdir()
    conf = home / "softhsm2.conf"
    conf.write_text(
        f"directories.tokendir = {home / 'tokens'}\nobjectstore.backend = file\n"
    )
    os.environ["SOFTHSM2_CONF"] = str(conf)
    subprocess.run(
        [
            util,
            "--init-token",
            "--free",
            "--label",
            _TOKEN,
            "--pin",
            _PIN,
            "--so-pin",
            "654321",
        ],
        check=True,
        capture_output=True,
    )
    return module


@pytest.fixture()
def source(softhsm):
    return Pkcs11Anchor(softhsm, _TOKEN, user_pin=_PIN)


@pytest.fixture()
def store(softhsm):
    return Pkcs11AnchorStore(softhsm, _TOKEN, user_pin=_PIN)


def test_round_trip_and_overwrite(source, store):
    head_a, head_b = b"\x01" * 32, b"\x02" * 32
    store.store_head(head_a)
    reading = source.current_head()
    assert reading is not None and reading.head == head_a
    assert reading.source_kind == "pkcs11"
    assert reading.source_detail == f"{_TOKEN}/pala-anchor-head"
    assert reading.observed_at_ns is not None

    store.store_head(head_b)  # destroy-then-create; exactly one object remains
    reading = source.current_head()
    assert reading is not None and reading.head == head_b


def test_absent_label_is_none_not_an_error(softhsm):
    src = Pkcs11Anchor(softhsm, _TOKEN, user_pin=_PIN, object_label="never-written")
    assert src.current_head() is None


def test_wrong_pin_raises_with_source_identity(softhsm):
    src = Pkcs11Anchor(softhsm, _TOKEN, user_pin="0000")
    with pytest.raises(AnchorSourceError) as exc:
        src.current_head()
    assert exc.value.source_kind == "pkcs11"


def test_missing_module_raises_not_none(tmp_path):
    src = Pkcs11Anchor(str(tmp_path / "no-such-module.so"), _TOKEN, user_pin=_PIN)
    with pytest.raises(AnchorSourceError, match="failed to load"):
        src.current_head()


def test_short_head_is_refused_at_the_boundary(store):
    with pytest.raises(ValueError, match="32 bytes"):
        store.store_head(b"short")


def test_wrong_length_on_token_is_unreadable_not_absent(softhsm, source, store):
    """A foreign 16-byte object under our label must raise, never pass."""
    from pkcs11 import Attribute, ObjectClass

    lib = pkcs11.lib(softhsm)
    token = lib.get_token(token_label=_TOKEN)
    store.store_head(b"\x03" * 32)
    with token.open(rw=True, user_pin=_PIN) as session:
        for obj in session.get_objects(
            {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: "pala-anchor-head"}
        ):
            obj.destroy()
        session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: "pala-anchor-head",
                Attribute.VALUE: b"\xee" * 16,
                Attribute.TOKEN: True,
            }
        )
    with pytest.raises(AnchorSourceError, match="present but unreadable"):
        source.current_head()


def test_chained_resolution_names_the_pkcs11_link(softhsm):
    absent = Pkcs11Anchor(softhsm, _TOKEN, user_pin=_PIN, object_label="empty-slot")
    manual = ManualAnchor("ab" * 32, detail="cli")
    chain = ChainedAnchorSource([absent, manual])
    reading = chain.current_head()
    assert reading is not None and reading.head == bytes.fromhex("ab" * 32)
    kinds = [(a.source_kind, a.outcome) for a in chain.last_attempts]
    assert ("pkcs11", "absent") in kinds
    assert ("manual", "answered") in kinds
