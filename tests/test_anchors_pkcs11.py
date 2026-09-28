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


def test_unknown_token_label_raises_not_none(softhsm):
    src = Pkcs11Anchor(softhsm, "no-such-token", user_pin=_PIN)
    with pytest.raises(AnchorSourceError, match="not found"):
        src.current_head()


def test_multiple_objects_under_the_label_are_ambiguous(softhsm, source):
    """Two objects under our label must raise, never pick one silently."""
    from pkcs11 import Attribute, ObjectClass

    lib = pkcs11.lib(softhsm)
    token = lib.get_token(token_label=_TOKEN)
    with token.open(rw=True, user_pin=_PIN) as session:
        for obj in session.get_objects(
            {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: "pala-anchor-head"}
        ):
            obj.destroy()
        for value in (b"\x04" * 32, b"\x05" * 32):
            session.create_object(
                {
                    Attribute.CLASS: ObjectClass.DATA,
                    Attribute.LABEL: "pala-anchor-head",
                    Attribute.VALUE: value,
                    Attribute.TOKEN: True,
                }
            )
    with pytest.raises(AnchorSourceError, match="unambiguous"):
        source.current_head()


# ── Tier-B needs an authenticated session (Auditor integration finding) ──
#
# Each attack test uses its own object label, so the one session token is
# never polluted for the tests after it. (SoftHSM scans its token directory
# once per process; creating a token per test would silently not work.)


def _plant_public_decoy(module: str, label: str, value: bytes) -> None:
    """What any host process can do with no PIN: an R/W *public* session."""
    from pkcs11 import Attribute, ObjectClass

    token = pkcs11.lib(module).get_token(token_label=_TOKEN)
    with token.open(rw=True) as session:  # no PIN
        session.create_object(
            {
                Attribute.CLASS: ObjectClass.DATA,
                Attribute.LABEL: label,
                Attribute.VALUE: value,
                Attribute.TOKEN: True,
                Attribute.PRIVATE: False,
            }
        )


def test_a_reader_without_a_pin_refuses_rather_than_answering(softhsm):
    """Without a PIN a private anchor is invisible and a planted public one
    is not — so an unauthenticated read could only ever answer 'absent' or
    an attacker's head. It must answer neither."""
    label = "f1-no-pin"
    Pkcs11AnchorStore(softhsm, _TOKEN, user_pin=_PIN, object_label=label).store_head(
        b"\xaa" * 32
    )
    _plant_public_decoy(softhsm, label, b"\xee" * 32)
    with pytest.raises(AnchorSourceError, match="no PIN"):
        Pkcs11Anchor(softhsm, _TOKEN, object_label=label).current_head()


def test_the_stored_anchor_is_a_private_object(softhsm):
    """Private explicitly, not by whatever the token's default happens to be:
    a public object is rewritable by any host process without a PIN."""
    from pkcs11 import Attribute, ObjectClass

    label = "f1-private"
    Pkcs11AnchorStore(softhsm, _TOKEN, user_pin=_PIN, object_label=label).store_head(
        b"\xab" * 32
    )
    token = pkcs11.lib(softhsm).get_token(token_label=_TOKEN)
    with token.open(user_pin=_PIN) as session:
        (obj,) = session.get_objects(
            {Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label}
        )
        assert obj[Attribute.PRIVATE] is True


def test_a_planted_decoy_is_a_tamper_signal_to_the_pin_reader(softhsm):
    """With a PIN both objects are visible, and ambiguity must raise: that
    error is the operator's evidence of the attempt. Filtering the query to
    private objects would answer correctly and erase that evidence."""
    label = "f1-decoy"
    Pkcs11AnchorStore(softhsm, _TOKEN, user_pin=_PIN, object_label=label).store_head(
        b"\xac" * 32
    )
    _plant_public_decoy(softhsm, label, b"\xee" * 32)
    with pytest.raises(AnchorSourceError, match="2 objects match"):
        Pkcs11Anchor(softhsm, _TOKEN, user_pin=_PIN, object_label=label).current_head()


def test_the_store_does_not_erase_a_planted_decoy(softhsm):
    """store_head used to destroy every object under its label before
    writing — including a decoy planted beside the genuine anchor, which is
    exactly the evidence the reader's ambiguity error exists to surface.
    With more than one object present it must refuse and leave them all."""
    from pkcs11 import Attribute, ObjectClass

    label = "f1-store-decoy"
    store = Pkcs11AnchorStore(softhsm, _TOKEN, user_pin=_PIN, object_label=label)
    store.store_head(b"\xad" * 32)
    _plant_public_decoy(softhsm, label, b"\xee" * 32)
    with pytest.raises(AnchorSourceError, match="2 objects"):
        store.store_head(b"\xae" * 32)
    token = pkcs11.lib(softhsm).get_token(token_label=_TOKEN)
    with token.open(user_pin=_PIN) as session:
        left = list(
            session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
        )
    assert len(left) == 2  # both the genuine anchor and the decoy survive


def test_no_pin_cannot_replace_the_private_anchor(softhsm):
    """Regression guard for the property tier B rests on: a host process
    without the PIN can neither see nor destroy the private anchor."""
    from pkcs11 import Attribute, ObjectClass

    label = "f1-guard"
    Pkcs11AnchorStore(softhsm, _TOKEN, user_pin=_PIN, object_label=label).store_head(
        b"\xaf" * 32
    )
    token = pkcs11.lib(softhsm).get_token(token_label=_TOKEN)
    with token.open(rw=True) as session:  # no PIN
        visible = list(
            session.get_objects({Attribute.CLASS: ObjectClass.DATA, Attribute.LABEL: label})
        )
        assert visible == []  # nothing to destroy
    reading = Pkcs11Anchor(softhsm, _TOKEN, user_pin=_PIN, object_label=label).current_head()
    assert reading is not None and reading.head == b"\xaf" * 32


def test_a_missing_extra_is_one_failed_link_not_a_failed_chain(softhsm, monkeypatch):
    """Pkcs11Unavailable used to escape ChainedAnchorSource, so a profile
    with a pkcs11 link on a machine without the extra consulted nothing
    else. On the read path it is an AnchorSourceError naming the extra."""
    from palimpsests.audit import anchors_pkcs11
    from palimpsests.audit.anchors_pkcs11 import Pkcs11Unavailable

    def missing():
        raise Pkcs11Unavailable(
            "the PKCS#11 anchor needs 'python-pkcs11'; install the [pkcs11] extra."
        )

    monkeypatch.setattr(anchors_pkcs11, "_pkcs11", missing)
    chain = ChainedAnchorSource(
        [Pkcs11Anchor(softhsm, _TOKEN, user_pin=_PIN), ManualAnchor("cd" * 32, detail="cli")]
    )
    reading = chain.current_head()
    assert reading is not None and reading.head == bytes.fromhex("cd" * 32)
    outcomes = [a.outcome for a in chain.last_attempts]
    assert outcomes == ["error", "answered"]
    assert "[pkcs11]" in chain.last_attempts[0].error


def test_the_store_still_fails_loudly_without_the_extra(softhsm, monkeypatch):
    """Only the read path converts; a caller writing an anchor must still
    get the packaging error itself, not a quiet per-link outcome."""
    from palimpsests.audit import anchors_pkcs11
    from palimpsests.audit.anchors_pkcs11 import Pkcs11Unavailable

    def missing():
        raise Pkcs11Unavailable("needs the [pkcs11] extra")

    monkeypatch.setattr(anchors_pkcs11, "_pkcs11", missing)
    with pytest.raises(Pkcs11Unavailable):
        Pkcs11AnchorStore(softhsm, _TOKEN, user_pin=_PIN).store_head(b"\x09" * 32)
