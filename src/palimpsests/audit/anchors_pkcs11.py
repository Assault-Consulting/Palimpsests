# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Tier-B anchor plumbing: the chain head as an object on a PKCS#11 token.

ADR-0004. The head lives in a ``CKO_DATA`` object
(``LABEL = "pala-anchor-head"``, ``APPLICATION = "palimpsests"``) on a
token the host can read but cannot silently rewrite at will — the first
anchor mechanism outside the host trust boundary that file and keychain
sources share.

Both classes speak the existing seams and change no default behaviour:
:class:`Pkcs11Anchor` is an ``AnchorSource`` (read side),
:class:`Pkcs11AnchorStore` an ``AnchorStore`` (write side). Failure
semantics are inherited, not invented: absent is normal and returns
``None``; present-but-unreadable — unreachable module, missing token,
wrong PIN, wrong value length, multiple matching objects — raises
:class:`~palimpsests.audit.anchors.AnchorSourceError` with the source
identity attached, so a chain records the link under its name.

Write is destroy-then-create in one read-write session. PKCS#11 has no
atomic replace; the window between the two is visible to a concurrent
reader as *absent*, never as a torn value — a strictly better failure
shape than a half-written file, and stated here rather than discovered.

Honesty of the claim (ADR-0004): this module is the tier-B *mechanism*.
A tier-B *claim* for a concrete deployment requires a real token or
HSM; SoftHSM in CI proves the code path, not the tier.

``python-pkcs11`` is imported lazily via the ``[pkcs11]`` extra,
mirroring ``bodies``/``scitt``: a bare install keeps every existing
anchor source.
"""
from __future__ import annotations

import time
from collections.abc import Mapping
from palimpsests.audit.anchors import AnchorReading, AnchorSourceError

__all__ = [
    "DEFAULT_OBJECT_LABEL",
    "Pkcs11Anchor",
    "Pkcs11AnchorStore",
    "Pkcs11Unavailable",
]

_HEAD_LEN = 32
DEFAULT_OBJECT_LABEL = "pala-anchor-head"
_APPLICATION = "palimpsests"


class Pkcs11Unavailable(RuntimeError):
    """Raised when the PKCS#11 anchor is used without the [pkcs11] extra."""


def _pkcs11():
    try:
        import pkcs11
        from pkcs11 import Attribute, ObjectClass
    except ImportError as e:  # pragma: no cover - import guard
        raise Pkcs11Unavailable(
            "the PKCS#11 anchor needs 'python-pkcs11'; install the [pkcs11] "
            "extra. Every other anchor source works without it."
        ) from e
    return pkcs11, Attribute, ObjectClass


class _TokenHandle:
    """Shared open-the-token plumbing for the source and the store."""

    def __init__(
        self,
        module_path: str,
        token_label: str,
        *,
        user_pin: str | None,
        object_label: str,
    ) -> None:
        self._module_path = module_path
        self._token_label = token_label
        self._user_pin = user_pin
        self._object_label = object_label
        self.source_kind = "pkcs11"
        self.source_detail = f"{token_label}/{object_label}"

    def _error(self, message: str) -> AnchorSourceError:
        return AnchorSourceError(
            message, source_kind=self.source_kind, source_detail=self.source_detail
        )

    def _token(self):
        pkcs11, _, _ = _pkcs11()
        try:
            lib = pkcs11.lib(self._module_path)
        except Exception as e:
            raise self._error(f"PKCS#11 module {self._module_path!r} failed to load: {e}") from e
        try:
            return lib.get_token(token_label=self._token_label)
        except Exception as e:
            raise self._error(f"token {self._token_label!r} not found: {e}") from e

    def _session(self, *, rw: bool):
        _, _, _ = _pkcs11()
        token = self._token()
        try:
            return token.open(rw=rw, user_pin=self._user_pin)
        except Exception as e:
            raise self._error(f"opening a session failed (PIN?): {e}") from e

    def _find(self, session) -> list:
        _, Attribute, ObjectClass = _pkcs11()
        query = {
            Attribute.CLASS: ObjectClass.DATA,
            Attribute.LABEL: self._object_label,
        }
        try:
            return list(session.get_objects(query))
        except Exception as e:
            raise self._error(f"object lookup failed: {e}") from e


class Pkcs11Anchor(_TokenHandle):
    """Read the anchored head from a token object (``AnchorSource``).

    Zero matching objects is ``None`` — absent is normal. One object
    with a 32-byte value answers. Anything else raises
    ``AnchorSourceError``: present but unreadable must never degrade
    into silently absent.
    """

    def __init__(
        self,
        module_path: str,
        token_label: str,
        *,
        user_pin: str | None = None,
        object_label: str = DEFAULT_OBJECT_LABEL,
    ) -> None:
        super().__init__(
            module_path, token_label, user_pin=user_pin, object_label=object_label
        )

    def current_head(self) -> AnchorReading | None:
        _, Attribute, _ = _pkcs11()
        with self._session(rw=False) as session:
            objects = self._find(session)
            if not objects:
                return None
            if len(objects) > 1:
                raise self._error(
                    f"{len(objects)} objects match label "
                    f"{self._object_label!r} — the anchor must be unambiguous"
                )
            try:
                value = bytes(objects[0][Attribute.VALUE])
            except Exception as e:
                raise self._error(f"reading the object value failed: {e}") from e
        if len(value) != _HEAD_LEN:
            raise self._error(
                f"anchored value is {len(value)} bytes, expected {_HEAD_LEN} — "
                "present but unreadable"
            )
        return AnchorReading(
            head=value,
            source_kind=self.source_kind,
            source_detail=self.source_detail,
            observed_at_ns=time.time_ns(),
        )


class Pkcs11AnchorStore(_TokenHandle):
    """Persist the head as the token object (``AnchorStore``).

    Destroy-then-create in one read-write session; the in-between state
    a concurrent reader can observe is *absent*, never torn. ``meta``
    is accepted for interface compatibility and not persisted: the
    token object is the head, nothing else.
    """

    def __init__(
        self,
        module_path: str,
        token_label: str,
        *,
        user_pin: str | None = None,
        object_label: str = DEFAULT_OBJECT_LABEL,
    ) -> None:
        super().__init__(
            module_path, token_label, user_pin=user_pin, object_label=object_label
        )

    def store_head(
        self, head: bytes, *, meta: Mapping[str, str] | None = None
    ) -> None:
        if len(head) != _HEAD_LEN:
            raise ValueError(f"anchor head must be {_HEAD_LEN} bytes, got {len(head)}")
        _, Attribute, ObjectClass = _pkcs11()
        with self._session(rw=True) as session:
            for obj in self._find(session):
                try:
                    obj.destroy()
                except Exception as e:
                    raise self._error(f"replacing the previous anchor failed: {e}") from e
            try:
                session.create_object(
                    {
                        Attribute.CLASS: ObjectClass.DATA,
                        Attribute.LABEL: self._object_label,
                        Attribute.APPLICATION: _APPLICATION,
                        Attribute.VALUE: head,
                        Attribute.TOKEN: True,
                    }
                )
            except Exception as e:
                raise self._error(f"writing the anchor object failed: {e}") from e
