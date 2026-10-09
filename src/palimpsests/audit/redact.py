# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Remove credentials from free text before it becomes evidence.

The audit stores keep a short free-text field — an exception message in
the operations log, ``EVT_DETAIL`` in the inference profile — and both
used to be *clipped* before writing. Clipping is not sanitising: an HTTP
client error that names a URL carrying ``?token=…`` fits comfortably in
200 characters. Once written, it is hash-chained: it cannot be removed
without breaking the chain it is evidence in. So it is scrubbed first,
then clipped.

What is removed — a value, never the text around it, so the message still
says what went wrong:

- ``Bearer`` / ``Basic`` credentials;
- the value of ``key=value`` / ``key: value`` / ``"key": "value"`` pairs
  whose key names a credential (``api_key``, ``token``, ``secret``,
  ``password``, ``authorization`` and their usual spellings);
- ``user:password@`` in URLs;
- token shapes that announce themselves (``sk-…``, ``ghp_…``,
  ``xox?-…``, ``AKIA…``, ``eyJ….….…`` JWTs).

It is a floor, not a guarantee: a secret with no recognisable shape, in
a field with no recognisable name, passes through. Deterministic, so
the same input is always written — and hashed — the same way.
"""

from __future__ import annotations

import re

__all__ = ["REDACTED", "scrub_secrets"]

REDACTED = "[REDACTED]"

_KEY = (
    r"(?:api[_-]?key|apikey|x-api-key|access[_-]?token|refresh[_-]?token|id[_-]?token|"
    r"auth[_-]?token|token|secret|client[_-]?secret|password|passwd|pwd|"
    r"authorization|private[_-]?key|session[_-]?id|sig|signature)"
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Authorization schemes
    (re.compile(r"(?i)\b(bearer|basic)(\s+)[A-Za-z0-9._~+/=-]+"), rf"\1\2{REDACTED}"),
    # "key": "value"  (JSON-ish)
    (re.compile(rf'(?i)("{_KEY}"\s*:\s*")[^"]*(")'), rf"\1{REDACTED}\2"),
    # key=value / key: value  (query strings, headers, env dumps)
    # (a value already handled above — a REDACTED marker, or a Bearer /
    # Basic scheme whose credential follows — is left as it is)
    (re.compile(
        rf"(?i)(\b{_KEY}\b\s*[=:]\s*)(?!{re.escape(REDACTED)}|(?:bearer|basic)\s)"
        r"[^\s&\"',;)}\]]+"
    ),
     rf"\1{REDACTED}"),
    # scheme://user:password@host
    (re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@"), rf"\1{REDACTED}@"),
    # self-announcing token shapes
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"), REDACTED),
    (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), REDACTED),
]


def scrub_secrets(text: str) -> str:
    """``text`` with recognisable credentials replaced by ``[REDACTED]``."""
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text
