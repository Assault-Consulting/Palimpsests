# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Agent tool hooks in the Claude schema → reported tool pairs.

Claude Code calls a hook before and after every tool it runs
(``PreToolUse``, ``PostToolUse``, ``PostToolUseFailure``) and can deliver
the hook as an HTTP ``POST`` with the event as the JSON body. This module
turns those events into the same records the ingestion route writes:
``TOOL_CALL`` / ``TOOL_RESULT`` (profile kinds 8/9) marked
``reported-by-client``. The chain then proves that the agent reported a
call and a result, their digests, and when — not that the tool ran.

What the hooks really send was measured before this was written
(``integrations/agent-hooks/PROBE-RESULTS.md``, Claude Code 2.1.288):

- ``tool_use_id`` is present on every event and equal between the
  ``Pre`` and ``Post`` events of one call — it is the pairing key;
- a successful result is ``tool_response`` (an object for Claude Code);
- a failure arrives as ``PostToolUseFailure`` carrying ``error``, a
  string, and no ``tool_response``.

Digests use the profile's canonical form for tool payloads
(:func:`canonical_tool_args_digest`: JSON, sorted keys, compact
separators, UTF-8, SHA-256) for the input *and* the result, so an object
and a string go through one rule and two deliveries of one result give
one digest. Content never enters the chain.

Contract with the agent: **never block, never alter.** Every outcome the
agent can see is a response with an empty JSON object — no decision, so
the tool proceeds — and an event this module does not record (a prompt
hook, a session hook) is accepted and ignored rather than refused.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from palimpsests.audit.pala_writer import (
    OUTCOME_ERROR,
    OUTCOME_OK,
    SOURCE_REPORTED_BY_CLIENT,
    canonical_tool_args_digest,
)

TOOL_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure")

#: How many closed call ids to remember, so a re-delivered ``Post`` event
#: is recognised as a duplicate instead of opening a second pair. Bounded:
#: a long-lived serve must not grow without limit for this.
CLOSED_MEMORY = 4096

# Hook call ids share the serve's pending map with wire-parsed and
# ingested calls. A prefix keeps an agent's ids from ever colliding with
# an id from another path.
_KEY_PREFIX = "hook:"


class HookIngest:
    """Per-app state for the hook route: what is open, what is closed."""

    def __init__(self, audit, pending: dict) -> None:
        self._audit = audit
        self._pending = pending
        self._closed: OrderedDict[str, None] = OrderedDict()
        # The serve runs route handlers on a thread pool, and an agent can
        # run tools in parallel: a Pre and a Post, or a re-delivered event,
        # can arrive at once. Every check-then-write below is one decision.
        self._lock = threading.Lock()

    def _remember_closed(self, key: str) -> None:
        self._closed[key] = None
        self._closed.move_to_end(key)
        while len(self._closed) > CLOSED_MEMORY:
            self._closed.popitem(last=False)

    def handle(self, payload: object) -> tuple[int, dict]:
        """One hook event in; ``(status, body)`` out."""
        with self._lock:
            return self._handle(payload)

    def _handle(self, payload: object) -> tuple[int, dict]:
        if not isinstance(payload, dict):
            return 400, {"error": "hook body must be a JSON object"}
        event = payload.get("hook_event_name")
        if event not in TOOL_EVENTS:
            # Other hook events (prompts, sessions, compaction) carry no
            # tool call. Accepted, not recorded — refusing them would only
            # produce errors in the agent's log for hooks that work.
            return 200, {}
        call_id = payload.get("tool_use_id")
        name = payload.get("tool_name")
        if not isinstance(call_id, str) or not call_id or not isinstance(name, str) or not name:
            return 400, {"error": "a tool hook needs tool_name and tool_use_id"}

        key = _KEY_PREFIX + call_id
        if key in self._closed:
            return 200, {}  # a re-delivered event for a pair already closed

        if event == "PreToolUse":
            if key in self._pending:
                return 200, {}  # a re-delivered Pre: the call is already on the chain
            self._open(key, name, payload)
            return 200, {}

        if key not in self._pending:
            # A result whose call this serve never saw: the Pre hook was not
            # configured, failed, or arrived before the serve started. Record
            # the call and then the result, so the result is never orphaned;
            # the call's record time is then the time the result arrived.
            self._open(key, name, payload)
        seq, call_hash, source = self._pending.pop(key)
        if event == "PostToolUse":
            outcome = OUTCOME_OK
            digest = (
                canonical_tool_args_digest(payload["tool_response"])
                if "tool_response" in payload
                else None
            )
        else:  # PostToolUseFailure
            outcome = OUTCOME_ERROR
            digest = canonical_tool_args_digest(payload["error"]) if "error" in payload else None
        self._audit.tool_result(seq, call_hash, outcome, digest, None, source=source)
        self._remember_closed(key)
        return 200, {}

    def _open(self, key: str, name: str, payload: dict) -> None:
        args = payload.get("tool_input")
        digest = canonical_tool_args_digest(args) if args is not None else None
        seq, call_hash = self._audit.tool_called(
            name, digest, None, source=SOURCE_REPORTED_BY_CLIENT
        )
        self._pending[key] = (seq, call_hash, SOURCE_REPORTED_BY_CLIENT)
