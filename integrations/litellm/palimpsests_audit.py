# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Palimpsests audit callback for LiteLLM.

One file, standard library only. Attach it to a LiteLLM client or proxy
and every *structured* tool loop that passes through LiteLLM lands on a
Palimpsests chain as ``TOOL_CALL`` / ``TOOL_RESULT`` records carrying
``EVT_SOURCE = reported-by-client`` (inference profile r5) — through the
serve's ingestion surface, ``POST /v1/pala/events``.

What it sees, and therefore what it can honestly report
--------------------------------------------------------
LiteLLM sits between an application and a model provider. It sees the
model's *response* — including the ``tool_calls`` the model asked for —
and, on the *next* request, the ``role: tool`` messages the application
fed back. It never sees the tool run. So:

* a ``tool_calls`` entry in a response is reported as a ``TOOL_CALL``
  (registered name + argument digest; the arguments themselves are sent
  to the serve, which stores only their digest);
* a ``role: tool`` message whose ``tool_call_id`` matches a call this
  callback reported is reported as a ``TOOL_RESULT`` with outcome ``ok``
  — meaning *a result re-entered generation*, never *the action took
  effect* (profile open issue 5).

That is the same pairing rule the serve applies to loops on its own
wire; the difference is the mark. A wire-parsed pair is the runtime's
observation. A pair reported from here is the client's assertion,
faithfully recorded — the chain proves the report and its digests, not
that the tool ran.

Install
-------
Copy this file next to your code (or into the proxy's ``custom_callbacks``
location) and register it::

    import litellm
    from palimpsests_audit import PalimpsestsAudit
    litellm.callbacks = [PalimpsestsAudit()]

Proxy ``config.yaml``::

    litellm_settings:
      callbacks: custom_callbacks.palimpsests_audit

with ``custom_callbacks.py`` containing ``palimpsests_audit =
PalimpsestsAudit()``. Configuration is by environment, the same variables
the serve and the OpenCode plugin read:

    PALIMPSESTS_SERVE_URL      default http://127.0.0.1:11435
    PALIMPSESTS_SERVE_API_KEY  bearer key when the serve runs with --api-key
    PALIMPSESTS_AUDIT_REPORT   "0" disables reporting entirely

Contract
--------
* Never blocks, never alters. A failed report is logged (``logging``,
  logger ``palimpsests.audit.litellm``) and the completion proceeds.
* One result per call. A call id is reported once, ever; a later tool
  message for the same id is reported once; further duplicates are
  ignored. (The ``_seen`` set grows by one string per tool call for the
  life of the process — bounded by the conversation, not the traffic.)
* A call whose result never comes back stays pending on the serve and is
  recorded ``cancelled`` at serve shutdown — abandonment recorded as
  abandonment, never an invented outcome.
* Streaming: LiteLLM assembles the final response before calling the
  success hook, so streamed tool calls arrive here exactly like
  non-streamed ones.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import urllib.error
import urllib.request

DEFAULT_URL = "http://127.0.0.1:11435"
_log = logging.getLogger("palimpsests.audit.litellm")


class Reporter:
    """The transport and the pairing memory, independent of LiteLLM.

    ``observe(messages, response)`` is the whole logic: report the
    results the request carries for calls already reported, then report
    the calls the response asks for. Safe to call from any thread.
    """

    def __init__(self, url: str | None = None, api_key: str | None = None) -> None:
        self.url = (url or os.environ.get("PALIMPSESTS_SERVE_URL") or DEFAULT_URL).rstrip("/")
        self.api_key = (
            api_key if api_key is not None else os.environ.get("PALIMPSESTS_SERVE_API_KEY", "")
        )
        self.enabled = os.environ.get("PALIMPSESTS_AUDIT_REPORT") != "0"
        self._pending: set[str] = set()  # reported calls awaiting a result
        self._seen: set[str] = set()  # every call id ever reported — never twice
        # LiteLLM runs success hooks off the request thread, so the hook for
        # turn N+1 (carrying a tool result) can fire before the hook for turn
        # N (carrying the call). A result whose call has not been reported
        # yet waits here and is sent right after the call, in one batch.
        self._early: dict[str, str] = {}
        self._lock = threading.RLock()

    # ── transport ───────────────────────────────────────────────────────
    def post(self, events: list[dict]) -> list[dict] | None:
        if not events or not self.enabled:
            return None
        body = json.dumps({"events": events}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(
            f"{self.url}/v1/pala/events", data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, ValueError) as e:
            _log.warning("palimpsests: report failed (%s events): %s", len(events), e)
            return None
        results = data.get("results", [])
        for r in results:
            if r.get("error"):
                _log.warning("palimpsests: serve rejected event %s: %s", r.get("id"), r["error"])
        return results

    # ── the logic ───────────────────────────────────────────────────────
    def observe(self, messages: list | None, response) -> list[dict]:
        """Report results-then-calls for one completion; return the events sent."""
        events: list[dict] = []
        with self._lock:
            for m in messages or []:
                if not isinstance(m, dict) or m.get("role") != "tool":
                    continue
                call_id = str(m.get("tool_call_id") or "")
                if call_id in self._pending:
                    self._pending.discard(call_id)
                    events.append(_result(call_id, m.get("content")))
                elif call_id and call_id not in self._seen and call_id not in self._early:
                    self._early[call_id] = _text(m.get("content"))
            for tc in _tool_calls(response):
                call_id = str(tc.get("id") or "")
                fn = tc.get("function") or {}
                name = str(fn.get("name") or "")
                if not call_id or not name or call_id in self._seen:
                    continue
                self._seen.add(call_id)
                events.append(
                    {
                        "type": "tool_call",
                        "id": call_id,
                        "name": name,
                        "arguments": _arguments(fn.get("arguments")),
                    }
                )
                early = self._early.pop(call_id, None)
                if early is not None:
                    events.append(_result(call_id, early))  # arrived first; sent after
                else:
                    self._pending.add(call_id)
            # Post while still holding the lock: a hook on another thread that
            # finds the call pending must not deliver the result before the
            # call itself has reached the serve. Reports are serialised; the
            # completions they describe are not delayed by them.
            if events:
                self.post(events)
        return events


def _result(call_id: str, content) -> dict:
    return {"type": "tool_result", "call_id": call_id, "outcome": "ok", "content": _text(content)}


def _text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    try:
        return json.dumps(content, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(content)


def _arguments(raw) -> dict:
    """OpenAI-shape arguments are a JSON *string*; the serve wants an object."""
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"_": parsed}
        except ValueError:
            return {"_raw": raw}
    return {}


def _tool_calls(response) -> list[dict]:
    """The response's tool calls as plain dicts, whatever object LiteLLM handed us."""
    if response is None:
        return []
    obj = response
    if hasattr(obj, "model_dump"):
        try:
            obj = obj.model_dump()
        except Exception:  # pragma: no cover - defensive against odd response types
            return []
    if not isinstance(obj, dict):
        return []
    out: list[dict] = []
    for choice in obj.get("choices") or []:
        msg = (choice or {}).get("message") or {}
        for tc in msg.get("tool_calls") or []:
            if isinstance(tc, dict):
                out.append(tc)
    return out


def _make_logger_class():
    """Build the LiteLLM ``CustomLogger`` subclass lazily, so this module
    imports (and its :class:`Reporter` is testable) without LiteLLM."""
    from litellm.integrations.custom_logger import CustomLogger

    class PalimpsestsAudit(CustomLogger):
        """Attach with ``litellm.callbacks = [PalimpsestsAudit()]``."""

        def __init__(self, url: str | None = None, api_key: str | None = None) -> None:
            super().__init__()
            self.reporter = Reporter(url, api_key)

        # Sync and async hooks both funnel into observe(); LiteLLM calls the
        # matching one for the entry point in use.
        def log_success_event(self, kwargs, response_obj, start_time, end_time):
            self.reporter.observe(kwargs.get("messages"), response_obj)

        async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
            self.reporter.observe(kwargs.get("messages"), response_obj)

        # A failed completion still carries the tool results the request fed
        # back; report those so the loop's shape stays complete on the chain.
        def log_failure_event(self, kwargs, response_obj, start_time, end_time):
            self.reporter.observe(kwargs.get("messages"), None)

        async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
            self.reporter.observe(kwargs.get("messages"), None)

    return PalimpsestsAudit


def __getattr__(name: str):
    # ``from palimpsests_audit import PalimpsestsAudit`` works when LiteLLM is
    # installed; without it, Reporter is still importable.
    if name == "PalimpsestsAudit":
        cls = _make_logger_class()
        globals()[name] = cls
        return cls
    raise AttributeError(name)
