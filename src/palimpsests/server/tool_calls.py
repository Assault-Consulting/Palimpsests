# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Function calling for the OpenAI-compatible endpoint — parsing and prompting.

Local models emit tool calls in *model-specific* syntaxes; there is no
universal wire format on the model side. This module implements the most
widespread local convention — Hermes/Qwen-style ``<tool_call>{json}</tool_call>``
blocks — plus a bare-JSON fallback (a lone object carrying ``name`` and
``arguments``), and the matching prompt side: a system message that
declares the available tools and instructs the model to use exactly that
syntax. One convention, stated and tested, beats five half-supported
ones; other model formats can register here later without touching the
endpoint.
"""
from __future__ import annotations

import json
import re
import uuid
from dataclasses import dataclass

_TOOL_CALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


@dataclass(frozen=True)
class ParsedToolCall:
    """One tool invocation the model asked for."""

    id: str
    name: str
    arguments: dict

    def as_openai(self) -> dict:
        return {
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": json.dumps(self.arguments, ensure_ascii=False),
            },
        }


def _new_id() -> str:
    return f"call_{uuid.uuid4().hex[:12]}"


def parse_tool_calls(text: str) -> tuple[list[ParsedToolCall], str]:
    """Extract tool calls from model output; return (calls, remaining_text).

    Recognizes Hermes/Qwen ``<tool_call>…</tool_call>`` blocks first; if
    none are present and the whole reply is a single JSON object with
    ``name`` and ``arguments``, that counts too (several instruct models
    answer bare when prompted with the convention). Anything unparseable
    stays in the text — a malformed call is the model's utterance, not
    this layer's guess.
    """
    calls: list[ParsedToolCall] = []
    remaining = text

    def _try(obj_text: str) -> ParsedToolCall | None:
        try:
            obj = json.loads(obj_text)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict) or "name" not in obj:
            return None
        args = obj.get("arguments", {})
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                return None
        if not isinstance(args, dict):
            return None
        return ParsedToolCall(id=_new_id(), name=str(obj["name"]), arguments=args)

    matches = list(_TOOL_CALL_RE.finditer(text))
    if matches:
        for m in matches:
            call = _try(m.group(1))
            if call is not None:
                calls.append(call)
        if not calls:
            # A block matched but nothing parsed: the model's utterance is
            # not this layer's to erase — return it untouched.
            return [], text
        remaining = _TOOL_CALL_RE.sub("", text).strip()
        return calls, remaining

    stripped = text.strip()
    if stripped.startswith("{") and stripped.endswith("}"):
        call = _try(stripped)
        if call is not None:
            return [call], ""
    return [], text


def tools_system_message(tools: list[dict]) -> dict:
    """The system message that declares ``tools`` in the one convention."""
    specs = []
    for t in tools:
        fn = t.get("function", t)
        specs.append(
            json.dumps(
                {
                    "name": fn.get("name"),
                    "description": fn.get("description", ""),
                    "parameters": fn.get("parameters", {}),
                },
                ensure_ascii=False,
            )
        )
    joined = "\n".join(specs)
    return {
        "role": "system",
        "content": (
            "You have access to the following tools:\n"
            f"{joined}\n\n"
            "To call a tool, respond with exactly:\n"
            '<tool_call>{"name": "<tool name>", "arguments": {…}}</tool_call>\n'
            "After a tool result arrives, continue the conversation."
        ),
    }
