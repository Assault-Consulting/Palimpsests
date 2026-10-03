# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""A Messages-API stand-in model for surface probes of Claude Code.

It plans nothing: on the first tool-bearing request it asks for one
``Read`` of ``NOTES.md``; once a ``tool_result`` is in the conversation
it answers with text. Requests without tools (titles, side calls) get
text. Everything else — running the tool, firing the hooks — is the
client's own behaviour, which is what a surface probe measures.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _sse(events: list[tuple[str, dict]]) -> bytes:
    return "".join(f"event: {n}\ndata: {json.dumps(d)}\n\n" for n, d in events).encode()


def _start(mid: str) -> tuple[str, dict]:
    return ("message_start", {"type": "message_start", "message": {
        "id": mid, "type": "message", "role": "assistant", "model": "stub", "content": [],
        "stop_reason": None, "usage": {"input_tokens": 1, "output_tokens": 1}}})


def _stop(reason: str) -> list[tuple[str, dict]]:
    return [("message_delta", {"type": "message_delta", "delta": {"stop_reason": reason},
                               "usage": {"output_tokens": 1}}),
            ("message_stop", {"type": "message_stop"})]


def _tool_use(mid: str, file_path: str) -> bytes:
    return _sse([_start(mid),
                 ("content_block_start", {"type": "content_block_start", "index": 0,
                  "content_block": {"type": "tool_use", "id": "toolu_surface_read",
                                    "name": "Read", "input": {}}}),
                 ("content_block_delta", {"type": "content_block_delta", "index": 0,
                  "delta": {"type": "input_json_delta",
                            "partial_json": json.dumps({"file_path": file_path})}}),
                 ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                 *_stop("tool_use")])


def _text(mid: str, text: str) -> bytes:
    return _sse([_start(mid),
                 ("content_block_start", {"type": "content_block_start", "index": 0,
                  "content_block": {"type": "text", "text": ""}}),
                 ("content_block_delta", {"type": "content_block_delta", "index": 0,
                  "delta": {"type": "text_delta", "text": text}}),
                 ("content_block_stop", {"type": "content_block_stop", "index": 0}),
                 *_stop("end_turn")])


class AnthropicStub:
    """Serve the stand-in on a loopback port; count tool-bearing requests."""

    def __init__(self, file_path: str):
        self.tool_requests = 0
        stub = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0)))
                                  or b"{}")
                answered = any(
                    isinstance(c, dict) and c.get("type") == "tool_result"
                    for m in body.get("messages", []) if isinstance(m.get("content"), list)
                    for c in m["content"])
                if body.get("tools"):
                    stub.tool_requests += 1
                data = (_tool_use("m", file_path) if body.get("tools") and not answered
                        else _text("m", "Done."))
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.end_headers()
                self.wfile.write(b"{}")

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
