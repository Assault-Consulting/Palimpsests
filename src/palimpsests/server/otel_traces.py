# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry GenAI tool spans → reported tool pairs (family B).

An application instrumented with OpenTelemetry exports its traces over
OTLP/HTTP. Among them, the GenAI semantic conventions put one span on
every tool execution — ``gen_ai.operation.name = execute_tool``, named
``execute_tool {gen_ai.tool.name}`` — carrying the tool's name and call
id, and, only when the application opted in to content capture, its
arguments and result as JSON strings. This module reads those spans out
of an OTLP export and leaves everything else: the chain records the tool
loop, not the trace — the serve is not a trace backend.

Decisions this follows (0.13 plan, D3–D5):

- **D3 — a version it does not recognise is recorded, marked.** The
  GenAI conventions are in Development and move between releases. A span
  is kept whatever ``schemaUrl`` the exporter declared, and that version
  (or "unstated") goes into the call record's detail, so a reader sees
  which conventions the span claimed. The one span that is dropped is a
  tool span with no tool name — in the attribute or in the span name —
  because there is nothing to record a call *of*.
- **D4 — digests over canonical JSON.** ``gen_ai.tool.call.arguments`` and
  ``.result`` are JSON strings; each is parsed and digested by the
  profile's canonical rule, so the same arguments give the same digest
  whichever exporter serialised them. A value that is not JSON is
  digested as the string it is. Content never enters the chain.
- **D5 — no dependency in the base package.** OTLP/JSON needs nothing.
  OTLP/protobuf needs ``opentelemetry-proto``, which ships in the
  ``[serve]`` extra; without it a protobuf export is refused with a
  sentence saying what to install, never misread.

**Outcome.** A tool span whose status is ``ERROR`` closes its pair as
``error``; any other status — ``OK`` or ``UNSET`` — as ``ok``. The
conventions signal a failed tool by the span's error status, so this
vantage *does* observe failure (unlike Codex's hooks, where r6's
``unobserved`` applies). What it cannot see is a tool that returned an
error *as its result*: to OpenTelemetry that is a success, and to the
chain it is ``ok`` — a return, never a confirmed effect.
"""

from __future__ import annotations

import gzip
import json
from dataclasses import dataclass, field

__all__ = [
    "OtlpUnavailable",
    "ToolSpan",
    "TraceBatch",
    "TraceIngest",
    "decode_otlp",
]

#: The GenAI attribute keys this module reads.
ATTR_OPERATION = "gen_ai.operation.name"
ATTR_TOOL_NAME = "gen_ai.tool.name"
ATTR_TOOL_CALL_ID = "gen_ai.tool.call.id"
ATTR_TOOL_ARGUMENTS = "gen_ai.tool.call.arguments"
ATTR_TOOL_RESULT = "gen_ai.tool.call.result"
ATTR_ERROR_TYPE = "error.type"
OPERATION_EXECUTE_TOOL = "execute_tool"
_SPAN_NAME_PREFIX = "execute_tool "

# OTLP Status.code (trace.proto): 0 UNSET, 1 OK, 2 ERROR. OTLP/JSON
# encodes enums as integers, but some exporters write the name.
_STATUS_ERROR = {2, "2", "STATUS_CODE_ERROR"}


class OtlpUnavailable(RuntimeError):
    """A protobuf export arrived and ``opentelemetry-proto`` is not installed."""


@dataclass(frozen=True)
class ToolSpan:
    """One ``execute_tool`` span, as much of it as the chain records."""

    trace_id: str  # hex
    span_id: str  # hex
    tool_name: str
    call_id: str | None
    start_ns: int
    end_ns: int
    failed: bool  # status ERROR
    error_type: str | None
    arguments: str | None  # the JSON string as exported; digested, never stored
    result: str | None
    semconv: str  # the declared conventions version, or "unstated"


@dataclass
class TraceBatch:
    """What one export held: the tool spans to record, in start order, and
    how many tool spans were dropped and why."""

    tool_spans: list[ToolSpan] = field(default_factory=list)
    dropped: int = 0
    dropped_reason: str | None = None


def decode_otlp(body: bytes, content_type: str, content_encoding: str | None = None) -> TraceBatch:
    """Read an OTLP/HTTP trace export; return its tool spans.

    ``content_type`` is ``application/json`` or ``application/x-protobuf``
    (parameters ignored); ``content_encoding`` may be ``gzip``. Raises
    ``ValueError`` for a body that is not what it claims, and
    :class:`OtlpUnavailable` for protobuf without ``opentelemetry-proto``.
    """
    if (content_encoding or "").strip().lower() == "gzip":
        try:
            body = gzip.decompress(body)
        except OSError as e:
            raise ValueError(f"Content-Encoding gzip, but the body is not gzip: {e}") from e
    ctype = (content_type or "").split(";")[0].strip().lower()
    if ctype == "application/json":
        try:
            doc = json.loads(body)
        except ValueError as e:
            raise ValueError(f"OTLP/JSON body is not JSON: {e}") from e
        spans = _spans_from_json(doc)
    elif ctype == "application/x-protobuf":
        spans = _spans_from_protobuf(body)
    else:
        raise ValueError(
            f"unsupported Content-Type {content_type!r}: OTLP/HTTP is "
            "application/json or application/x-protobuf"
        )
    return _select(spans)


# ── one neutral span shape, from either encoding ─────────────────────────


@dataclass(frozen=True)
class _Span:
    trace_id: str
    span_id: str
    name: str
    start_ns: int
    end_ns: int
    status_code: object
    attrs: dict
    semconv: str


def _semconv(*schema_urls: str | None) -> str:
    """The version from the innermost declared ``schemaUrl``, or "unstated".

    Conventions schema URLs end in the version
    (``https://opentelemetry.io/schemas/1.41.0``); a scope's URL overrides
    its resource's.
    """
    for url in schema_urls:
        if url:
            return url.rstrip("/").rsplit("/", 1)[-1]
    return "unstated"


def _json_value(v: dict):
    """An OTLP/JSON ``AnyValue`` → a Python value (strings are what matter)."""
    if not isinstance(v, dict):
        return None
    for k in ("stringValue", "boolValue", "doubleValue"):
        if k in v:
            return v[k]
    if "intValue" in v:  # int64 arrives as a string in OTLP/JSON
        try:
            return int(v["intValue"])
        except (TypeError, ValueError):
            return v["intValue"]
    return None


def _spans_from_json(doc: object) -> list[_Span]:
    if not isinstance(doc, dict):
        raise ValueError("OTLP/JSON export is not an object")
    out: list[_Span] = []
    for rs in doc.get("resourceSpans") or []:
        res_url = rs.get("schemaUrl")
        for ss in rs.get("scopeSpans") or []:
            sem = _semconv(ss.get("schemaUrl"), res_url)
            for sp in ss.get("spans") or []:
                attrs = {
                    a.get("key"): _json_value(a.get("value"))
                    for a in sp.get("attributes") or []
                    if isinstance(a, dict)
                }
                out.append(_Span(
                    trace_id=str(sp.get("traceId") or ""),
                    span_id=str(sp.get("spanId") or ""),
                    name=str(sp.get("name") or ""),
                    start_ns=int(sp.get("startTimeUnixNano") or 0),
                    end_ns=int(sp.get("endTimeUnixNano") or 0),
                    status_code=(sp.get("status") or {}).get("code", 0),
                    attrs=attrs,
                    semconv=sem,
                ))
    return out


def _spans_from_protobuf(body: bytes) -> list[_Span]:
    try:
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
            ExportTraceServiceRequest,
        )
    except ImportError as e:
        raise OtlpUnavailable(
            "an OTLP/protobuf export needs 'opentelemetry-proto' — install the "
            "[serve] extra, or have the exporter send OTLP/JSON "
            "(OTEL_EXPORTER_OTLP_TRACES_PROTOCOL=http/json)"
        ) from e
    req = ExportTraceServiceRequest()
    try:
        req.ParseFromString(body)
    except Exception as e:  # protobuf's DecodeError is not a ValueError
        raise ValueError(f"OTLP/protobuf body does not parse: {e}") from e
    out: list[_Span] = []
    for rs in req.resource_spans:
        for ss in rs.scope_spans:
            sem = _semconv(ss.schema_url, rs.schema_url)
            for sp in ss.spans:
                attrs = {}
                for a in sp.attributes:
                    which = a.value.WhichOneof("value")
                    attrs[a.key] = getattr(a.value, which) if which else None
                out.append(_Span(
                    trace_id=sp.trace_id.hex(),
                    span_id=sp.span_id.hex(),
                    name=sp.name,
                    start_ns=sp.start_time_unix_nano,
                    end_ns=sp.end_time_unix_nano,
                    status_code=sp.status.code,
                    attrs=attrs,
                    semconv=sem,
                ))
    return out


def _select(spans: list[_Span]) -> TraceBatch:
    """Keep the ``execute_tool`` spans; order them by start time.

    An exporter batches, and a batch is not in execution order; the chain
    is append-only, so the order within a batch is fixed here, by the
    span's own start time. Across batches nothing can be reordered — two
    batches land in the order they arrive.
    """
    batch = TraceBatch()
    for sp in spans:
        if sp.attrs.get(ATTR_OPERATION) != OPERATION_EXECUTE_TOOL:
            continue
        name = sp.attrs.get(ATTR_TOOL_NAME)
        if not (isinstance(name, str) and name):
            # v1.41 also puts the name in the span name
            if sp.name.startswith(_SPAN_NAME_PREFIX) and sp.name[len(_SPAN_NAME_PREFIX):].strip():
                name = sp.name[len(_SPAN_NAME_PREFIX):].strip()
            else:
                batch.dropped += 1
                batch.dropped_reason = (
                    "execute_tool span without a tool name (gen_ai.tool.name or "
                    "the span name 'execute_tool <name>'): nothing to record a call of"
                )
                continue
        call_id = sp.attrs.get(ATTR_TOOL_CALL_ID)
        args = sp.attrs.get(ATTR_TOOL_ARGUMENTS)
        result = sp.attrs.get(ATTR_TOOL_RESULT)
        etype = sp.attrs.get(ATTR_ERROR_TYPE)
        batch.tool_spans.append(ToolSpan(
            trace_id=sp.trace_id,
            span_id=sp.span_id,
            tool_name=name,
            call_id=str(call_id) if call_id is not None else None,
            start_ns=sp.start_ns,
            end_ns=sp.end_ns,
            failed=sp.status_code in _STATUS_ERROR,
            error_type=str(etype) if etype is not None else None,
            arguments=args if isinstance(args, str) else None,
            result=result if isinstance(result, str) else None,
            semconv=sp.semconv,
        ))
    batch.tool_spans.sort(key=lambda s: (s.start_ns, s.span_id))
    return batch


def canonical_payload(value: str | None):
    """What D4 digests: the parsed JSON when the string is JSON, else the string."""
    if value is None:
        return None
    try:
        return json.loads(value)
    except ValueError:
        return value


# ── recording ────────────────────────────────────────────────────────────

#: Span ids remembered, so an exporter's retry of a batch it thinks failed
#: does not record its spans twice. Bounded, like the hook route's memory.
SEEN_MEMORY = 16384


class TraceIngest:
    """Per-app state for the traces route: one pair per tool span, once."""

    def __init__(self, audit) -> None:
        import threading
        from collections import OrderedDict

        self._audit = audit
        self._seen: OrderedDict[tuple[str, str], None] = OrderedDict()
        self._lock = threading.Lock()

    def record(self, batch: TraceBatch) -> tuple[int, int]:
        """Write the batch's tool spans; return ``(recorded, duplicates)``."""
        from palimpsests.audit.pala_writer import (
            OUTCOME_ERROR,
            OUTCOME_OK,
            SOURCE_REPORTED_BY_CLIENT,
            canonical_tool_args_digest,
        )

        recorded = duplicates = 0
        with self._lock:
            for span in batch.tool_spans:
                key = (span.trace_id, span.span_id)
                if key in self._seen:
                    duplicates += 1
                    continue
                args = canonical_payload(span.arguments)
                result = canonical_payload(span.result)
                detail = f"otel execute_tool; semconv {span.semconv}"
                if span.failed and span.error_type:
                    detail += f"; error.type {span.error_type}"
                seq, call_hash = self._audit.tool_called(
                    span.tool_name,
                    canonical_tool_args_digest(args) if args is not None else None,
                    None,
                    source=SOURCE_REPORTED_BY_CLIENT,
                    detail=detail,
                )
                self._audit.tool_result(
                    seq,
                    call_hash,
                    OUTCOME_ERROR if span.failed else OUTCOME_OK,
                    canonical_tool_args_digest(result) if result is not None else None,
                    None,
                    source=SOURCE_REPORTED_BY_CLIENT,
                )
                self._seen[key] = None
                while len(self._seen) > SEEN_MEMORY:
                    self._seen.popitem(last=False)
                recorded += 1
        return recorded, duplicates
