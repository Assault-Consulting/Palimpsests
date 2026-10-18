# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""Family B: OpenTelemetry GenAI tool spans onto the chain.

One realistic export — a whole agent trace, of which only the
``execute_tool`` spans belong on the chain — read as OTLP/JSON, as
OTLP/protobuf and gzip-compressed, and posted to ``/v1/traces``.
"""
from __future__ import annotations

import gzip
import json
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402
from palimpsests.audit.pala_writer import (  # noqa: E402
    OUTCOME_ERROR,
    OUTCOME_OK,
    canonical_tool_args_digest,
)
from palimpsests.server.otel_traces import decode_otlp  # noqa: E402

TRACE = "5b8efff798038103d269b633813fc60c"


def _attr(key, value):
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    return {"key": key, "value": {"stringValue": value}}


def _span(span_id, name, start, *, op=None, tool=None, call_id=None, args=None,
          result=None, status=0, error_type=None):
    attrs = []
    if op:
        attrs.append(_attr("gen_ai.operation.name", op))
    if tool:
        attrs.append(_attr("gen_ai.tool.name", tool))
    if call_id:
        attrs.append(_attr("gen_ai.tool.call.id", call_id))
    if args is not None:
        attrs.append(_attr("gen_ai.tool.call.arguments", args))
    if result is not None:
        attrs.append(_attr("gen_ai.tool.call.result", result))
    if error_type:
        attrs.append(_attr("error.type", error_type))
    return {
        "traceId": TRACE, "spanId": span_id, "name": name,
        "startTimeUnixNano": str(start), "endTimeUnixNano": str(start + 1000),
        "attributes": attrs, "status": {"code": status},
    }


def _export():
    """A whole agent turn, spans deliberately out of start order."""
    spans = [
        _span("0000000000000003", "execute_tool fs.read", 300, op="execute_tool",
              tool="fs.read", call_id="call_2", args='{"path": "missing"}',
              status=2, error_type="FileNotFoundError"),
        _span("0000000000000001", "invoke_agent helper", 100, op="invoke_agent"),
        _span("0000000000000002", "execute_tool web.search", 200, op="execute_tool",
              tool="web.search", call_id="call_1", args='{"q": "pala", "n": 3}',
              result='{"hits": 3}'),
        _span("0000000000000004", "chat gpt-x", 150, op="chat"),
        # v1.41: the name only in the span name
        _span("0000000000000005", "execute_tool calc", 400, op="execute_tool"),
        # no name anywhere: dropped, with the reason
        _span("0000000000000006", "execute_tool", 500, op="execute_tool"),
    ]
    return {
        "resourceSpans": [{
            "resource": {"attributes": [_attr("service.name", "agent")]},
            "schemaUrl": "https://opentelemetry.io/schemas/1.37.0",
            "scopeSpans": [{
                "scope": {"name": "genai-instrumentation"},
                "schemaUrl": "https://opentelemetry.io/schemas/1.41.0",
                "spans": spans,
            }],
        }]
    }


def _protobuf(doc) -> bytes:
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceRequest,
    )

    req = ExportTraceServiceRequest()
    for rs in doc["resourceSpans"]:
        prs = req.resource_spans.add(schema_url=rs.get("schemaUrl", ""))
        for ss in rs["scopeSpans"]:
            pss = prs.scope_spans.add(schema_url=ss.get("schemaUrl", ""))
            for sp in ss["spans"]:
                ps = pss.spans.add(
                    trace_id=bytes.fromhex(sp["traceId"]), span_id=bytes.fromhex(sp["spanId"]),
                    name=sp["name"], start_time_unix_nano=int(sp["startTimeUnixNano"]),
                    end_time_unix_nano=int(sp["endTimeUnixNano"]),
                )
                ps.status.code = sp["status"]["code"]
                for a in sp["attributes"]:
                    kv = ps.attributes.add(key=a["key"])
                    if "intValue" in a["value"]:
                        kv.value.int_value = int(a["value"]["intValue"])
                    else:
                        kv.value.string_value = a["value"]["stringValue"]
    return req.SerializeToString()


# ── decoding ───────────────────────────────────────────────────────────────


def test_only_tool_spans_in_start_order_with_the_declared_version():
    batch = decode_otlp(json.dumps(_export()).encode(), "application/json")
    assert [s.tool_name for s in batch.tool_spans] == ["web.search", "fs.read", "calc"]
    assert [s.failed for s in batch.tool_spans] == [False, True, False]
    assert batch.tool_spans[1].error_type == "FileNotFoundError"
    # the scope's schemaUrl overrides the resource's
    assert {s.semconv for s in batch.tool_spans} == {"1.41.0"}
    assert batch.dropped == 1 and "without a tool name" in batch.dropped_reason


def test_protobuf_and_gzip_read_exactly_like_json():
    pytest.importorskip("opentelemetry.proto")
    from_json = decode_otlp(json.dumps(_export()).encode(), "application/json")
    from_pb = decode_otlp(_protobuf(_export()), "application/x-protobuf")
    gz = decode_otlp(gzip.compress(_protobuf(_export())), "application/x-protobuf", "gzip")
    assert from_json.tool_spans == from_pb.tool_spans == gz.tool_spans


def test_unstated_version_is_kept_and_marked():
    doc = _export()
    del doc["resourceSpans"][0]["schemaUrl"]
    del doc["resourceSpans"][0]["scopeSpans"][0]["schemaUrl"]
    batch = decode_otlp(json.dumps(doc).encode(), "application/json")
    assert {s.semconv for s in batch.tool_spans} == {"unstated"}  # D3: kept, marked


def test_bad_bodies_are_refused_by_name():
    with pytest.raises(ValueError, match="Content-Type"):
        decode_otlp(b"{}", "text/plain")
    with pytest.raises(ValueError, match="not JSON"):
        decode_otlp(b"{nope", "application/json")
    with pytest.raises(ValueError, match="not gzip"):
        decode_otlp(b"{}", "application/json", "gzip")


def test_protobuf_without_the_extra_is_refused_with_what_to_install(monkeypatch):
    import builtins
    from palimpsests.server.otel_traces import OtlpUnavailable

    real = builtins.__import__

    def no_proto(name, *a, **k):
        if name.startswith("opentelemetry.proto"):
            raise ImportError(name)
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_proto)
    with pytest.raises(OtlpUnavailable, match=r"\[serve\] extra"):
        decode_otlp(b"", "application/x-protobuf")


# ── the route ──────────────────────────────────────────────────────────────


def _app(tmp_path):
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.providers.native.audit import NativeAudit
    from palimpsests.server.openai_api import create_app

    log = tmp_path / "traces.pala"
    audit = NativeAudit(PalaWriter(log))
    app = create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [], audit=audit)
    return log, audit, TestClient(app)


def _pairs(log):
    from palimpsests.audit.reader import AuditReader

    with AuditReader.open(log) as r:
        assert r.verify().chain.chain_ok
        codes = {i.code for i in r.verify().advisory.items}
        recs = [d for d in r.records() if d.kind_name in ("TOOL_CALL", "TOOL_RESULT")]
    assert "reference_hash_mismatch" not in codes and "reference_unresolved" not in codes
    return recs


def test_the_route_records_one_pair_per_tool_span(tmp_path):
    log, audit, client = _app(tmp_path)
    r = client.post("/v1/traces", content=json.dumps(_export()),
                    headers={"Content-Type": "application/json"})
    assert r.status_code == 200
    assert r.json() == {"partialSuccess": {"rejectedSpans": "1", "errorMessage": (
        "execute_tool span without a tool name (gen_ai.tool.name or the span name "
        "'execute_tool <name>'): nothing to record a call of")}}
    audit.writer.close()
    recs = _pairs(log)
    calls = [d for d in recs if d.kind_name == "TOOL_CALL"]
    results = [d for d in recs if d.kind_name == "TOOL_RESULT"]
    assert [c.detail for c in calls][0] == "otel execute_tool; semconv 1.41.0"
    assert "error.type FileNotFoundError" in calls[1].detail
    assert [r.outcome for r in results] == [OUTCOME_OK, OUTCOME_ERROR, OUTCOME_OK]
    assert {d.source_name for d in recs} == {"reported-by-client"}


def test_digests_are_canonical_and_content_never_lands(tmp_path):
    log, audit, client = _app(tmp_path)
    client.post("/v1/traces", content=json.dumps(_export()),
                headers={"Content-Type": "application/json"})
    audit.writer.close()
    call = next(d for d in _pairs(log) if d.kind_name == "TOOL_CALL")
    digest = dict(call.body_tlvs)[0x000D]
    # the same arguments, serialised differently, give the same digest (D4)
    assert digest == canonical_tool_args_digest({"n": 3, "q": "pala"})
    assert b"pala" not in log.read_bytes()  # only digests reach the chain


def test_a_retried_batch_is_not_recorded_twice(tmp_path):
    log, audit, client = _app(tmp_path)
    body = json.dumps(_export())
    for _ in range(2):  # an exporter retrying a batch it thinks failed
        client.post("/v1/traces", content=body, headers={"Content-Type": "application/json"})
    audit.writer.close()
    assert len([d for d in _pairs(log) if d.kind_name == "TOOL_CALL"]) == 3


def test_protobuf_in_protobuf_out(tmp_path):
    pytest.importorskip("opentelemetry.proto")
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
        ExportTraceServiceResponse,
    )

    log, audit, client = _app(tmp_path)
    r = client.post("/v1/traces", content=gzip.compress(_protobuf(_export())),
                    headers={"Content-Type": "application/x-protobuf",
                             "Content-Encoding": "gzip"})
    assert r.status_code == 200 and r.headers["content-type"] == "application/x-protobuf"
    reply = ExportTraceServiceResponse()
    reply.ParseFromString(r.content)
    assert reply.partial_success.rejected_spans == 1
    audit.writer.close()
    assert len([d for d in _pairs(log) if d.kind_name == "TOOL_RESULT"]) == 3


def test_status_codes_say_what_is_wrong(tmp_path):
    from palimpsests.server.openai_api import create_app

    _, audit, client = _app(tmp_path)
    assert client.post("/v1/traces", content=b"x",
                       headers={"Content-Type": "text/plain"}).status_code == 415
    assert client.post("/v1/traces", content=b"{bad",
                       headers={"Content-Type": "application/json"}).status_code == 400
    audit.writer.close()
    bare = TestClient(create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: []))
    assert bare.post("/v1/traces", content=b"{}",
                     headers={"Content-Type": "application/json"}).status_code == 503


def test_the_traces_route_sits_behind_the_bearer(tmp_path):
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.providers.native.audit import NativeAudit
    from palimpsests.server.openai_api import create_app

    audit = NativeAudit(PalaWriter(tmp_path / "a.pala"))
    client = TestClient(create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [],
                                   audit=audit, api_key="k"))
    hdr = {"Content-Type": "application/json"}
    assert client.post("/v1/traces", content=b"{}", headers=hdr).status_code == 401
    assert client.post("/v1/traces", content=b"{}",
                       headers={**hdr, "Authorization": "Bearer k"}).status_code == 200
    audit.writer.close()


# ── the seq a result binds to ──────────────────────────────────────────────


def test_a_call_seq_is_the_calls_own_even_when_another_write_interleaves(tmp_path):
    """Another route of the serve writes between the call and the moment its
    seq is known: the seq must still be the call's, or the result binds to a
    record that is not its call."""
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.audit.reader import AuditReader
    from palimpsests.providers.native.audit import NativeAudit

    w = PalaWriter(tmp_path / "race.pala")
    w.genesis()
    audit = NativeAudit(w)
    real = w.tool_call

    def call_then_someone_else_writes(*a, **k):
        out = real(*a, **k)
        w.prefix_warm(token_count=1)  # the other thread's record
        return out

    w.tool_call = call_then_someone_else_writes
    seq, call_hash = audit.tool_called("t", None, None)
    w.close()
    with AuditReader.open(tmp_path / "race.pala") as r:
        rec = r.record_by_seq(seq)
    assert rec.kind_name == "TOOL_CALL" and rec.record_hash == call_hash


def test_an_escalation_refers_to_its_own_refusal_even_when_another_write_interleaves(tmp_path):
    """The same race on the guard path: an INCIDENT_CANDIDATE names the
    refusal that tipped it over, by seq and hash — both must be the
    refusal's, whatever was written in between."""
    from palimpsests.audit.pala_writer import PalaWriter
    from palimpsests.audit.reader import AuditReader
    from palimpsests.providers.native.audit import NativeAudit

    w = PalaWriter(tmp_path / "guard.pala")
    w.genesis()
    audit = NativeAudit(w, guard_escalation_threshold=1)
    real = w.guard_state_reject

    def refuse_then_someone_else_writes(*a, **k):
        out = real(*a, **k)
        w.prefix_warm(token_count=1)
        return out

    w.guard_state_reject = refuse_then_someone_else_writes
    audit.state_rejected("bad blob", None)
    w.close()
    with AuditReader.open(tmp_path / "guard.pala") as r:
        codes = {i.code for i in r.verify().advisory.items}
        kinds = [d.kind_name for d in r.records()]
    assert "INCIDENT_CANDIDATE" in kinds
    assert "reference_hash_mismatch" not in codes and "reference_unresolved" not in codes
