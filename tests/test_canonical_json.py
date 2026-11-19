# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""RFC 8785 (JCS), against the RFC's own samples.

The digests of tool arguments and of the engine's configuration are taken
over this form. They were taken over what ``json.dumps`` printed — and for
the configuration over ``str()`` of each value — which another language
cannot reproduce for a float, and for a nested configuration not at all.
"""
from __future__ import annotations

import json
import pytest
import random
import struct
from hashlib import sha256
from palimpsests.audit.canonical_json import canonical_json
from palimpsests.audit.pala_writer import (
    canonical_config_digest,
    canonical_tool_args_digest,
    canonical_tool_names_digest,
)

# RFC 8785, Appendix B — "Number Serialization Samples".
APPENDIX_B = [
    ("0000000000000000", "0"),
    ("8000000000000000", "0"),
    ("0000000000000001", "5e-324"),
    ("8000000000000001", "-5e-324"),
    ("7fefffffffffffff", "1.7976931348623157e+308"),
    ("ffefffffffffffff", "-1.7976931348623157e+308"),
    ("4340000000000000", "9007199254740992"),
    ("c340000000000000", "-9007199254740992"),
    ("4430000000000000", "295147905179352830000"),
    ("44b52d02c7e14af5", "9.999999999999997e+22"),
    ("44b52d02c7e14af6", "1e+23"),
    ("44b52d02c7e14af7", "1.0000000000000001e+23"),
    ("444b1ae4d6e2ef4e", "999999999999999700000"),
    ("444b1ae4d6e2ef4f", "999999999999999900000"),
    ("444b1ae4d6e2ef50", "1e+21"),
    ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
    ("3eb0c6f7a0b5ed8d", "0.000001"),
    ("41b3de4355555553", "333333333.3333332"),
    ("41b3de4355555554", "333333333.33333325"),
    ("41b3de4355555555", "333333333.3333333"),
    ("41b3de4355555556", "333333333.3333334"),
    ("41b3de4355555557", "333333333.33333343"),
    ("becbf647612f3696", "-0.0000033333333333333333"),
    ("43143ff3c1cb0959", "1424953923781206.2"),
]


@pytest.mark.parametrize(("ieee", "expected"), APPENDIX_B)
def test_numbers_are_written_as_the_rfc_samples(ieee, expected):
    (value,) = struct.unpack(">d", bytes.fromhex(ieee))
    assert canonical_json(value) == expected.encode()


@pytest.mark.parametrize("ieee", ["7fffffffffffffff", "7ff0000000000000", "fff0000000000000"])
def test_nan_and_the_infinities_are_refused(ieee):
    (value,) = struct.unpack(">d", bytes.fromhex(ieee))
    with pytest.raises(ValueError, match="no canonical JSON form"):
        canonical_json(value)


@pytest.mark.parametrize(("value", "expected"), [
    (1.0, "1"), (-1.0, "-1"), (1.5, "1.5"), (100.0, "100"), (1e20, "100000000000000000000"),
    (1e21, "1e+21"), (1e-6, "0.000001"), (1e-7, "1e-7"), (123e-20, "1.23e-18"),
    (0.1, "0.1"), (4.5, "4.5"), (2 ** 53, "9007199254740992"), (7, "7"), (-0.0, "0"),
    (2 ** 63, "9223372036854776000"),  # an integer beyond 2**53 is its nearest double
])
def test_the_layout_rules_of_ecmascript(value, expected):
    assert canonical_json(value) == expected.encode()


def test_every_number_reads_back_to_the_same_double():
    rng = random.Random(8785)
    for _ in range(20000):
        (x,) = struct.unpack(">d", rng.getrandbits(64).to_bytes(8, "big"))
        if x != x or x in (float("inf"), float("-inf")):
            continue
        text = canonical_json(x).decode()
        assert float(text) == x
        assert "E" not in text and not text.startswith(".") and not text.endswith(".")


EURO, OUML, CTRL80, DALET, GRIN = chr(0x20AC), chr(0xF6), chr(0x80), chr(0xFB33), chr(0x1F600)
BS, QUOTE = chr(0x5C), chr(0x22)


def test_keys_are_sorted_by_utf16_code_unit():
    """RFC 8785 section 3.2.3, its own sample. The emoji is a surrogate pair
    (D83D ...), so it sorts before U+FB33 - by code point it would sort after."""
    sample = {EURO: "Euro Sign", chr(0x0D): "Carriage Return",
              DALET: "Hebrew Letter Dalet With Dagesh", "1": "One",
              GRIN: "Emoji: Grinning Face", CTRL80: "Control",
              OUML: "Latin Small Letter O With Diaeresis"}
    order = list(json.loads(canonical_json(sample)).values())
    assert order == ["Carriage Return", "One", "Control",
                     "Latin Small Letter O With Diaeresis", "Euro Sign",
                     "Emoji: Grinning Face", "Hebrew Letter Dalet With Dagesh"]
    by_code_point = [sample[k] for k in sorted(sample)]
    assert by_code_point != order and by_code_point[-1] == "Emoji: Grinning Face"


def test_strings_are_escaped_as_the_rfc_says():
    """RFC 8785 section 3.2.2.2."""
    short = "".join(chr(c) for c in (0x08, 0x09, 0x0A, 0x0C, 0x0D))
    assert canonical_json(short) == (QUOTE + BS + "b" + BS + "t" + BS + "n" + BS + "f"
                                     + BS + "r" + QUOTE).encode()
    # other control characters: lowercase hexadecimal; U+007F is not one of them
    assert canonical_json(chr(0x00) + chr(0x0F) + chr(0x1F) + chr(0x7F)) == (
        QUOTE + BS + "u0000" + BS + "u000f" + BS + "u001f" + chr(0x7F) + QUOTE).encode()
    # the quote and the backslash, and nothing else
    assert canonical_json(QUOTE + BS + "/<" + chr(0x2028)) == (
        QUOTE + BS + QUOTE + BS + BS + "/<" + chr(0x2028) + QUOTE).encode("utf-8")
    assert canonical_json(OUML + EURO + GRIN) == (QUOTE + OUML + EURO + GRIN + QUOTE).encode(
        "utf-8")
    for lone in (0xD800, 0xDBFF, 0xDC00, 0xDFFF):
        with pytest.raises(ValueError, match="lone surrogate"):
            canonical_json("a" + chr(lone))
        with pytest.raises(ValueError, match="lone surrogate"):
            canonical_json({chr(lone): 1})


def test_the_rfc_example_object():
    """RFC 8785 section 3.2.2: the sample input and its canonical output.
    The string is: euro sign, $, U+000F, line feed, A'B, a quote, two
    backslashes, a quote, a slash."""
    string = EURO + "$" + chr(0x0F) + chr(0x0A) + "A'B" + QUOTE + BS + BS + QUOTE + "/"
    value = {"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
             "string": string,
             "literals": [None, True, False]}
    expected_string = (QUOTE + EURO + "$" + BS + "u000f" + BS + "n" + "A'B" + BS + QUOTE
                       + BS + BS + BS + BS + BS + QUOTE + "/" + QUOTE)
    assert canonical_json(value) == (
        '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
        '"string":' + expected_string + "}").encode("utf-8")


def test_what_is_not_a_json_value_is_refused():
    for value in ({1: "a"}, {None: 1}, b"bytes", {"a": {1, 2}}, object(), {"a": 1j}):
        with pytest.raises(TypeError):
            canonical_json(value)
    assert canonical_json({"a": (1, 2), "b": []}) == b'{"a":[1,2],"b":[]}'
    assert canonical_json(True) == b"true" and canonical_json(1) == b"1"


def test_where_it_is_the_bytes_the_serializer_printed_before():
    """For a value with no float and no key outside the BMP — which is what
    tool arguments are, nearly always — the canonical form is the bytes
    ``json.dumps`` printed, so the digests on existing chains still
    reproduce."""
    rng = random.Random(1)

    def value(depth=0):
        kind = rng.choice("sibnlo" if depth < 3 else "sibn")
        if kind == "s":
            return "".join(rng.choice("aé€\n\"\\ \t/") for _ in range(rng.randrange(6)))
        if kind == "i":
            return rng.randrange(-10**9, 10**9)
        if kind == "b":
            return rng.choice([True, False])
        if kind == "n":
            return None
        if kind == "l":
            return [value(depth + 1) for _ in range(rng.randrange(4))]
        return {"".join(rng.choice("abcé€Z_1") for _ in range(rng.randrange(1, 5))):
                value(depth + 1) for _ in range(rng.randrange(4))}

    for _ in range(3000):
        v = value()
        assert canonical_json(v) == json.dumps(
            v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# -- the digests taken over it ------------------------------------------------

def test_tool_arguments_are_digested_in_the_canonical_form():
    args = {"b": 1.0, "a": [1e21, OUML], GRIN: 0, DALET: 0}
    canonical = ('{"a":[1e+21,"' + OUML + '"],"b":1,"' + GRIN + '":0,"' + DALET + '":0}')
    assert canonical_tool_args_digest(args) == sha256(canonical.encode("utf-8")).digest()
    # the same value however the client wrote the number
    assert canonical_tool_args_digest(json.loads('{"t": 1.0}')) == \
        canonical_tool_args_digest(json.loads('{"t": 1}')) == \
        canonical_tool_args_digest(json.loads('{"t": 10e-1}'))
    # bytes are still taken as already canonical
    assert canonical_tool_args_digest(b'{"x": 1.0}') == sha256(b'{"x": 1.0}').digest()
    assert canonical_tool_args_digest("a string result") == sha256(b'"a string result"').digest()


def test_the_configuration_is_digested_as_one_canonical_object():
    config = {"n_ctx": 4096, "kv": "disk", "flash_attn": True, "temp": 0.7,
              "sampling": {"top_p": 1.0, "stop": ["\n"]}}
    expected = sha256(
        b'{"flash_attn":true,"kv":"disk","n_ctx":4096,'
        b'"sampling":{"stop":["\\n"],"top_p":1},"temp":0.7}').digest()
    assert canonical_config_digest(config) == expected
    assert canonical_config_digest(dict(reversed(config.items()))) == expected
    nested = {**config, "sampling": {"stop": ["\n"], "top_p": 1.0}}
    assert canonical_config_digest(nested) == expected  # nested order does not matter
    assert canonical_config_digest({**config, "temp": 0.8}) != expected
    with pytest.raises(TypeError):
        canonical_config_digest({"path": object()})


def test_the_offered_names_digest_did_not_move():
    """Sorted names as a JSON array (r4). The published vector pins it."""
    names = ["web.search", "fs.read", "é", "a\"b"]
    assert canonical_tool_names_digest(names) == sha256(json.dumps(
        sorted(names), separators=(",", ":"), ensure_ascii=False).encode("utf-8")).digest()


# -- a payload with no canonical form does not cost the record ---------------

def test_a_call_whose_arguments_have_no_canonical_form_is_still_recorded(tmp_path):
    """A lenient JSON parser lets NaN through, and an escaped lone surrogate.
    The call happened; it is recorded, without a digest."""
    fastapi = pytest.importorskip("fastapi")  # noqa: F841
    from fastapi.testclient import TestClient
    from palimpsests.audit.pala import iter_records
    from palimpsests.audit.pala.codec import decode_tlvs
    from palimpsests.audit.pala_writer import PalaWriter, _tool_payload_digest
    from palimpsests.audit.profiles.inference import EVT_PAYLOAD_DIGEST
    from palimpsests.providers.native.audit import NativeAudit
    from palimpsests.server.openai_api import create_app

    assert _tool_payload_digest({"x": float("nan")}) is None
    assert _tool_payload_digest({"x": float("inf")}) is None
    assert _tool_payload_digest("a" + chr(0xD800)) is None
    assert _tool_payload_digest({"x": 1.0}) == canonical_tool_args_digest({"x": 1})
    with pytest.raises(ValueError):
        canonical_tool_args_digest({"x": float("nan")})

    log = tmp_path / "s.pala"
    audit = NativeAudit(PalaWriter(log))
    client = TestClient(create_app(chat_fn=lambda **k: iter(()), models_fn=lambda: [],
                                   audit=audit))
    body = ('{"events": [{"type": "tool_call", "id": "a", "name": "t", '
            '"arguments": {"x": NaN}},'
            ' {"type": "tool_call", "id": "b", "name": "t", "arguments": {"x": 2}}]}')
    r = client.post("/v1/pala/events", content=body,
                    headers={"content-type": "application/json"})
    hook = client.post("/v1/pala/hooks/claude", content=(
        '{"hook_event_name": "PreToolUse", "tool_name": "T", "tool_use_id": "h", '
        '"tool_input": {"x": Infinity}}'), headers={"content-type": "application/json"})
    audit.writer.close()
    assert r.status_code == 200 and all("error" not in x for x in r.json()["results"])
    assert (hook.status_code, hook.json()) == (200, {})
    calls = [dict(decode_tlvs(b)) for _h, b in iter_records(log.read_bytes()) if b]
    calls = [t for t in calls if EVT_PAYLOAD_DIGEST in t or 0x000C in t]  # tool records
    assert [EVT_PAYLOAD_DIGEST in t for t in calls] == [False, True, False]
