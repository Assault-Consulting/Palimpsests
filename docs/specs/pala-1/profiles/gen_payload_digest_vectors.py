# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Generate the payload digest vectors of the inference profile (§11).

A tool's arguments or result, and the engine's configuration, are
digested as RFC 8785 canonical JSON, UTF-8, SHA-256. These vectors let
another implementation, in another language, check that it computes the
same digests - and, as importantly, that it computes *none* where this
profile says a value has no canonical form.

Each case gives the value as JSON **text**, because two of the rules are
about the text: a repeated key and the exact digits of an integer are
gone once a parser has returned a value. An implementation reads the
text with a parser that keeps both, and either produces the canonical
bytes and their digest or produces no digest, for the reason given.

Deep cases are given as a recipe (``nesting``) rather than as text, so
that reading this file does not itself need a deep parser.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))

from palimpsests.audit.canonical_json import MAX_DEPTH, canonical_json, loads  # noqa: E402

OUT = HERE / "payload-digest-vectors.json"
BS = chr(92)  # a backslash, written this way so no tool decodes the escapes below


def nested(depth: int, kind: str) -> object:
    value: object = [] if kind == "array" else 0
    for _ in range(depth - 1 if kind == "array" else depth):
        value = [value] if kind == "array" else {"k": value}
    return value


# (id, JSON text, note)
DIGESTED = [
    ("empty-object", "{}", "an empty arguments object"),
    ("key-order", '{"b": 1, "a": 2}', "keys are sorted"),
    ("whitespace", '{ "a" : [ 1 , 2 ] }', "no whitespace survives"),
    ("float-is-integer", '{"n": 1.0}', "1.0 is written 1"),
    ("exponent", '{"n": 1e21}', "written 1e+21"),
    ("small-exponent", '{"n": 1e-7}', "written 1e-7"),
    ("fraction-kept", '{"n": 0.000001}', "0.000001 is not exponential"),
    ("minus-zero", '{"n": -0.0}', "minus zero is written 0"),
    ("largest-safe-integer", '{"n": 9007199254740991}', "2^53 - 1: the last integer digested"),
    ("smallest-safe-integer", '{"n": -9007199254740991}', "-(2^53 - 1)"),
    ("large-as-a-double", '{"n": 9007199254740992.0}',
     "written with a fraction, so a double as it stands: digested, as 9007199254740992"),
    ("large-with-exponent", '{"n": 1e20}', "a double: written 100000000000000000000"),
    ("string-escapes", '{"s": "a' + BS + 'n' + BS + 't' + BS + '"' + BS + BS + BS + 'u0001"}',
     "short escapes kept; U+0001 as a lowercase " + BS + "u0001"),
    ("non-ascii", '{"s": "' + chr(0xE9) + chr(0x6F22) + '"}', "written as UTF-8, not escaped"),
    ("escaped-non-ascii", '{"s": "' + BS + 'u00e9"}', "the same string as the raw character"),
    ("astral-key-order", '{"' + chr(0x1F600) + '": 1, "' + chr(0xFFFF) + '": 2}',
     "keys sort by UTF-16 code unit: the surrogate pair of U+1F600 before U+FFFF"),
    ("nested", '{"a": {"c": [true, false, null], "b": "x"}}', "sorted at every level"),
    ("array-order-kept", "[3, 1, 2]", "an array is not sorted"),
    ("a-string", '"just text"', "a value need not be an object"),
    ("same-keys-in-two-objects", '[{"a": 1}, {"a": 2}]',
     "a key repeated across two objects is not a repeated key"),
]

# (id, JSON text, reason code, note)
NO_DIGEST = [
    ("integer-2^53", '{"n": 9007199254740992}', "integer_out_of_range",
     "2^53: as a double it is also 2^53 + 1"),
    ("integer-2^53+1", '{"n": 9007199254740993}', "integer_out_of_range",
     "would be the same bytes as 2^53"),
    ("integer-negative", '{"n": -9007199254740992}', "integer_out_of_range", "-(2^53)"),
    ("integer-20-digits", '{"id": 12345678901234567890}', "integer_out_of_range",
     "an identifier this large belongs in a string"),
    ("integer-in-array", "[1, [2, 18446744073709551615]]", "integer_out_of_range",
     "anywhere in the value"),
    ("repeated-key", '{"a": 1, "a": 2}', "repeated_key", "first-wins and last-wins disagree"),
    ("repeated-key-same-value", '{"a": 1, "a": 1}', "repeated_key",
     "refused for the repetition, whatever the values"),
    ("repeated-key-nested", '{"x": {"y": [{"a": 1, "a": 2}]}}', "repeated_key",
     "anywhere in the value"),
    ("repeated-key-escaped", '{"a": 1, "' + BS + 'u0061": 2}', "repeated_key",
     "the same key written two ways is the same key"),
    ("lone-surrogate", '{"s": "' + BS + 'ud800"}', "not_unicode",
     "an unpaired surrogate is not a Unicode string"),
    ("lone-surrogate-key", '{"' + BS + 'udc00": 1}', "not_unicode", "in a key as well"),
    ("number-overflow", '{"n": 1e400}', "not_finite", "reads as an infinity"),
    ("nan-token", '{"n": NaN}', "not_finite",
     "not JSON at all (RFC 8259); a lenient parser accepts it, a strict one rejects the text - "
     "either way there is no digest"),
]


def digested(case_id: str, text: str, note: str) -> dict:
    canonical = canonical_json(loads(text))
    return {"id": case_id, "json_text": text, "note": note,
            "canonical_utf8_hex": canonical.hex(),
            "sha256": hashlib.sha256(canonical).hexdigest()}


def refused(case_id: str, text: str, reason: str, note: str) -> dict:
    try:
        canonical_json(loads(text))
    except ValueError:
        return {"id": case_id, "json_text": text, "digest": None, "reason": reason,
                "note": note}
    raise AssertionError(f"{case_id}: digested")


cases = [digested(*c) for c in DIGESTED] + [refused(*c) for c in NO_DIGEST]

deep = []
for kind in ("array", "object"):
    canonical = canonical_json(nested(MAX_DEPTH, kind))
    deep.append({"id": f"depth-{MAX_DEPTH}-{kind}", "nesting": {"depth": MAX_DEPTH, "kind": kind},
                 "canonical_utf8_length": len(canonical),
                 "sha256": hashlib.sha256(canonical).hexdigest()})
    try:
        canonical_json(nested(MAX_DEPTH + 1, kind))
    except ValueError:
        deep.append({"id": f"depth-{MAX_DEPTH + 1}-{kind}",
                     "nesting": {"depth": MAX_DEPTH + 1, "kind": kind},
                     "digest": None, "reason": "nested_too_deep"})
    else:
        raise AssertionError("depth")

doc = {
    "format": "pala-1 inference profile payload digest vectors",
    "profile_section": "docs/specs/pala-1/profiles/inference.md, section 11",
    "purpose": (
        "EVT_PAYLOAD_DIGEST and ORIGIN_CONFIG_DIGEST are SHA-256 over RFC 8785 canonical "
        "JSON, UTF-8. These cases let another implementation check that it computes the "
        "same digest - and none where the profile says a value has no canonical form."),
    "how_to_read": [
        "json_text is the value as JSON text. Read it with a parser that keeps a repeated "
        "key in sight and reads an integer exactly: both are lost by a parser that "
        "returns a map and a double.",
        "A case with sha256 is digested: canonical_utf8_hex is the canonical form and "
        "sha256 its digest.",
        "A case with digest null has no canonical form. The emitter records the event "
        "without EVT_PAYLOAD_DIGEST; it does not substitute a form of its own.",
        "A deep case gives a recipe instead of text: 'array' at depth n is n arrays, each "
        "holding the next, the innermost empty; 'object' at depth n is n objects, each "
        "holding the next under the key k, the innermost holding 0.",
    ],
    "reasons": {
        "integer_out_of_range": "an integer beyond +-(2^53 - 1), written without a fraction "
                                "or an exponent (RFC 7493 section 2.2)",
        "repeated_key": "an object gives a key more than once (RFC 7493 section 2.3)",
        "not_unicode": "a string holds an unpaired surrogate (RFC 8785 section 3.2.2.2)",
        "not_finite": "NaN or an infinity (RFC 8785 section 3.2.2.3)",
        "nested_too_deep": f"more than {MAX_DEPTH} arrays and objects, one inside another",
    },
    "reasons_note": (
        "The reason is for the reader of this file. An emitter does not record it: the "
        "event carries no digest, and that is all the chain says."),
    "counts": {"digested": len(DIGESTED) + 2, "no_digest": len(NO_DIGEST) + 2},
    "cases": cases,
    "deep_cases": deep,
}
OUT.write_text(json.dumps(doc, indent=2, ensure_ascii=True) + "\n", encoding="utf-8",
               newline="\n")
print(f"wrote {OUT.name}: {len(cases)} cases, {len(deep)} deep")
