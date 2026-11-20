# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The refusal vectors are what the verifier refuses, code for code.

``docs/interop/scitt-statement-refusal-vectors.json`` gives a refused
statement for every code of ``STATEMENT_REFUSAL_CODES``, for comparison by
another verifier. Each case is refused here with the code it names, every
code has a case, and the file regenerates byte for byte from the three
published statement vectors, which it leaves untouched.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pytest
import shutil
import subprocess
import sys
from pathlib import Path

pytest.importorskip("cbor2")
pytest.importorskip("cryptography")
import cbor2  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519  # noqa: E402
from palimpsests.audit.pala import scitt, vectors  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
INTEROP = REPO / "docs" / "interop"
VECTOR = INTEROP / "scitt-statement-refusal-vectors.json"
#: The 64 cases published before the one-encoding rule, as canonical JSON.
FIRST_64_SHA256 = "7b93c2106a7b2aa2dcba8f6f670ce793ad3a815ef27d023960a0040df2c97c21"
INPUTS = ("scitt-statement-vector.json", "scitt-statement-vector-v3.json",
          "scitt-statement-vector-alg19.json")


@pytest.fixture(scope="module")
def doc():
    return json.loads(VECTOR.read_text(encoding="utf-8"))


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _key(jwk: dict):
    if jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(_unb64(jwk["x"]))
    if jwk["kty"] == "OKP" and jwk["crv"] == "Ed448":
        return ed448.Ed448PublicKey.from_public_bytes(_unb64(jwk["x"]))
    curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1()}[jwk["crv"]]
    x, y = (int.from_bytes(_unb64(jwk[c]), "big") for c in ("x", "y"))
    return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()


class _Chain:
    """The subject chain as the verifier reads one: record headers in seq
    order. They are the headers of the published core vectors, so the root
    comes from real records and nothing in the package is replaced."""

    def __init__(self, headers: list[bytes]) -> None:
        self._headers = headers


@pytest.fixture
def chain(doc):
    core = vectors.load("core")["records"]
    assert [r["record_hash"] for r in core] == doc["subject_chain"]["record_hashes_hex"]
    return _Chain([bytes.fromhex(r["header_hex"]) for r in core])


def test_every_case_is_refused_with_its_code(doc, chain):
    for case in doc["cases"]:
        message = bytes.fromhex(case["statement_hex"])
        assert hashlib.sha256(message).hexdigest() == case["statement_sha256"], case["id"]
        v = case["verify_with"]
        with pytest.raises(scitt.StatementRefused) as info:
            scitt.verify_statement(
                message, _key(doc["keys"][v["key"]]), bytes.fromhex(v["expected_head_hex"]),
                reader=chain if v["chain"] else None)
        assert info.value.code == case["code"], (case["id"], str(info.value))


def test_every_code_has_a_case_and_no_other(doc):
    codes = {c["code"] for c in doc["cases"]}
    assert codes == set(scitt.STATEMENT_REFUSAL_CODES) == set(doc["codes"])
    assert len({c["id"] for c in doc["cases"]}) == len(doc["cases"]) == doc["counts"]["cases"]
    for code in codes:
        assert doc["counts"][code] == sum(c["code"] == code for c in doc["cases"])


def test_the_file_carries_its_subject_chain(doc):
    """The root cases need the chain; the file gives it and does not send
    the reader to another one."""
    v3 = json.loads((INTEROP / INPUTS[1]).read_text(encoding="utf-8"))
    chain = doc["subject_chain"]
    assert chain["record_hashes_hex"] == v3["subject_chain"]["record_hashes_hex"]
    assert chain["records"] == len(chain["record_hashes_hex"]) == 12
    assert sum(c["verify_with"]["chain"] == "subject_chain" for c in doc["cases"]) == 3


def test_every_algorithm_reaches_the_signature_check(doc):
    """A refusal by key type stops before the signature. Each of -7, -8 and
    -19 also has a case that gets as far as the signature and fails there."""
    reached = set()
    for case in doc["cases"]:
        if case["code"] == "signature_invalid":
            protected = cbor2.loads(bytes.fromhex(case["statement_hex"])).value[0]
            reached.add(cbor2.loads(protected)[1])
    assert reached == {scitt.ALG_ES256, scitt.ALG_EDDSA, scitt.ALG_ED25519}


def test_a_case_without_a_base_is_not_a_statement(doc):
    no_base = [c for c in doc["cases"] if c["base"] is None]
    assert len(no_base) == 4 and {c["code"] for c in no_base} == {"not_cose_sign1"}


def test_the_cases_published_before_the_encoding_rule_are_as_they_were(doc):
    """The one-encoding rule (0.15) added two codes and nineteen cases at
    the end. The 64 cases another verifier may already have been run
    against keep their ids, their bytes and their codes: a check that
    names what is wrong is reached before the general one."""
    assert len(doc["cases"]) == 83
    first = doc["cases"][:64]
    assert not {c["code"] for c in first} & {
        "non_deterministic_encoding", "unprotected_header_malformed"}
    digest = hashlib.sha256(json.dumps(first, sort_keys=True).encode()).hexdigest()
    assert digest == FIRST_64_SHA256
    added = doc["cases"][64:]
    assert {c["code"] for c in added} == {
        "non_deterministic_encoding", "unprotected_header_malformed"}
    assert doc["counts"]["non_deterministic_encoding"] == 12
    assert doc["counts"]["unprotected_header_malformed"] == 7
    assert doc["counts"]["cases"] == 83
    assert all(c["base"] in doc["bases"] for c in doc["cases"] if c["base"] is not None)


def test_the_bases_are_the_published_statements_and_verify(doc):
    sources = {n: json.loads((INTEROP / n).read_text(encoding="utf-8")) for n in INPUTS}
    published = {
        "v2": sources[INPUTS[0]]["expected"]["statement_hex"],
        "v3": sources[INPUTS[1]]["statements"]["later"]["expected"]["statement_hex"],
        "v2-alg19": sources[INPUTS[2]]["statements"]["v2"]["expected"]["statement_hex"],
    }
    test_key = _key(doc["keys"]["ed25519-test"])
    for name, base in doc["bases"].items():
        message = bytes.fromhex(published[name])
        assert hashlib.sha256(message).hexdigest() == base["statement_sha256"]
        scitt.verify_statement(message, test_key, bytes.fromhex(base["expected_head_hex"]))


def test_the_file_regenerates_byte_for_byte_and_leaves_its_inputs(tmp_path):
    work = tmp_path / "docs" / "interop"
    work.mkdir(parents=True)
    for name in (*INPUTS, "gen_scitt_statement_refusal_vectors.py"):
        shutil.copy(INTEROP / name, work / name)
    proc = subprocess.run(
        [sys.executable, str(work / "gen_scitt_statement_refusal_vectors.py")],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert (work / VECTOR.name).read_bytes() == VECTOR.read_bytes()
    assert all((work / n).read_bytes() == (INTEROP / n).read_bytes() for n in INPUTS)
