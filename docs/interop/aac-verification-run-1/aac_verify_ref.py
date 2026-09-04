# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""aac_verify_ref.py — an independent Class-1 verifier for Agent Action
Capsules, written from the text of draft-mih-scitt-agent-action-capsule-02
(6 July 2026) and nothing else.

Discipline: the reference implementation's source was NOT read. Every
rule below cites the section of the -02 text it comes from. Where the
text is silent, the choice is marked `[interpretation]` and listed in
the run record. Standard library only, plus nothing — SHA-256 and JSON
are all the payload layer needs; COSE/receipt verification is
"by reference" (§6) and out of scope for this verifier.

Result shape (§6: "a structured result, never throw; a single ok boolean;
findings in a fixed order"):
    {ok, derived: {attestation_mode, effect_mode, ledger_mode},
     capsule_id_recomputed, findings: [{check, severity, note}]}
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SPEC = "draft-mih-scitt-agent-action-capsule-02"
FORMAT_VERSION = "2"  # §5.1: "The value defined by this profile version is '2'"
SAFE_INT = 2**53 - 1  # [interpretation] RFC 8785 numbers are IEEE doubles (I-JSON)

HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_Z = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
)  # §5.1 timestamp: RFC 3339 UTC with "Z" suffix

# §5.5.2: classes that "by its kind never dispatch"; resolved by the
# pairing rule; epoch_boundary per §12.1 item 1 (REQUIRES not_applicable).
NEVER_DISPATCH = {
    "blocked",
    "hitl_dispatched",
    "denied",
    "engine_failure",
    "deferred",
    "needs_decision",
    "expired",
    "escalated",
    "resolved",
    "epoch_boundary",
}
# §12.1 seeded registries (unknown values → informational, never reject)
REG_VERDICT_CLASS = NEVER_DISPATCH | {"executed", "timeout", "errored"}
REG_DECISION = {"accept", "reject", "needs_input", "deferred"}
REG_EFFECT_TYPE = {"write_order", "send_payment"}
REG_IRREVERSIBILITY = {
    "two_way",
    "one_way_recoverable",
    "one_way_consequential",
    "one_way_terminal",
}
REG_ATTESTATION = {"gate_executed", "runtime_claimed"}
REG_RELATION = {"supersedes", "epoch_opens"}
APPROVER = {"human", "policy"}  # §5.5: closed enum, fixed by the spec
EFFECT_STATUS = {"planned", "dispatched", "confirmed", "failed", "reverted"}
LEDGER_RANK = {"standalone": 0, "chained": 1, "anchored": 2}  # §5.4 order
EFFECT_RANK = {"not_applicable": 0, "dispatched_unconfirmed": 1, "confirmed": 2}
ATTEST_RANK = {"self_attested": 0, "anchored": 1}
RANKS = {"ledger_mode": LEDGER_RANK, "effect_mode": EFFECT_RANK, "attestation_mode": ATTEST_RANK}


class DigestError(ValueError):
    """A value that cannot be digested reproducibly (§5.1 floats; §6 check 1)."""


# ─── JSON-DIGEST (§2): HEX(SHA-256(JCS(normalize(v)))) ─────────────────


def normalize(v: Any) -> Any:
    """§2: remove members whose value is null, [] or {} — bottom-up."""
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            nx = normalize(x)
            if nx is None or nx == [] or nx == {}:
                continue
            out[k] = nx
        return out
    if isinstance(v, list):
        return [normalize(x) for x in v]
    return v


def _jcs_string(s: str) -> str:
    # RFC 8785 §3.2.2.2: escape " \ and the C0 controls; named shortcuts
    # for \b \t \n \f \r; everything else literal (solidus not escaped;
    # non-BMP passes through).
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(s: str) -> list[int]:
    # RFC 8785 §3.2.3: sort property names by UTF-16 code units
    return [
        int.from_bytes(s.encode("utf-16-be")[i : i + 2], "big")
        for i in range(0, len(s.encode("utf-16-be")), 2)
    ]


def jcs(v: Any) -> str:
    """RFC 8785 serialization, restricted to what this profile allows:
    strings, booleans, null, integers within the IEEE-754 safe range,
    arrays (order preserved), objects (keys sorted by UTF-16 units).
    Floats raise: §5.1 and §6 check 1 forbid them in digest-bearing
    fields, and the whole canonical capsule form is digest-bearing."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > SAFE_INT:
            raise DigestError(f"integer outside the IEEE-754 safe range: {v}")
        return str(v)
    if isinstance(v, float):
        raise DigestError(f"floating-point value in a digest-bearing field: {v!r}")
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(jcs(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_jcs_string(k) + ":" + jcs(x) for k, x in items) + "}"
    raise DigestError(f"unsupported JSON type: {type(v).__name__}")


def json_digest(v: Any) -> str:
    return hashlib.sha256(jcs(normalize(v)).encode("utf-8")).hexdigest()


def canonical_capsule_form(capsule: dict) -> dict:
    """§5.1 capsule_id: 'the envelope minus capsule_id and chain-linkage
    fields, after absent-field normalization'. [interpretation] the
    exclusion is of the top-level `capsule_id` and top-level `chain`
    (§5.5.4: 'a digested chain block {parent_capsule_id, relation}');
    nested members of those names are ordinary data."""
    return {k: v for k, v in capsule.items() if k not in ("capsule_id", "chain")}


# ─── Class 1 verification (§6) ──────────────────────────────────────────


def _find(findings: list, check: int | None, severity: str, note: str) -> None:
    findings.append({"check": check, "severity": severity, "note": note})


def derive_effect_mode(capsule: dict) -> str:
    """§5.3 / §5.5.2: effect.status → effect_mode. No effect record, or
    status planned → not_applicable ('the no-effect case', 'the planned
    carve'); dispatched, failed, reverted → dispatched_unconfirmed
    (§5.3 text, explicitly for failed and reverted; dispatched by its
    own definition 'result not observed'); confirmed → confirmed."""
    effect = capsule.get("effect")
    if not isinstance(effect, dict):
        return "not_applicable"
    status = effect.get("status")
    if status in (None, "planned"):
        return "not_applicable"
    if status == "confirmed":
        # [interpretation] §5.4: modes are "rederived from the evidence
        # present"; the evidence for confirmed is the bound response
        # (§5.3: "confirmed is an observed result, never a promise"). With
        # no well-formed response_digest, what the bytes evidence is a
        # dispatch whose result was not bound → dispatched_unconfirmed.
        # Check 3 still fails the capsule; this only decides the derived
        # mode. The -02 text does not state this derivation explicitly.
        rd = effect.get("response_digest")
        return "confirmed" if isinstance(rd, str) and HEX64.match(rd) else "dispatched_unconfirmed"
    if status in ("dispatched", "failed", "reverted"):
        return "dispatched_unconfirmed"
    return "not_applicable"  # [interpretation] unknown status: no dispatch is evidenced


def verify_capsule(
    capsule: Any, store: dict[str, dict] | None = None, ledger_order: list[str] | None = None
) -> dict:
    findings: list[dict] = []
    derived = {
        "attestation_mode": "self_attested",
        "effect_mode": "not_applicable",
        "ledger_mode": "standalone",
    }
    result = {"ok": False, "derived": derived, "capsule_id_recomputed": None, "findings": findings}

    # 1. Structural (§6 check 1; field table §5.1; disposition §5.5; assurance §5.4)
    if not isinstance(capsule, dict):
        _find(findings, 1, "error", "capsule is not a JSON object")
        return result
    for f in (
        "spec_version",
        "format_version",
        "capsule_id",
        "action_id",
        "action_type",
        "operator",
        "developer",
        "timestamp",
    ):
        if not isinstance(capsule.get(f), str):
            _find(findings, 1, "error", f"REQUIRED string field missing or mistyped: {f}")
    if capsule.get("format_version") != FORMAT_VERSION and isinstance(
        capsule.get("format_version"), str
    ):
        # [interpretation] §5.1 defines exactly one value for this profile
        # version and no forward-compatibility rule; a -02 verifier cannot
        # apply -02 checks to a serialization suite it does not know.
        _find(
            findings,
            1,
            "error",
            f"format_version {capsule['format_version']!r} is not the value "
            f"this profile defines ({FORMAT_VERSION!r})",
        )
    if capsule.get("action_type") not in ("fyi", "decide"):
        _find(findings, 1, "error", "action_type must be 'fyi' or 'decide' (§5.1)")
    cid = capsule.get("capsule_id")
    if isinstance(cid, str) and not HEX64.match(cid):
        _find(findings, 1, "error", "capsule_id is not 64 lowercase hex (§5.1)")
    ts = capsule.get("timestamp")
    if isinstance(ts, str) and not RFC3339_Z.match(ts):
        _find(findings, 1, "error", "timestamp is not RFC 3339 UTC with 'Z' (§5.1)")
    disp = capsule.get("disposition")
    if not isinstance(disp, dict):
        _find(findings, 1, "error", "disposition block missing (§5.5)")
        disp = {}
    else:
        if not isinstance(disp.get("decision"), str):
            _find(findings, 1, "error", "disposition.decision REQUIRED (§5.5)")
        if disp.get("approver") not in APPROVER:
            _find(
                findings,
                1,
                "error",
                "disposition.approver outside the closed enum {human, policy}: "
                "not a conforming Capsule (§5.5)",
            )
        if not isinstance(disp.get("human_disposed"), bool):
            _find(findings, 1, "error", "disposition.human_disposed REQUIRED boolean (§5.5)")
    assurance = capsule.get("assurance")
    if not isinstance(assurance, dict):
        _find(findings, 1, "error", "assurance object missing (§5.4)")
        assurance = {}
    effect = capsule.get("effect")
    if effect is not None and not isinstance(effect, dict):
        _find(findings, 1, "error", "effect must be an object (§5.3)")
        effect = None
    # 2. Identity (§6 check 2, §5.1) — a float or unsafe integer anywhere in
    # the canonical form is the check-1 structural failure (§5.1, §6 check 1)
    try:
        recomputed = json_digest(canonical_capsule_form(capsule))
        result["capsule_id_recomputed"] = recomputed
        if isinstance(cid, str) and HEX64.match(cid) and recomputed != cid:
            _find(
                findings,
                2,
                "error",
                "capsule_id does not recompute over the canonical capsule form",
            )
    except DigestError as e:
        _find(findings, 1, "error", f"digest-bearing field cannot be digested: {e}")

    # derived effect_mode (§5.3) — needed by checks 3–5 and 7
    derived["effect_mode"] = derive_effect_mode(capsule)
    status = effect.get("status") if isinstance(effect, dict) else None

    # 3. Confirmed-effect binding (§5.3, §6 check 3)
    if status == "confirmed":
        rd = effect.get("response_digest")
        if not (isinstance(rd, str) and HEX64.match(rd)):
            _find(
                findings,
                3,
                "error",
                "effect.status confirmed without a well-formed response_digest (§5.3)",
            )

    # 4. Verdict/effect orthogonality (§5.5.2, §6 check 4)
    vclass = disp.get("verdict_class")
    if vclass in NEVER_DISPATCH and derived["effect_mode"] != "not_applicable":
        _find(
            findings,
            4,
            "error",
            f"never-dispatching verdict_class {vclass!r} with derived "
            f"effect_mode {derived['effect_mode']!r} (§5.5.2)",
        )
    if vclass == "errored" and derived["effect_mode"] == "not_applicable":
        # §5.5.2: "errored pairs with dispatched_unconfirmed ... not_applicable
        # would falsely assert nothing happened ... equally non-conforming"
        _find(
            findings,
            4,
            "error",
            "verdict_class errored with derived effect_mode not_applicable (§5.5.2)",
        )

    # 5. Effect-attestation matrix (§5.3 Table 5, planned carve; §6 check 5)
    att = effect.get("effect_attestation") if isinstance(effect, dict) else None
    if derived["effect_mode"] in ("confirmed", "dispatched_unconfirmed"):
        if att is None:
            _find(
                findings,
                5,
                "error",
                f"effect_attestation REQUIRED for effect_mode "
                f"{derived['effect_mode']} (§5.3 Table 5)",
            )
    else:
        if att is not None:
            _find(
                findings,
                5,
                "error",
                "effect_attestation MUST be absent for not_applicable / planned (§5.3)",
            )

    # 6. Chain semantics (§5.5.4, §6 check 6) — store-level
    chain = capsule.get("chain")
    if isinstance(chain, dict):
        parent = chain.get("parent_capsule_id")
        if not (isinstance(parent, str) and HEX64.match(parent)):
            _find(findings, 1, "error", "chain.parent_capsule_id malformed (§5.5.4)")
        elif store is not None:
            if parent not in store:
                _find(findings, 6, "error", "chain parent not present in the store (§6 check 6)")
            else:
                derived["ledger_mode"] = "chained"
                if (
                    chain.get("relation") == "supersedes"
                    and ledger_order is not None
                    and isinstance(cid, str)
                ):
                    earlier = [
                        x
                        for x in ledger_order
                        if x != cid
                        and isinstance(store.get(x, {}).get("chain"), dict)
                        and store[x]["chain"].get("parent_capsule_id") == parent
                        and store[x]["chain"].get("relation") == "supersedes"
                        and ledger_order.index(x) < ledger_order.index(cid)
                    ]
                    if earlier:
                        # §5.5.4: structurally valid, MUST surface as a finding
                        # [interpretation] non-gating → warning
                        _find(
                            findings,
                            6,
                            "warning",
                            "concurrent supersedes: an earlier capsule already "
                            "supersedes this parent (§5.5.4)",
                        )
        else:
            derived["ledger_mode"] = (
                "chained"  # [interpretation] linkage present, store unavailable
            )

    # 7. Assurance reconciliation (§5.4, §6 check 7)
    for key in ("attestation_mode", "effect_mode", "ledger_mode"):
        declared = assurance.get(key)
        if declared is None:
            _find(findings, 1, "error", f"assurance.{key} missing (§5.4)")
            continue
        if declared == derived[key]:
            continue
        rank = RANKS[key]
        if declared in rank and rank[declared] < rank[derived[key]]:
            # §5.4 asks for overclaims to be reported; a weaker declared
            # mode is not an overclaim. [interpretation] surfaced as info.
            _find(
                findings,
                7,
                "info",
                f"assurance.{key} under-claims ({declared} < derived {derived[key]})",
            )
        else:
            _find(
                findings,
                7,
                "error",
                f"assurance.{key} overclaim: declared {declared!r}, "
                f"derived {derived[key]!r} (§5.4)",
            )

    # 8. Unknown registry values (§4, §12.1 binding invariant; §6 check 8)
    def unknown(name: str, value: Any, registry: set) -> None:
        if isinstance(value, str) and value not in registry:
            _find(findings, 8, "info", f"unregistered {name} value {value!r}: informational")

    unknown("verdict_class", vclass, REG_VERDICT_CLASS)
    unknown("disposition.decision", disp.get("decision"), REG_DECISION)
    if isinstance(effect, dict):
        unknown("effect.type", effect.get("type"), REG_EFFECT_TYPE)
        unknown("irreversibility_class", effect.get("irreversibility_class"), REG_IRREVERSIBILITY)
        if isinstance(att, str) and att not in REG_ATTESTATION:
            _find(
                findings,
                8,
                "info",
                f"unregistered effect_attestation {att!r}: informational (§12.1)",
            )
            _find(
                findings,
                8,
                "info",
                "unknown effect_attestation graded no stronger than runtime_claimed (§5.3)",
            )
    if isinstance(chain, dict):
        unknown("chain.relation", chain.get("relation"), REG_RELATION)

    # Defensive disposition honesty (§6 last paragraphs; §5.5) — non-gating
    if disp.get("human_disposed") is True and disp.get("approver") != "human":
        _find(
            findings,
            None,
            "warning",
            "human_disposed true with a non-human approver: "
            "structurally unrepresentable, asserted defensively (§6)",
        )

    result["ok"] = not any(f["severity"] == "error" for f in findings)
    return result


def verify_store(ledger: list[dict]) -> list[dict]:
    store = {c.get("capsule_id"): c for c in ledger if isinstance(c, dict)}
    order = [c.get("capsule_id") for c in ledger if isinstance(c, dict)]
    return [verify_capsule(c, store=store, ledger_order=order) for c in ledger]


if __name__ == "__main__":
    import sys

    data = json.load(open(sys.argv[1]))
    if isinstance(data, dict) and "ledger" in data:
        print(json.dumps(verify_store(data["ledger"]), indent=1))
    else:
        print(json.dumps(verify_capsule(data), indent=1))
