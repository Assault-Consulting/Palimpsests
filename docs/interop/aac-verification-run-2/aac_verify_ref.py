# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""aac_verify_ref.py (run 2) — an independent Class-1 verifier for Agent
Action Capsules, written from the text of
draft-mih-scitt-agent-action-capsule-05 (26 September 2026) and the
documents it references normatively (RFC 8785; the typed-digest-reference
model of draft-mih-sokolov-scitt-payload-binding-05, Section 8), and
nothing else.

Discipline: the reference implementation's source was NOT read, and no
vector's expected value was consulted while this file was written. Every
rule below cites the -05 section it comes from. Where the text is silent
or open, the choice is marked `[interpretation]` and is listed in the run
record. Standard library only. COSE / Receipt verification ("by
reference", Section 6) and Class 2 (Section 8.2) are out of scope.

Result shape (Section 6: "a structured result, never throw; a single ok
boolean; findings in a fixed order"):
    {ok, derived: {attestation_mode, effect_mode, ledger_mode
                   [, cross_party_rung]},
     capsule_id_recomputed, findings: [{check, severity, note}],
     provenance: {mode, time_rung}   # only when a provenance_mode block is present
    }

Lineage: derived from the run-1 verifier (written from -02) and re-targeted
to -05; every behavioural change is justified in the comments below by a
-05 section.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
from typing import Any

SPEC = "draft-mih-scitt-agent-action-capsule-05"
# Section 5.1: a verifier MUST accept -04 and -05 (the revisions that define format 4).
ACCEPTED_SPEC_VERSIONS = {
    "draft-mih-scitt-agent-action-capsule-04",
    "draft-mih-scitt-agent-action-capsule-05",
}
FORMAT_VERSION = "4"  # Sections 2, 5.1, 6 check 1: exactly the string "4"
CANONICALIZATION_ID = "jcs"  # Sections 2, 5.1, 6 check 1: exactly the string "jcs"
SAFE_INT = 2**53 - 1  # Section 2: integers outside the IEEE-754 safe range must be strings

HEX64 = re.compile(r"^[0-9a-f]{64}$")
RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")  # 5.1 timestamp
RFC3339_ANY = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$"
)  # RFC 3339 date-time, used for fields typed only "([RFC3339])"

# Section 5.5.2 and 12.1 item 1: classes that by their kind never dispatch,
# plus epoch_boundary which "REQUIRES effect_mode: not_applicable".
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
# Section 12.1 seeded registries (unknown values -> informational, never reject)
REG_VERDICT_CLASS = NEVER_DISPATCH | {"executed", "timeout", "errored"}
REG_DECISION = {"accept", "reject", "needs_input", "deferred"}
REG_EFFECT_TYPE = {"write_order", "send_payment", "inference_completion"}
REG_IRREVERSIBILITY = {
    "two_way",
    "one_way_recoverable",
    "one_way_consequential",
    "one_way_terminal",
}
REG_ATTESTATION = {"gate_executed", "runtime_claimed", "host_served_observed"}
REG_RELATION = {"follows", "confirms", "supersedes", "epoch_opens", "duplicates"}
REG_CITATION_PURPOSE = {
    "acted_on",
    "responds_to",
    "ran_under",
    "corroborates_source_time",
    "counterparty_half",
    "counterparty_inclusion",
}
APPROVER = {"human", "policy", "counterparty"}  # 5.5: closed three-member enum
EFFECT_STATUS = {"planned", "dispatched", "confirmed", "failed", "reverted"}  # 5.3 Table 3
PROVENANCE_MODES = {"contemporaneous", "backfilled"}  # 5.4.3 Table 7 closed enum
TIME_RUNGS = {"self_attested", "witnessed"}  # 5.4.3 Table 7
CROSS_PARTY_RUNGS = {"unilateral_fallback", "acknowledged_receipt", "full_bilateral"}  # 5.4.1
LEDGER_RANK = {"standalone": 0, "chained": 1, "anchored": 2}  # 5.4 order
EFFECT_RANK = {"not_applicable": 0, "dispatched_unconfirmed": 1, "confirmed": 2}
ATTEST_RANK = {"self_attested": 0, "anchored": 1}
RUNG_RANK = {"unilateral_fallback": 0, "acknowledged_receipt": 1, "full_bilateral": 2}  # 5.4.1
RANKS = {
    "ledger_mode": LEDGER_RANK,
    "effect_mode": EFFECT_RANK,
    "attestation_mode": ATTEST_RANK,
}
# Section 6 check 9: "unlike the informational overclaim treatment of
# attestation_mode, ledger_mode, and cross_party_rung in check 7" -> those three
# are reported at severity info. effect_mode is not named there.
# [interpretation] effect_mode overclaims keep severity error.
INFO_OVERCLAIM = {"attestation_mode", "ledger_mode", "cross_party_rung"}


# Post-hoc sensitivity switches. EMPTY in every headline run. They exist only so the
# run record can show, separately and honestly labelled, which disagreements disappear
# under an alternative reading of an open point in the text. Names:
#   fail_closed_continue  keep deriving modes/checks after a fail-closed declaration (no digest)
#   decl_merged           one check-1 finding for the two declarations
#   concurrent_info       concurrent-supersedes finding at severity info
#   prov_per_field        one check-9 finding per missing/malformed backfilled member
#   orphan_forbidden      backfill-only members under mode contemporaneous are a check-9 error
#   store_info            info finding (check 6) when a chain is present and no store is supplied
ALT: set[str] = set()


class DigestError(ValueError):
    """A value that cannot be digested reproducibly (Section 2; Section 6 check 1)."""


# --- JSON-DIGEST (Section 2): HEX(SHA-256(UTF8(JCS(value)))) --------------


def _jcs_string(s: str) -> str:
    # RFC 8785 3.2.2.2: escape " \ and C0 controls; short forms for \b \t \n \f \r;
    # everything else literal (solidus not escaped; non-BMP passes through).
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
    # RFC 8785 3.2.3: sort property names by UTF-16 code units
    b = s.encode("utf-16-be", "surrogatepass")
    return [int.from_bytes(b[i : i + 2], "big") for i in range(0, len(b), 2)]


def jcs(v: Any) -> str:
    """RFC 8785 serialization restricted to what the profile allows: strings,
    booleans, null, integers within the IEEE-754 safe range, arrays (order
    preserved), objects (members sorted by UTF-16 code units, recursively).
    Floats raise: Section 2 forbids them in digest-bearing material, and the
    whole Capsule is digest-bearing (Section 5.1). Section 2 also requires that
    no allow-list, replacer or other key filter be applied at any depth, and
    that null / [] / {} participate: there is no normalization step here
    (this is the main change from run 1, which targeted -02)."""
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
    """Section 2: lowercase-hex SHA-256 of UTF8(JCS(value)), whole value, no filtering."""
    try:
        return hashlib.sha256(jcs(v).encode("utf-8")).hexdigest()
    except UnicodeEncodeError as e:  # lone surrogate: not representable as UTF-8
        raise DigestError(f"string not encodable as UTF-8: {e}") from e


def canonical_preimage(capsule: dict) -> str:
    return jcs(capsule_identity_form(capsule))


def capsule_identity_form(capsule: dict) -> dict:
    """Sections 5.1 and 6 check 2: 'Remove local-only signature and key_id
    envelope fields, if present in a local composite representation, then
    compute SHA-256 over plain JCS of the Capsule after removing only
    capsule_id.' The canonicalization_id declaration, chain block and
    references array participate (they are simply not removed).
    [interpretation] the removals are of top-level members only; nested
    members of those names are ordinary data."""
    return {k: v for k, v in capsule.items() if k not in ("capsule_id", "signature", "key_id")}


# --- helpers --------------------------------------------------------------


def _find(findings: list, check: int | None, severity: str, note: str) -> None:
    findings.append({"check": check, "severity": severity, "note": note})


def _is_int(x: Any) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _rfc3339(s: Any) -> bool:
    if not isinstance(s, str):
        return False
    m = RFC3339_ANY.match(s)
    if not m:
        return False
    y, mo, d, h, mi, sec = (int(m.group(i)) for i in range(1, 7))
    try:
        _dt.date(y, mo, d)
    except ValueError:
        return False
    return h < 24 and mi < 60 and sec <= 60  # 60: leap second, RFC 3339 5.7


def _typed_digest_ref_ok(ref: Any) -> bool:
    """Typed digest reference per 5.5.5 / CPB-05 Section 8: members type,
    digest_alg, digest are REQUIRED text. [interpretation] 'well-formed' at
    Class 1 = an object whose three members are non-empty strings; the digest
    representation belongs to a digest context the verifier does not resolve
    (CPB 8.1), so it is not interpreted here."""
    return isinstance(ref, dict) and all(
        isinstance(ref.get(k), str) and ref.get(k) != "" for k in ("type", "digest_alg", "digest")
    )


def derive_effect_mode(capsule: dict) -> str:
    """Section 5.3 / 5.5.2. No effect record, or planned -> not_applicable;
    dispatched, failed, reverted -> dispatched_unconfirmed (5.3, explicit for
    failed / reverted); confirmed -> confirmed, but 'confirmed' without a
    response_digest derives dispatched_unconfirmed, 'never confirmed' (5.3,
    stated explicitly in -05; run 1 had to interpret this)."""
    effect = capsule.get("effect")
    if not isinstance(effect, dict):
        return "not_applicable"
    status = effect.get("status")
    if status in (None, "planned"):
        return "not_applicable"
    if status == "confirmed":
        rd = effect.get("response_digest")
        return "confirmed" if isinstance(rd, str) and HEX64.match(rd) else "dispatched_unconfirmed"
    if status in ("dispatched", "failed", "reverted"):
        return "dispatched_unconfirmed"
    return "not_applicable"  # [interpretation] unknown status: no dispatch evidenced


def _chain_block_ok(chain: Any) -> bool:
    """5.4: 'chained is derived solely from the presence and integrity of the
    Capsule's own chain-linkage block (5.5.4)' = {parent_capsule_id, relation}.
    [interpretation] integrity of the block = parent_capsule_id is 64 lowercase
    hex and relation is a string. Parent resolution is NOT part of it."""
    return (
        isinstance(chain, dict)
        and isinstance(chain.get("parent_capsule_id"), str)
        and bool(HEX64.match(chain["parent_capsule_id"]))
        and isinstance(chain.get("relation"), str)
    )


def derive_cross_party_rung(cp: Any) -> str:
    """5.4.1, from the block's own bytes alone: unilateral_fallback when
    counterparty_ref is absent or malformed; acknowledged_receipt when
    counterparty_ref and correlator are both present and well-formed and
    substantive is absent or false; full_bilateral when substantive is true.
    [interpretation] well-formed counterparty_ref = 64 lowercase hex (it is 'a
    JSON digest', Section 2); well-formed correlator = a non-empty string
    (an 'opaque ... correlation string')."""
    if not isinstance(cp, dict):
        return "unilateral_fallback"
    cref, corr = cp.get("counterparty_ref"), cp.get("correlator")
    if not (isinstance(cref, str) and HEX64.match(cref)):
        return "unilateral_fallback"
    if not (isinstance(corr, str) and corr != ""):
        return "unilateral_fallback"
    return "full_bilateral" if cp.get("substantive") is True else "acknowledged_receipt"


def _check_references(refs: Any, findings: list) -> list[dict]:
    """5.5.5 / 5.5.6 structural checks (check 1). Returns the well-formed entries."""
    good: list[dict] = []
    # FIX D2 (run-2 defect log): 5.5.5 says a Capsule MAY carry a references *array* and
    # that "absent or empty means the Capsule makes no such citation"; Section 2 says
    # null "participate[s] when present", i.e. a present null is not an absent member.
    # A present `references` that is not an array (null included) is malformed (check 1).
    # The first run of this verifier treated null as absent; corrected here (the
    # disagreement that exposed it is disclosed in RUN-RECORD.md).
    if not isinstance(refs, list):
        _find(findings, 1, "error", "references must be an array (5.5.5)")
        return good
    for i, e in enumerate(refs):
        tag = f"references[{i}]"
        if not isinstance(e, dict):
            _find(findings, 1, "error", f"{tag} is not an object (5.5.5)")
            continue
        ok = True
        if not _typed_digest_ref_ok(e):
            _find(
                findings,
                1,
                "error",
                f"{tag} is not a typed digest reference: type, digest_alg and digest "
                "must all be non-empty strings (5.5.5, CPB-05 section 8)",
            )
            ok = False
        cp = e.get("citation_purpose")
        if "citation_purpose" in e and not isinstance(cp, str):
            _find(findings, 1, "error", f"{tag}.citation_purpose must be a string (5.5.5)")
            ok = False
        if "retention" in e:
            r = e["retention"]
            if not isinstance(r, dict):
                _find(findings, 1, "error", f"{tag}.retention is not an object (5.5.6)")
                ok = False
            else:
                if not (isinstance(r.get("declarant"), str) and r["declarant"] != ""):
                    _find(
                        findings, 1, "error", f"{tag}.retention.declarant REQUIRED string (5.5.6)"
                    )
                    ok = False
                has_bound = False
                for k in ("retained_until", "not_retained_after"):
                    if k in r:
                        if _rfc3339(r[k]):
                            has_bound = True
                        else:
                            _find(
                                findings,
                                1,
                                "error",
                                f"{tag}.retention.{k} is not an RFC 3339 string (5.5.6)",
                            )
                            ok = False
                if not has_bound and ok:
                    _find(
                        findings,
                        1,
                        "error",
                        f"{tag}.retention carries neither retained_until nor not_retained_after (5.5.6)",  # noqa: E501
                    )
                    ok = False
        if "log_coordinates" in e:
            lc = e["log_coordinates"]
            # 5.5.6: {log_id, leaf_index, inclusion_proof} 'present as a unit';
            # leaf_index MUST be a JSON integer, not a string. The proof itself is
            # 'structurally recorded' and not verified at Class 1.
            if not (
                isinstance(lc, dict)
                and isinstance(lc.get("log_id"), str)
                and _is_int(lc.get("leaf_index"))
                and lc["leaf_index"] >= 0  # 'zero-based' index
                and lc.get("inclusion_proof") is not None
            ):
                _find(
                    findings,
                    1,
                    "error",
                    f"{tag}.log_coordinates must be {{log_id: string, leaf_index: non-negative "
                    "integer, inclusion_proof}} as a unit (5.5.6)",
                )
                ok = False
        if ok:
            good.append(e)
    return good


def _check_provenance(capsule: dict, findings: list, good_refs: list[dict]) -> dict | None:
    """Section 6 check 9 and 5.4.3. [interpretation] every malformation of the
    provenance_mode block is reported under check 9 (the section 6 check named
    'Provenance mode'), not check 1."""
    if "provenance_mode" not in capsule:
        return None
    pm = capsule["provenance_mode"]
    if not isinstance(pm, dict):
        _find(findings, 9, "error", "provenance_mode is not an object (5.4.3)")
        return None
    mode = pm.get("mode")
    if mode not in PROVENANCE_MODES:
        _find(
            findings,
            9,
            "error",
            "provenance_mode.mode must be 'contemporaneous' or 'backfilled' (5.4.3)",
        )
        return None
    time_rung = pm.get("time_rung")
    cap = "self_attested"
    if "time_rung" in pm and time_rung not in TIME_RUNGS:
        _find(
            findings,
            9,
            "error",
            "provenance_mode.time_rung must be 'self_attested' or 'witnessed' (5.4.3)",
        )
    elif "time_rung" in pm and mode != "backfilled":
        _find(
            findings,
            9,
            "error",
            "provenance_mode.time_rung MUST be absent unless mode is 'backfilled' (5.4.3)",
        )
    if mode == "contemporaneous" and "orphan_forbidden" in ALT:
        orphans = [
            k
            for k in ("source_ref", "source_asserted_at", "import_batch", "imported_at")
            if k in pm
        ]
        if orphans:
            _find(
                findings,
                9,
                "error",
                f"backfill-only members under mode contemporaneous: {', '.join(orphans)}",
            )
    if mode == "backfilled":
        missing = []
        if not _typed_digest_ref_ok(pm.get("source_ref")):
            missing.append("source_ref")
        for k in ("source_asserted_at", "imported_at"):
            if not _rfc3339(pm.get(k)):
                missing.append(k)
        if not (isinstance(pm.get("import_batch"), str) and pm["import_batch"] != ""):
            missing.append("import_batch")
        if missing:
            for m in missing if "prov_per_field" in ALT else [", ".join(missing)]:
                _find(
                    findings,
                    9,
                    "error",
                    "mode 'backfilled' without a well-formed provenance_mode block; "
                    f"missing or malformed: {m} (5.4.3, check 9)",
                )
        sa, ia = pm.get("source_asserted_at"), pm.get("imported_at")
        if isinstance(sa, str) and isinstance(ia, str) and sa == ia:
            _find(
                findings,
                9,
                "error",
                "imported_at is byte-equal to source_asserted_at: the laundering shape (5.4.3, check 9)",  # noqa: E501
            )
        if time_rung == "witnessed":
            supported = any(
                r.get("citation_purpose") == "corroborates_source_time" for r in good_refs
            )
            if supported:
                cap = "witnessed"
            else:
                _find(
                    findings,
                    9,
                    "error",
                    "time_rung 'witnessed' without a well-formed references[] entry citing "
                    "citation_purpose 'corroborates_source_time' (5.4.3, check 9)",
                )
    return {"mode": mode, "time_rung": cap}


# --- Class 1 verification (Section 6) -------------------------------------


def verify_capsule(
    capsule: Any, store: dict[str, dict] | None = None, ledger_order: list[str] | None = None
) -> dict:
    findings: list[dict] = []
    derived = {
        "attestation_mode": "self_attested",
        "effect_mode": "not_applicable",
        "ledger_mode": "standalone",
    }
    result: dict[str, Any] = {
        "ok": False,
        "derived": derived,
        "capsule_id_recomputed": None,
        "findings": findings,
    }

    def finish() -> dict:
        findings.sort(
            key=lambda f: (f["check"] is None, f["check"] or 0)
        )  # fixed order (Section 6)
        result["ok"] = not any(f["severity"] == "error" for f in findings)
        return result

    # 1. Structural. 'A producer or verifier MUST check both declarations before
    # computing any digest ... MUST fail closed' (Section 2, Section 6 check 1).
    if not isinstance(capsule, dict):
        _find(findings, 1, "error", "capsule is not a JSON object")
        return finish()
    fv, cz = capsule.get("format_version"), capsule.get("canonicalization_id")
    decl_errors = []
    if fv != FORMAT_VERSION:
        decl_errors.append(
            f"format_version must be exactly the string {FORMAT_VERSION!r} (2, 5.1, 6)"
        )
    if cz != CANONICALIZATION_ID:
        decl_errors.append(
            "canonicalization_id must be exactly the string 'jcs'; absent, null, non-string, "
            "empty, unknown and 'jcs-n' declarations fail closed (2, 5.1, 6)"
        )
    skip_digest = False
    if decl_errors:
        if "decl_merged" in ALT:
            _find(findings, 1, "error", " ; ".join(decl_errors))
        else:
            for m in decl_errors:  # [interpretation] one finding per failed declaration
                _find(findings, 1, "error", m)
        # [interpretation] fail closed = stop: no digest, no mode derivation, no later
        # check is applied to a Capsule whose serialization suite is not the one this
        # verifier implements. (Open point: the text says "fail closed" and "check both
        # declarations before computing any digest"; it does not say whether the other
        # reported fields are still derived. See ALT fail_closed_continue.)
        if "fail_closed_continue" not in ALT:
            return finish()
        skip_digest = True

    for f in (
        "spec_version",
        "capsule_id",
        "action_id",
        "action_type",
        "operator",
        "developer",
        "timestamp",
    ):
        if not isinstance(capsule.get(f), str):
            _find(findings, 1, "error", f"REQUIRED string field missing or mistyped: {f}")
    sv = capsule.get("spec_version")
    if isinstance(sv, str) and sv not in ACCEPTED_SPEC_VERSIONS:
        # 5.1: 'An unrecognized spec_version value is informational and is never by
        # itself a reason to reject (consistent with check 8).'
        _find(findings, 8, "info", f"unrecognized spec_version {sv!r}: informational (5.1)")
    if capsule.get("action_type") not in ("fyi", "decide"):
        _find(findings, 1, "error", "action_type must be 'fyi' or 'decide' (5.1)")
    cid = capsule.get("capsule_id")
    if isinstance(cid, str) and not HEX64.match(cid):
        _find(findings, 1, "error", "capsule_id is not 64 lowercase hex (5.1)")
    ts = capsule.get("timestamp")
    if isinstance(ts, str) and not RFC3339_Z.match(ts):
        _find(findings, 1, "error", "timestamp is not RFC 3339 UTC with 'Z' (5.1)")

    disp = capsule.get("disposition")
    if "disposition" not in capsule and capsule.get("action_type") == "fyi":
        # FIX D1 (run-2 defect log): 5.1 defines action_type "fyi" as informational and
        # "decide" as "a disposition was required"; the REQUIRED members listed in 5.5
        # are REQUIRED *within* a disposition block. The block itself is therefore
        # required only for action_type "decide". Run 1 (-02) required it always.
        disp = {}
    elif not isinstance(disp, dict):
        _find(
            findings,
            1,
            "error",
            "disposition block missing or not an object (5.1 action_type decide, 5.5)",
        )
        disp = {}
    else:
        if not isinstance(disp.get("decision"), str):
            _find(findings, 1, "error", "disposition.decision REQUIRED string (5.5)")
        if disp.get("approver") not in APPROVER:
            # 5.5 and 6: closed three-member enum; structural, absent from check 8.
            _find(
                findings,
                1,
                "error",
                "disposition.approver outside the closed enum {human, policy, counterparty}: "
                "not a conforming Capsule (5.5)",
            )
        if not isinstance(disp.get("human_disposed"), bool):
            _find(findings, 1, "error", "disposition.human_disposed REQUIRED boolean (5.5)")
        if "verdict_class" in disp and not isinstance(disp["verdict_class"], str):
            _find(findings, 1, "error", "disposition.verdict_class must be a string (5.5)")

    assurance = capsule.get("assurance")
    if not isinstance(assurance, dict):
        _find(findings, 1, "error", "assurance object missing (5.4)")
        assurance = {}

    effect = capsule.get("effect")
    if effect is not None and not isinstance(effect, dict):
        _find(findings, 1, "error", "effect must be an object (5.3)")
        effect = None
    if isinstance(effect, dict):
        st = effect.get("status")
        if st is not None and st not in EFFECT_STATUS:
            # [interpretation] Table 3: 'takes one of five values' -> closed.
            _find(findings, 1, "error", f"effect.status {st!r} is not one of the five values (5.3)")
        for k in ("type", "irreversibility_class", "effect_attestation"):
            if k in effect and not isinstance(effect[k], str):
                _find(findings, 1, "error", f"effect.{k} must be a string (5.3)")

    chain = capsule.get("chain")
    chain_ok = False
    if chain is not None or "chain" in capsule:
        if not isinstance(chain, dict):
            _find(
                findings,
                1,
                "error",
                "chain must be an object {parent_capsule_id, relation} (5.5.4)",
            )
        else:
            if not (
                isinstance(chain.get("parent_capsule_id"), str)
                and HEX64.match(chain["parent_capsule_id"])
            ):
                _find(findings, 1, "error", "chain.parent_capsule_id malformed (5.5.4)")
            if not isinstance(chain.get("relation"), str):
                _find(findings, 1, "error", "chain.relation REQUIRED string (5.5.4)")
            chain_ok = _chain_block_ok(chain)

    good_refs = (
        _check_references(capsule.get("references"), findings) if "references" in capsule else []
    )

    cp = capsule.get("cross_party")
    if "cross_party" in capsule:
        if not isinstance(cp, dict):
            _find(findings, 1, "error", "cross_party must be an object (5.4.1)")
        else:
            iref = cp.get("initiator_ref")
            if not (isinstance(iref, str) and HEX64.match(iref)):
                _find(
                    findings, 1, "error", "cross_party.initiator_ref REQUIRED JSON digest (5.4.1)"
                )
            cref = cp.get("counterparty_ref")
            if isinstance(cref, str) and HEX64.match(cref):
                if not (isinstance(cp.get("correlator"), str) and cp["correlator"] != ""):
                    _find(
                        findings,
                        1,
                        "error",
                        "cross_party.correlator REQUIRED when counterparty_ref is present (5.4.1)",
                    )
            if "substantive" in cp and not isinstance(cp["substantive"], bool):
                _find(findings, 1, "error", "cross_party.substantive must be boolean (5.4.1)")
            if "correlator" in cp and not isinstance(cp["correlator"], str):
                _find(findings, 1, "error", "cross_party.correlator must be a string (5.4.1)")
        if "cross_party_rung" not in assurance:
            _find(
                findings,
                1,
                "error",
                "assurance.cross_party_rung REQUIRED when cross_party is present (5.4.1)",
            )

    # 9. Provenance mode (block validity; time-rung and laundering failures)
    prov = _check_provenance(capsule, findings, good_refs)
    if prov is not None:
        result["provenance"] = prov

    # Section 2 / Section 6 check 1: a float or unsafe integer anywhere in the
    # (digest-bearing) Capsule is a structural failure.
    # 2. Identity (check 2): remove local-only signature/key_id and capsule_id; plain JCS.
    if not skip_digest:
        try:
            recomputed = json_digest(capsule_identity_form(capsule))
            result["capsule_id_recomputed"] = recomputed
            if isinstance(cid, str) and HEX64.match(cid) and recomputed != cid:
                _find(
                    findings,
                    2,
                    "error",
                    "capsule_id does not recompute over plain JCS of the Capsule",
                )
        except DigestError as e:
            _find(findings, 1, "error", f"digest-bearing field cannot be digested: {e}")

    derived["effect_mode"] = derive_effect_mode(capsule)
    status = effect.get("status") if isinstance(effect, dict) else None

    # 3. Confirmed-effect binding (5.3)
    if status == "confirmed":
        rd = effect.get("response_digest")
        if not (isinstance(rd, str) and HEX64.match(rd)):
            _find(
                findings,
                3,
                "error",
                "effect.status confirmed without a well-formed response_digest (5.3)",
            )

    # 4. Verdict/effect orthogonality (5.5.2)
    vclass = disp.get("verdict_class")
    if vclass in NEVER_DISPATCH and derived["effect_mode"] != "not_applicable":
        _find(
            findings,
            4,
            "error",
            f"never-dispatching verdict_class {vclass!r} with derived effect_mode {derived['effect_mode']!r} (5.5.2)",  # noqa: E501
        )
    if vclass == "errored" and derived["effect_mode"] == "not_applicable":
        _find(
            findings,
            4,
            "error",
            "verdict_class errored with derived effect_mode not_applicable (5.5.2)",
        )

    # 5. Effect-attestation matrix (5.3 Table 5, planned carve)
    att = effect.get("effect_attestation") if isinstance(effect, dict) else None
    if derived["effect_mode"] in ("confirmed", "dispatched_unconfirmed"):
        if att is None:
            _find(
                findings,
                5,
                "error",
                f"effect_attestation REQUIRED for effect_mode {derived['effect_mode']} (5.3 Table 5)",  # noqa: E501
            )
    elif att is not None:
        _find(
            findings,
            5,
            "error",
            "effect_attestation MUST be absent for not_applicable / planned (5.3)",
        )

    # 6. Chain semantics (5.5.4, 5.5.5; store-level)
    if chain_ok:
        parent = chain["parent_capsule_id"]
        # 5.4: ledger_mode 'chained' derives solely from the Capsule's own linkage
        # block; parent resolution never downgrades it (stated in -05; run 1's F2).
        derived["ledger_mode"] = "chained"
        if store is None and "store_info" in ALT:
            _find(
                findings,
                6,
                "info",
                "chain parent-existence and concurrent-supersedes are store-level checks; not run without a store",  # noqa: E501
            )
        if store is not None:
            if parent not in store:
                _find(findings, 6, "error", "chain parent not present in the store (check 6)")
            elif (
                chain.get("relation") == "supersedes"
                and ledger_order is not None
                and isinstance(cid, str)
                and cid in ledger_order
            ):
                earlier = [
                    x
                    for x in ledger_order
                    if x != cid
                    and ledger_order.index(x) < ledger_order.index(cid)
                    and isinstance(store.get(x, {}).get("chain"), dict)
                    and store[x]["chain"].get("parent_capsule_id") == parent
                    and store[x]["chain"].get("relation") == "supersedes"
                ]
                if earlier:
                    # 5.5.4: 'structurally valid but MUST surface as a verification
                    # finding'. [interpretation] severity warning: 5.2.3 and check 8
                    # say 'informational finding' where they mean info; 5.5.4 does not.
                    _find(
                        findings,
                        6,
                        "info" if "concurrent_info" in ALT else "warning",
                        "concurrent supersedes: an earlier Capsule in ledger order already supersedes this parent",  # noqa: E501
                    )
        # 5.5.5 boundary rule: a references entry MUST NOT name the same target as
        # chain.parent_capsule_id. Identity is {digest_alg, digest} alone, and bare
        # hex equality is not a join (CPB-05 8.1), so [interpretation] the same target
        # means digest_alg 'SHA-256' (exact, case-sensitive) and an equal digest.
        for e in good_refs:
            if e.get("digest_alg") == "SHA-256" and e.get("digest") == parent:
                _find(
                    findings,
                    6,
                    "error",
                    "references entry duplicates chain.parent_capsule_id (5.5.5 boundary rule, check 6)",  # noqa: E501
                )
                break

    # 7. Assurance reconciliation (5.4, 5.4.1)
    for key in ("attestation_mode", "effect_mode", "ledger_mode"):
        declared = assurance.get(key)
        if declared is None:
            _find(findings, 1, "error", f"assurance.{key} missing (5.4)")
            continue
        rank = RANKS[key]
        if declared not in rank:
            _find(
                findings,
                1,
                "error",
                f"assurance.{key} value {declared!r} outside the closed vocabulary (5.4)",
            )
            continue
        if declared == derived[key]:
            continue
        if rank[declared] < rank[derived[key]]:
            # 5.4 asks for overclaims to be reported; a weaker declared mode is not an
            # overclaim. [interpretation] surfaced as info (unchanged from run 1).
            _find(
                findings,
                7,
                "info",
                f"assurance.{key} under-claims ({declared} < derived {derived[key]})",
            )
        else:
            sev = "info" if key in INFO_OVERCLAIM else "error"
            _find(
                findings,
                7,
                sev,
                f"assurance_overclaim: assurance.{key} declared {declared!r}, derived {derived[key]!r} (5.4)",  # noqa: E501
            )
    declared_rung = assurance.get("cross_party_rung")
    if "cross_party" in capsule or declared_rung is not None:
        # 5.4.1: derived from the block's own bytes; with no block the evidence
        # supports only the lowest rung [interpretation].
        d_rung = derive_cross_party_rung(cp)
        derived["cross_party_rung"] = d_rung
        if declared_rung is not None:
            if declared_rung not in RUNG_RANK:
                _find(
                    findings,
                    1,
                    "error",
                    f"assurance.cross_party_rung {declared_rung!r} outside the closed vocabulary (5.4.1)",  # noqa: E501
                )
            elif RUNG_RANK[declared_rung] > RUNG_RANK[d_rung]:
                _find(
                    findings,
                    7,
                    "info",  # check 9 lists cross_party_rung as informational
                    f"assurance_overclaim: assurance.cross_party_rung declared {declared_rung!r}, derived {d_rung!r} (5.4.1)",  # noqa: E501
                )
            elif RUNG_RANK[declared_rung] < RUNG_RANK[d_rung]:
                _find(
                    findings,
                    7,
                    "info",
                    f"assurance.cross_party_rung under-claims ({declared_rung} < derived {d_rung})",
                )

    # 8. Unknown registry values (informational; never reject)
    def unknown(name: str, value: Any, registry: set) -> None:
        if isinstance(value, str) and value not in registry:
            _find(findings, 8, "info", f"unregistered {name} value {value!r}: informational")

    unknown("verdict_class", vclass, REG_VERDICT_CLASS)
    unknown("disposition.decision", disp.get("decision"), REG_DECISION)
    if isinstance(effect, dict):
        unknown("effect.type", effect.get("type"), REG_EFFECT_TYPE)
        unknown("irreversibility_class", effect.get("irreversibility_class"), REG_IRREVERSIBILITY)
        if isinstance(att, str) and att not in REG_ATTESTATION:
            _find(findings, 8, "info", f"unregistered effect_attestation {att!r}: informational")
            _find(
                findings,
                8,
                "info",
                "unknown effect_attestation graded no stronger than runtime_claimed (5.3)",
            )
    if isinstance(chain, dict):
        unknown("chain.relation", chain.get("relation"), REG_RELATION)
    for e in good_refs:
        unknown("citation_purpose", e.get("citation_purpose"), REG_CITATION_PURPOSE)

    # Defensive disposition honesty (6, last paragraphs; 5.5): 'SHOULD nonetheless
    # assert the invariant defensively'; not a numbered check. Unchanged from run 1.
    if disp.get("human_disposed") is True and disp.get("approver") != "human":
        _find(
            findings,
            None,
            "warning",
            "human_disposed true with a non-human approver: asserted defensively (5.5, 6)",
        )

    return finish()


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
