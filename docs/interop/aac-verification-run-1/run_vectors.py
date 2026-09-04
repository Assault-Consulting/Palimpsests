# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Run every case in the AAC frozen conformance corpus through
aac_verify_ref.py and report agreement per the corpus README criterion:
ok, check numbers + severities, derived modes, capsule_id.

Usage: python3 run_vectors.py /path/to/agent-action-capsule/test-vectors
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import aac_verify_ref as V  # noqa: E402


def _gating(findings: list[dict]) -> list[tuple]:
    return sorted((f["check"], f["severity"]) for f in findings if f["severity"] != "info")


def _infos(findings: list[dict]) -> int:
    return sum(1 for f in findings if f["severity"] == "info")


def compare_case(root: pathlib.Path, case: dict) -> tuple[str, str, bool, str]:
    cid = case.get("id") or case.get("name") or case.get("case")
    kind = case["kind"]
    inp = json.load(open(root / cid / "input.json"))
    exp = json.load(open(root / cid / "expected.json"))
    if kind == "canonical":
        got, got_exc = None, None
        try:
            got = V.json_digest(inp)
        except V.DigestError as e:
            got_exc = type(e).__name__
        digest_ok = got == exp.get("capsule_id_recomputed")
        match = digest_ok and (bool(got_exc) == bool(exp.get("exception")))
        note = f"digest={'ok' if digest_ok else 'DIFF'} exc={got_exc}/{exp.get('exception')}"
        return cid, kind, match, note
    if "ledger" in inp:
        pairs = list(zip(V.verify_store(inp["ledger"]), exp["results"], strict=True))
    else:
        pairs = [(V.verify_capsule(inp), exp)]
    notes = []
    match = True
    for ours, theirs in pairs:
        same = (
            ours["ok"] == theirs["ok"]
            and ours["capsule_id_recomputed"] == theirs.get("capsule_id_recomputed")
            and ours["derived"] == theirs.get("derived")
            and _gating(ours["findings"]) == _gating(theirs.get("findings", []))
            and _infos(ours["findings"]) == _infos(theirs.get("findings", []))
        )
        same_id = ours["capsule_id_recomputed"] == theirs.get("capsule_id_recomputed")
        if not same:
            match = False
            notes.append(
                f"ok {ours['ok']}/{theirs['ok']} "
                f"id {'=' if same_id else '≠'} "
                f"derived {'=' if ours['derived'] == theirs.get('derived') else ours['derived']} "
                f"findings {_gating(ours['findings'])}/{_gating(theirs.get('findings', []))} "
                f"info {_infos(ours['findings'])}/{_infos(theirs.get('findings', []))}"
            )
    return cid, kind, match, "; ".join(notes)


def main(root: pathlib.Path) -> int:
    manifest = json.load(open(root / "vectors.json"))
    rows = [compare_case(root, c) for c in manifest["cases"]]
    agree = sum(1 for r in rows if r[2])
    print(f"{agree}/{len(rows)} agree\n")
    for cid, kind, m, note in rows:
        print(f"{'AGREE' if m else 'DIFF '}  {cid:46s} {kind:10s} {note}")
    return 0


if __name__ == "__main__":
    sys.exit(main(pathlib.Path(sys.argv[1])))
