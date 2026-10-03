# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
"""Run every case of the AAC `vectors/capsule/` corpus (and, separately, the
`provenance-mode-vectors/` corpus) through aac_verify_ref.py and report
agreement per the corpus README criterion: ok, the Section 6 check numbers +
severities, the derived modes, and capsule_id. Results are split by the
`provenance` label carried by each case (spec-derived / reference-derived /
unlabelled) and are never merged across it.

Usage:
    python3 run_vectors.py <vectors/capsule dir> [<provenance-mode-vectors dir>]
                           [--json out.json] [--alt name[,name...]]

--alt switches on post-hoc alternative readings (see ALT in aac_verify_ref.py). It is a
sensitivity tool for the run record and is never used for the headline numbers.
"""

from __future__ import annotations

import json
import pathlib
import sys
from collections import Counter

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import aac_verify_ref as V  # noqa: E402

BASE_MODES = ("attestation_mode", "effect_mode", "ledger_mode")


def _gating(findings: list[dict]) -> list[tuple]:
    return sorted(
        (f["check"] if f["check"] is not None else -1, f["severity"])
        for f in findings
        if f["severity"] != "info"
    )


def _infos(findings: list[dict]) -> int:
    return sum(1 for f in findings if f["severity"] == "info")


def _strings(x):
    if isinstance(x, str):
        yield x
    elif isinstance(x, dict):
        for v in x.values():
            yield from _strings(v)
    elif isinstance(x, list):
        for v in x:
            yield from _strings(v)


def compare_one(ours: dict, theirs: dict) -> tuple[bool, list[str], bool]:
    """Returns (strict_agree, strict_reasons, loose_agree).

    strict  = the run-1 criterion verbatim: ok, check numbers + severities (as a
              multiset), derived modes, capsule_id, and the count of info findings.
    loose   = the same, but findings compared as a SET of (check, severity) and the
              info-count ignored; it separates a disagreement about a rule from a
              disagreement about how many findings carry it / about diagnostics the
              text does not define. Reported as a secondary column, never as the headline.
    """
    reasons: list[str] = []
    loose_ok = True
    if ours["ok"] != theirs.get("ok"):
        reasons.append(f"ok {ours['ok']}/{theirs.get('ok')}")
        loose_ok = False
    if ours["capsule_id_recomputed"] != theirs.get("capsule_id_recomputed"):
        reasons.append("capsule_id differs")
        loose_ok = False
    od = dict(ours["derived"])
    if (
        "provenance" in ours
    ):  # shape translation only: 5.4.3 requires these to be reported, not under which key
        od["provenance_mode"] = ours["provenance"]["mode"]
        od["provenance_time_rung"] = ours["provenance"]["time_rung"]
    td = theirs.get("derived", {})
    for k in list(BASE_MODES) + sorted(set(td) - set(BASE_MODES)):
        if od.get(k) != td.get(k):
            reasons.append(f"derived.{k} {od.get(k)}/{td.get(k)}")
            loose_ok = False
    og, tg = _gating(ours["findings"]), _gating(theirs.get("findings", []))
    if og != tg:
        reasons.append(f"findings {og}/{tg}")
        if set(og) != set(tg):
            loose_ok = False
    if _infos(ours["findings"]) != _infos(theirs.get("findings", [])):
        reasons.append(
            f"info-count {_infos(ours['findings'])}/{_infos(theirs.get('findings', []))}"
        )
    return (not reasons), reasons, loose_ok


def run_case(root: pathlib.Path, name: str) -> dict:
    inp = json.load(open(root / name / "input.json"))
    exp = json.load(open(root / name / "expected.json"))
    row: dict = {"name": name, "provenance": exp.get("provenance"), "kind": exp.get("kind")}
    if isinstance(inp, dict) and "ledger" in inp:
        pairs = list(zip(V.verify_store(inp["ledger"]), exp["results"], strict=True))
        row["store"] = True
    else:
        pairs = [(V.verify_capsule(inp), exp)]
    reasons_all, ok_all, loose_all = [], True, True
    id_same = True
    for ours, theirs in pairs:
        agree, reasons, loose = compare_one(ours, theirs)
        ok_all &= agree
        loose_all &= loose
        reasons_all += reasons
        id_same &= ours["capsule_id_recomputed"] == theirs.get("capsule_id_recomputed")
        row["ours"] = {"ok": ours["ok"], "findings": ours["findings"], "derived": ours["derived"]}
        row["theirs"] = {
            "ok": theirs.get("ok"),
            "findings": theirs.get("findings", []),
            "derived": theirs.get("derived"),
        }
    row["agree"] = ok_all
    row["agree_loose"] = loose_all
    row["reasons"] = reasons_all
    row["capsule_id_identical"] = id_same
    # spec-derived cases record the literal RFC 8785 canonical strings: compare our preimage
    pre = exp.get("canonical_preimages")
    if pre is not None and not (isinstance(inp, dict) and "ledger" in inp):
        try:
            mine = V.canonical_preimage(inp)
            row["preimage_in_recorded_set"] = mine in set(_strings(pre))
        except V.DigestError:
            row["preimage_in_recorded_set"] = None
    return row


def summarize(rows: list[dict], title: str) -> None:
    print(f"\n=== {title} ===")
    agree = sum(r["agree"] for r in rows)
    print(f"{agree}/{len(rows)} agree (strict, run-1 criterion)")
    print(
        f"{sum(r['agree_loose'] for r in rows)}/{len(rows)} agree (secondary: findings as a set, info-count ignored)"  # noqa: E501
    )
    by = Counter()
    tot = Counter()
    for r in rows:
        p = r["provenance"] or "unlabelled"
        tot[p] += 1
        by[p] += r["agree"]
    for p in sorted(tot):
        print(f"  {p:18s} {by[p]}/{tot[p]}")
    ids = sum(r["capsule_id_identical"] for r in rows)
    print(f"  capsule_id identical: {ids}/{len(rows)}")
    pre = [r for r in rows if "preimage_in_recorded_set" in r]
    if pre:
        print(
            f"  recorded RFC 8785 preimage reproduced byte-for-byte: {sum(1 for r in pre if r['preimage_in_recorded_set'])}/{len(pre)}"  # noqa: E501
        )
    for r in rows:
        print(
            f"{'AGREE' if r['agree'] else ('LOOSE' if r['agree_loose'] else 'DIFF ')}  {r['name']:58s} {(r['provenance'] or '-'):17s} {'; '.join(r['reasons'])}"  # noqa: E501
        )


def main(argv: list[str]) -> int:
    out_json = None
    if "--json" in argv:
        i = argv.index("--json")
        out_json = argv[i + 1]
        argv = argv[:i] + argv[i + 2 :]
    if "--alt" in argv:  # post-hoc sensitivity run only; never the headline
        i = argv.index("--alt")
        V.ALT.update(x for x in argv[i + 1].split(",") if x)
        argv = argv[:i] + argv[i + 2 :]
        print(f"[SENSITIVITY RUN - alternative readings enabled: {sorted(V.ALT)}]")
    root = pathlib.Path(argv[1])
    manifest = json.load(open(root / "vectors.json"))
    rows = [run_case(root, c["name"]) for c in manifest["cases"]]
    summarize(rows, "vectors/capsule")
    canon = [r for r in rows if r["name"].startswith("canonical-")]
    print(
        f"\nJSON-DIGEST group (canonical-*): capsule_id byte-identical {sum(r['capsule_id_identical'] for r in canon)}/{len(canon)}"  # noqa: E501
    )
    prov_rows: list[dict] = []
    if len(argv) > 2:
        proot = pathlib.Path(argv[2])
        names = sorted(
            {line.split()[1].split("/")[0] for line in open(proot / "SHA256SUMS") if line.strip()}
        )
        prov_rows = [run_case(proot, n) for n in names]
        summarize(
            prov_rows, "provenance-mode-vectors (separate corpus; never merged with the headline)"
        )
    if out_json:
        json.dump(
            {"capsule": rows, "provenance_mode": prov_rows},
            open(out_json, "w"),
            indent=1,
            ensure_ascii=False,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
