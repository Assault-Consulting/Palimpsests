"""Builds out/report.json: one boolean or "not attempted" per check, with totals. Usage: python make_report.py OUT_DIR"""
import json
import os
import sys

NA = "not attempted"


def main():
    out = sys.argv[1]
    rep = {"reading": "dps-reading-2", "carried_out": "by an AI assistant under the direction of Andrii Sparysh",
           "anchoring_checkpoint": {}, "opentimestamps_replay": {}, "totals": {}}
    for suite in ("schema_cases", "vector_cases", "timestamp_cases", "checkpoint_cases", "pairing_cases"):
        rows = json.load(open(os.path.join(out, "final", suite + ".json")))
        d = {}
        for r in rows:
            d[r["id"]] = r["agree"] if r["agree"] in (True, False) else NA
        if suite == "vector_cases":
            # V16 is split: the vectors against the case's values, and the case's values against RFC 9500's text
            d["V16a_vectors_equal_case_values"] = d.pop("V16")
            d["V16b_case_values_equal_rfc9500_text"] = NA
            d["V06b_rsa_key_equals_rfc9500_text"] = NA
        rep["anchoring_checkpoint"][suite] = d
    ots = json.load(open(os.path.join(out, "ots-replay.json")))
    for name, p in ots["proofs"].items():
        d = {}
        for k, v in p.items():
            if isinstance(v, bool):
                d[k] = v
        d["file_size_equals_d4"] = p["file_size"]["holds"]
        for i, b in enumerate(p.get("branches", [])):
            for k, v in b.items():
                if k == "value_after_op43_reversed_begins_3cad384e":
                    continue  # recorded in ots-replay.json to show which byte order D.4 prints; not a check (A25)
                if isinstance(v, bool):
                    d["bitcoin_branch_%d.%s" % (i, k)] = v
                elif isinstance(v, dict) and all(isinstance(x, bool) for x in v.values()):
                    for s, x in v.items():
                        d["bitcoin_branch_%d.%s.%s" % (i, k, s)] = x
            d["bitcoin_branch_%d.step7b_header_on_validated_chain" % i] = NA
            d["bitcoin_branch_%d.step9_confirmations_on_validated_chain" % i] = NA
            d["bitcoin_branch_%d.header_cross_checked_with_block_explorer" % i] = NA
            d["bitcoin_branch_%d.median_time_past" % i] = NA
        rep["opentimestamps_replay"][name] = d
    hc = ots["header_chain_summary"]
    rep["opentimestamps_replay"]["header_chain_957289_957300"] = {
        "all_80_bytes": hc["all_80_bytes"], "all_proof_of_work_hold": hc["all_proof_of_work_hold"],
        "all_link_to_previous": hc["all_link_to_previous"], "same_bits_throughout": hc["same_bits_throughout"],
        "validated_from_genesis_or_held_checkpoint": NA}
    rep["opentimestamps_replay"]["constants_copied_from_draft_found_in_draft"] = not ots["constants_not_found_in_draft"]

    def tot(d):
        vals = []
        for v in d.values():
            if isinstance(v, dict):
                vals += list(tot_vals(v))
            else:
                vals.append(v)
        return vals

    def tot_vals(d):
        for v in d.values():
            if isinstance(v, dict):
                yield from tot_vals(v)
            else:
                yield v

    for part in ("anchoring_checkpoint", "opentimestamps_replay"):
        rep["totals"][part] = {}
        for k, v in rep[part].items():
            vals = list(tot_vals(v)) if isinstance(v, dict) else [v]
            rep["totals"][part][k] = {"true": sum(1 for x in vals if x is True), "false": sum(1 for x in vals if x is False),
                                      "not_attempted": sum(1 for x in vals if x == NA)}
    with open(os.path.join(out, "report.json"), "w") as f:
        json.dump(rep, f, indent=1)
    print(json.dumps(rep["totals"], indent=1))


if __name__ == "__main__":
    main()
