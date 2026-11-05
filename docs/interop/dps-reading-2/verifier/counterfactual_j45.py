"""Finding F01: vectors.json /beside_results/st_a names key witness-a-1, while /scitt/statements/st_a is signed by
witness-a-scitt-1 under kid witness-a-scitt-1. This reruns J45, J46 and J47 with that one value changed to the
statement's own key, to see what each case then tests. Not part of the suite counts.
Usage: python counterfactual_j45.py INPUTS_DIR OUT_FILE"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_suites as RS  # noqa: E402

def main():
    env = RS.Env(sys.argv[1])
    st = env.V["beside_results"]["st_a"]
    before = (st["signature"]["key_ref"], st["key_state"]["key_ref"])
    st["signature"]["key_ref"] = "witness-a-scitt-1"
    st["key_state"]["key_ref"] = "witness-a-scitt-1"
    env.C["pairing_cases"] = [c for c in env.C["pairing_cases"] if c["id"] in ("J45", "J46", "J47")]
    res = RS.run_pairing(env)
    out = {"changed": "/beside_results/st_a/signature/key_ref and /key_state/key_ref: %s -> witness-a-scitt-1" % (before,),
           "results": res}
    with open(sys.argv[2], "w") as f:
        json.dump(out, f, indent=1)
    print(json.dumps(out, indent=1))

if __name__ == "__main__":
    main()
