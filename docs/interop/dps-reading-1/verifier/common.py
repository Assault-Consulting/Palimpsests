import os, sys, json
from strictjson import loads, dumps_compact
from ab_check import sha256_hex

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STD = os.path.join(ROOT, "inputs", "standard")
LL = os.path.join(ROOT, "inputs", "lemonnier")

def load_strict(path):
    with open(path, "rb") as f:
        return loads(f.read())

def agg(statuses):
    order = ["failed", "unavailable", "not_checked", "not_supported", "verified"]
    for s in order:
        if s in statuses:
            return s
    return "verified"

class Recorder:
    def __init__(self):
        self.rows = []
    def add(self, suite, cid, ok, detail=None, attempted=True, why=None):
        r = {"suite": suite, "id": cid}
        if not attempted:
            r["result"] = "not attempted"
            r["why"] = why
        else:
            r["result"] = bool(ok)
            if detail:
                r["detail"] = detail
        self.rows.append(r)
