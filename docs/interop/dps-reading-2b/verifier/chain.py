"""FETCH-BLOCK-HEADER-BY-HEIGHT, VALIDATE-HEADER-ON-CHAIN and CONFIRMATIONS-ON (draft -08, Section 4.1).

This run holds no validated chain. HeaderSet is a test fixture: a set of headers that the CALLER declares to be a
validated view. Constructing one validates nothing; the record says so wherever a result rests on one. The internal
checks of the set (80 bytes, linkage, proof of work against its own bits) are those reading 2 already reported, taken
from its ots_replay.chain_checks, and are recorded as a description of the fixture, not as validation.
"""


class FileHeaderSource:
    """FETCH-BLOCK-HEADER-BY-HEIGHT(H) over a dict {height: {"header": hex}}: 80 bytes or None."""

    def __init__(self, headers_json, label):
        self.h = headers_json
        self.label = label

    def fetch(self, H):
        e = self.h.get(str(H))
        if not isinstance(e, dict) or not isinstance(e.get("header"), str):
            return None
        try:
            b = bytes.fromhex(e["header"])
        except ValueError:
            return None
        return b if len(b) == 80 else None


class HeaderSet:
    """A header set declared validated for a test. mode:
    - "held" (this run's reading, ambiguity log B07): the view establishes the header at H only where it holds a header
      at H equal to the candidate; CONFIRMATIONS-ON counts the held headers at H and above, contiguous from H.
    - "held-or-committed" (the other reading of B07, run only to report what it would give): also where the view
      holds a header at H+1 whose previous-block hash is the double SHA-256 of the candidate; that header then counts
      as established for CONFIRMATIONS-ON.
    """

    def __init__(self, headers, label, r2, mode="held"):
        self.headers = dict(headers)  # {int height: 80 bytes}
        self.label = label
        self.r2 = r2
        self.mode = mode
        self._committed = {}  # H -> candidate established through H+1's prev_hash (mode held-or-committed)

    def validate(self, H, candidate):
        if candidate is None:
            return None
        held = self.headers.get(H)
        if held is not None:
            return candidate if held == candidate else None
        if self.mode == "held-or-committed" and (H + 1) in self.headers:
            prev = self.r2.header_fields(self.headers[H + 1])["prev_hash"]
            if self.r2.sha256d(candidate)[::-1].hex() == prev:
                self._committed[H] = candidate
                return candidate
        return None

    def confirmations(self, H):
        established = set(self.headers) | set(self._committed)
        if H not in established:
            return None
        k = 0
        h = H
        while h in established:
            k += 1
            h += 1
        return k

    def describe(self):
        hs = sorted(self.headers)
        rows = self.r2.chain_checks({str(h): {"header": self.headers[h].hex()} for h in hs}, hs[0]) if hs else []
        return {"label": self.label, "mode": self.mode, "heights": [hs[0], hs[-1]] if hs else [], "count": len(hs),
                "declared_validated_for_the_test": True, "validated_by_this_run": False,
                "internal_checks_not_validation": {
                    "all_80_bytes": all(r["length_80"] for r in rows),
                    "all_proof_of_work_hold_against_own_bits": all(r["proof_of_work_hash_le_target"] for r in rows),
                    "each_links_to_the_one_before": all(r["links_to_previous"] for r in rows[1:])}}
