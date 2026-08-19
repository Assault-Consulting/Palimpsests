# PALA-1 core — post-freeze clarifications

The core specification is frozen at v1.0: no wire byte, no verification
rule, and no §8 expected value changes. What a frozen document can still
do is explain itself better. This file records clarifications — text
that resolves an ambiguity **without changing any verifier's answer** —
so an implementer can tell a decision from an oversight. Entries cite
the independent verification run that surfaced them; that channel
finding real gaps is the process working, not failing.

Licence: CC0-1.0, like the specification.

## C-1 — Span pairing is deliberately not a §7 check (run #5)

**The gap, as reported.** §3.1 promises that a crash leaves a *visibly*
unclosed span, yet §7 defines no span-pairing check — and unlike
`MERKLE_LEAF_COUNT`, whose omission §7.4 justifies explicitly, this
omission was silent. The committed core vectors even demonstrate it:
seq 3 and seq 6 reference span `2222…`, for which no `SPAN_START` and no
`SPAN_END` exist. Two conformant verifiers could differ on whether a
user ever sees that.

**The decision, now stated.** Span structure is deliberately **not**
part of the §7 verdict, for the same reason the verdict is header-only
and body-blind: `chain_ok` answers *"are these the bytes, in order,
complete?"* — a property of the container. Whether spans pair is a
property of what the writer *chose to record*: an unclosed span is
truthful evidence of a crash (§3.1), not damage to the chain, and a
verdict that turned red on truthful evidence would punish honesty.

**Where the promise is operationalized.** The reference reader surfaces
span structure on the **advisory channel** — the same never-a-verdict
channel as referential integrity: `span_unclosed` (a `SPAN_START` with
no `SPAN_END` — §3.1's crash evidence, surfaced) and `span_unopened`
(a span referenced by records with no `SPAN_START` anywhere). Both are
signals for a reader of the chain, never a change to `chain_ok`, exit
codes, or any §8 value. Independent verifiers are encouraged — not
required — to report the same two observations.

## C-2 — §4.3: a promoted node emits nothing into an inclusion proof (run #5)

In an unbalanced tree a node promoted without a sibling contributes no
element to an inclusion proof — which is why proof lengths within one
tree may differ by one. An implementation that pads promoted levels
produces proofs that verify for some leaves and silently differ in
length for others; do not pad. (Both constructions in §4.3 agree at
every leaf count — verified 0–200 in run #5.)

## C-3 — §7.1's `header_len` check, restated for real readers (run #5)

`MUST h.header_len == actual header bytes` cannot fire in a reader that
uses `header_len` to *find* the header. Its operational content is at
the container walk: a `header_len` that overruns the file (or is shorter
than the fixed header) makes the record unparseable — a break at that
position — and a `header_len` inconsistent with the supplied bytes in
an API that receives headers directly is the violation as written.

## C-4 — §2.2 TLV structural rules are §7.4-class checks (run #5)

Whether TLV structural validation is skipped for records of unknown
versions (§7.6) or applied always: it follows the §7.1 pseudocode —
**skipped**. A verifier claims the checks of the version it implements;
a future version's TLV area is opaque bytes under the frozen envelope
rule, hashed but not judged.

## C-5 — Wording: "break" (run #5)

§7.1's pseudocode uses `break` as loop control and `breaks` as a report
array. These are unrelated; the report array is the normative object.

## Implementation count

§11's "four independent implementations — two of them external" was
correct at the freeze. As of 2026-08-18 the count is **five**
implementations, **three** external and unaffiliated (runs recorded
under `independent-runs/`), the fifth in Perl 5 with an
AES-256-GCM implemented from FIPS-197/SP 800-38D and self-tested
against NIST vectors before making any claim about a PALA-1 body.
