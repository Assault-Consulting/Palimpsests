# Evidence vs observability — choosing an audit substrate by checkable criteria

The keyword field around "tamper-evident logging" and Article 12 has
filled up. The procurement conversation, meanwhile, has sharpened into
one question: **will your auditor be able to reproduce a specific
recorded action eighteen months from now — without trusting anyone's
word for it?** This document turns that question into criteria that can
be checked, and answers them for this repository.

**Claim form.** Criteria first; no product is named and nothing here
ranks vendors. Other approaches appear as *classes*, described by their
design center, with statements tied to the public standards that define
them — for any specific product, ask the vendor the questions in §4 and
check the answers. Our own column claims only what this repository
proves: every cell links to a spec section, a shipped artifact, or a
recorded run. This is positioning, not legal advice.

## 1. The axis: where does trust live?

Every logging approach answers one question differently — **what do you
have to trust to believe the log?**

- **Platform-anchored** (enterprise log platforms, WORM retention,
  ledger services): integrity is enforced by the platform — access
  controls, retention locks, internal attestations. The evidence is as
  strong as your trust in the operator and their controls, and
  verification usually happens *inside* the platform.
- **Pipeline-anchored** (observability stacks: syslog
  [RFC 5424](https://www.rfc-editor.org/rfc/rfc5424), OpenTelemetry
  [spec](https://opentelemetry.io/docs/specs/otel/)): built for
  operating systems in production — rich telemetry, superb tooling. The
  transport and schema are standardized; a tamper-evidence contract is
  not part of the format. Integrity, where present, is added by the
  platform underneath — which returns you to the row above.
- **Format-anchored** (transparency-log lineage: Certificate
  Transparency [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162),
  COSE [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052), SCITT
  [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943); PALA-1 here):
  integrity properties live in the byte format itself. The artifact is
  the evidence: anyone with the spec can re-derive every claim offline,
  with no account, no API, and no code from the producer.

A fourth group borrows the vocabulary of the third without its
obligations: **hash-chain libraries** (typically JSONL + SHA-256 chain
linking). The chain is real; what makes a chain *auditable* — a frozen
wire spec, byte-exact public vectors, independent implementations, an
offline verification protocol — is a separate, checkable list, and it
is the list below.

## 2. The criteria, checked

"Ours" = this repository, at the tags and commits named in each link.
"Typical for class" describes the design center, not any particular
product — a specific product may do better; ask (§4).

| Criterion (checkable) | This repo (PALA-1) | Platform-anchored | Pipeline-anchored | Hash-chain libraries |
|---|---|---|---|---|
| Frozen, versioned wire spec with change rules | **Yes** — PALA-1 v1.0, frozen at tag `pala1-v1.0` ([spec §11](specs/pala-1/PALA-1.md)); additive-only evolution rules | Storage format typically proprietary; the contract is the platform API | Transport/schema standardized (RFC 5424, OTel); no integrity clauses in the format | Typically none — the library *is* the spec |
| Byte-exact public test vectors | **Yes** — [`test-vectors.json`](specs/pala-1/test-vectors.json), digest `476c05ce…8193`, byte-identical since the freeze | Typically not published | Not applicable to the format's goals | Typically absent |
| Independent verifier implementations, on record | **Five, three external** — the fifth in Perl from core modules alone; runs, ambiguity logs and defects filed in-repo ([INDEPENDENT-VERIFICATION.md](specs/pala-1/INDEPENDENT-VERIFICATION.md), [`independent-runs/`](specs/pala-1/independent-runs/)) | Verification happens inside the platform | Many *consumers*; verification of integrity is not the format's contract | Typically the author's implementation only |
| Offline verification without producer code | **Yes, by construction** — spec + vectors suffice; proved by the external runs; a [self-service kit](specs/pala-1/INDEPENDENT-VERIFICATION.md) packages the protocol; `pala verify` is a convenience, never a dependency | Requires the platform (account, API, attestation) | Requires the platform underneath | Usually requires the library itself |
| Selective disclosure with inclusion proofs | **Yes** — Merkle tree over records (spec §4.3); proofs ride in the evidence bundle ([`pala bundle`](../CHANGELOG.md), format `pala-bundle/1`) | Varies; usually platform-internal | Not a goal | Rarely |
| Machine-readable verification verdict with one schema owner | **Yes** — `pala-verification-report/1` with an in-repo JSON Schema; completeness never silently true | Platform-defined | Not applicable | Typically absent |
| Truncation caught, not silenced | **Yes** — completeness against an out-of-band anchor (spec §7.2): a truncated tail fails the anchor check; an archived-away prefix reports exactly one explicit violation | Retention locks help; verification remains platform-side | No | A bare chain cannot see its own truncation without an anchor protocol |
| Cost of integrity, measured — and measured *independently* | **Yes** — in-repo harness ([`benchmarks/`](../benchmarks/bench_cose_compare.py), rules in [BENCHMARKING.md](BENCHMARKING.md)) **plus** a contamination-bounded independent run in-tree ([REPORT](specs/pala-1/independent-runs/oleksandr/serialization-cost/REPORT.md)): chain hashing vs per-record signing, honest floor 45–61× on write / 116–168× on verify (native primitives, workstation upper bound) | Rarely published for the integrity layer | Overhead well studied; integrity is not the measured object | Rarely measured |
| Where trust lives | **In the format** — the artifact self-verifies offline | In the platform and its operator | In the platform underneath | In the author's code |

Two honest counterweights, stated at equal prominence: **(1)** a
COSE_Sign1-signed statement is *self-evidencing* — it proves its origin
standing alone, which a PALA-1 record deliberately does not (the
chain's per-record saving is bought by that weaker standalone
property); this repo therefore *bridges to* SCITT (checkpoint →
Signed Statement, [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943)
vocabulary) rather than competing with it. **(2)** observability
pipelines solve a different, real problem — operating systems — and
nothing here argues against running one *next to* an evidence log; the
argument is only against calling one an evidence log.

## 3. Why the axis is the differentiator

One criterion separates both ends of the market at once. Ask *"can my
auditor re-derive this specific record's integrity in eighteen months,
offline, from the artifact alone?"* —

- the platform-anchored answer is *"yes, if the platform still exists,
  your access still works, and you trust its attestation"*;
- the hash-chain answer is *"yes, if you run my code and trust that it
  does what I say"*;
- the format-anchored answer is *"yes — here is the frozen spec, here
  are the byte vectors, five people have already done it, one of them
  in Perl with no dependencies at all."*

That last sentence is the product.

## 4. The questions to ask any vendor (including us)

Criteria are only useful if they survive contact with procurement.
These five questions are the table above in RFP form — every one has a
yes/no answer that can be checked, and our answers are the links in §2:

1. Is the wire format's spec public, versioned, and frozen — and what
   are the change rules?
2. Are there byte-exact public test vectors, and is their digest
   pinned?
3. How many verifier implementations exist that were written *without
   reading your code* — and where are those runs recorded?
4. Can an auditor verify a log offline, with no account and none of
   your software? What exactly do they need?
5. When the log is truncated or a prefix is archived away, what does
   verification report — and to whom?

A "no" on any of these is not a scandal; it is a scoping fact. It
means integrity is being supplied by something other than the format —
and *that something* is what the auditor will have to trust in month
eighteen.

## 5. Related documents

- Regulatory mapping: [EU-AI-ACT-MAPPING.md](compliance/EU-AI-ACT-MAPPING.md)
  (Article 12; claim form and status legend), [24970-MAPPING.md](compliance/24970-MAPPING.md).
- Positioning inside the transparency-log lineage: [POSITIONING.md](POSITIONING.md).
- Measured storage/retention math: [RETENTION.md](RETENTION.md).
- Verification protocol and the recorded runs:
  [INDEPENDENT-VERIFICATION.md](specs/pala-1/INDEPENDENT-VERIFICATION.md).
