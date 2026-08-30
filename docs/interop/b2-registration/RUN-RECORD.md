# Run record: B.2/B.4 — registering a PALA-1 Signed Statement, verifying the receipt

**Result: registered (HTTP 201) and the receipt verified.** One
statement in the vector-v2 construction, over a purpose-built PALA-1
chain, registered with a self-operated SCRAPI-compatible transparency
service; the receipt's ES256 signature verified against the service's
published key over the RFC 9162 root reconstructed from its own
inclusion data. Three findings, one of them ecosystem-level.

## What this run is and is not

- **Association:** a project-side interop exercise, executed by an AI
  agent (Claude) at the direction of maintainer Andrii, using the
  project's own code throughout. This is **not** an independent or
  clean-room run and claims no contamination boundary — the bridge
  runs B1/B2 hold that role for the statement side.
- **The service is self-operated.** The claim is exactly: *registered
  with a conforming SCRAPI-compatible implementation
  ([vcon-dev/scittles](https://github.com/vcon-dev/scittles) at
  `6653ab2`), operated by the project for this run; receipt verified
  using the service's published key and the service's own
  merkle/verification modules.* A third-party-operated registration is
  a distinct, stronger claim and remains open (see INTEROP-SCITT.md).
- **Existence-in-time is only as durable as the service instance.**
  This run demonstrates the pipeline end to end; it does not claim
  durable witnessing.
- The signing key is a per-run Ed25519 key generated inside the run
  and retained by the maintainer. The published test-vector key was
  not used anywhere near the service.

## Procedure and evidence (digests in `artifacts.json`)

1. **Chain**: fresh 4-record PALA-1 chain (705 B), `chain_ok` true;
   `pala verify` exit 2 — PARTIAL, no anchor supplied, stated rather
   than hidden. Head `41082765…eea4d1`.
2. **Statement**: 345 B, the vector-v2 construction — EdDSA; `kid` =
   RFC 9679 thumbprint and the content type in the *protected* header;
   CWT `iss`/`sub` with the **full** head. Self-verified with
   `check_statement_against_head` before leaving the process.
3. **Registration**: `POST /entries` → **201**, `Location` carrying
   the entry id. The registration-time receipt and a later
   `GET /entries/{id}` receipt are byte-identical (131 B).
4. **Round-trip**: `GET /signed-statements/{id}` returned the
   submitted statement byte-for-byte.
5. **Receipt verification** (the service's protocol): the receipt is a
   COSE_Sign1 (ES256, service key from `/jwks`) whose payload is
   **detached and equals the Merkle root** — a verifier must
   reconstruct the root from the inclusion data before the signature
   can be checked, which authenticates the proof despite its
   unprotected-header location. Reconstructed root
   `064bf68d…616983` (tree_size 1, leaf_index 0, empty path);
   inclusion re-checked with the service's own
   `src.core.verification.verify_inclusion`; **signature over the
   reconstructed root: valid.**

## Findings

- **B4-F1 (ecosystem, substantive).** `cbor2` ≥ 6 decodes a tag's
  array value as a **tuple**; `pycose` 1.1.0's decoder requires a
  `list`, so **every tagged COSE message fails to decode** under that
  pair — the first registration attempt died with the service's
  generic "Bytes cannot be decoded as COSE message", and a six-probe
  bisection showed even `{alg}` alone failing. The service's own pin
  (`cbor2>=5.6.0`) admits the broken combination, so a fresh install
  today cannot accept any tagged statement. One-line fixes on either
  side: `isinstance(value, (list, tuple))` in pycose, or `cbor2<6` in
  scittles. Resolved locally by pinning `cbor2==5.6.5`; the
  palimpsests stack itself is agnostic (it unpacks the tag value
  positionally) and its 15 scitt tests pass under both majors with
  byte-identical statements.
- **B4-F2 (service design).** The entry identity — and the Merkle
  leaf — is **sha256 of the statement's *payload***, not of the
  signed statement: two distinct COSE_Sign1 messages over one payload
  (different keys, different headers) collide into a single entry, and
  the second registration is refused as a duplicate. The signature and
  issuer are not part of the logged identity. This is the
  `byte_stability` lesson of the vector, resurfacing at the service
  layer: *"the signature verifies"* and *"these bytes are what the log
  identifies"* are different claims — a consumer must know **which
  identity a given service logs**.
- **B4-F3.** The receipt's CWT claims carry the service-default
  issuer; the statement's own `iss`/`sub` are not propagated. Binding
  of receipt to statement is therefore by the leaf alone.

## Files

| file | what |
|---|---|
| `artifacts.json` | every artifact as hex + SHA-256: chain, statement, receipt, jwks, entry id, root, verification detail |
| `transcript.txt` | the raw stdout of the registration and verification runs, including the leaf-definition probes |

Reproduction: any party can re-run the whole loop from `artifacts.json`
alone — re-verify the chain from its hex, the statement against the
head, and the receipt against the embedded jwks — or stand up scittles
at the recorded commit (with `cbor2<6`) and register the same
statement afresh.
