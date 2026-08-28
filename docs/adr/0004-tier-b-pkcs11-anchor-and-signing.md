# ADR-0004 — Tier B via PKCS#11: the anchor on a token, the signature in one

Status: accepted (2026-08-28) · Scope: audit anchor sources / assurance tiers

## Context

The anchor store answers §7.2's completeness question — "is this the
whole log?" — by holding the current head *outside* the log. Today's
sources (file, OS keychain, manual) share one honest weakness, stated
in SECURITY.md: they live inside the **same host trust boundary** as
the writer. An attacker who owns the host owns the anchor.

Tier B (core §6) names the way out: a head held by hardware the host
can read but not silently rewrite at will, and — part 2 — a signature
made by a key that never leaves that hardware. ANCHOR-SOURCES.md
already catalogues composition; what is missing is the first
non-keychain mechanism in code.

The seam already exists and is not changed by this ADR:
``AnchorSource`` (read) and ``AnchorStore`` (write) protocols,
``AnchorReading`` with provenance, ``ChainedAnchorSource`` recording
named per-link attempts. Keychain and file are existing
implementations; PKCS#11 becomes the next one, behind the same
interfaces, with **no change to default behaviour**.

## Decision

**One mechanism, one path.** PKCS#11 through ``python-pkcs11``, behind
a new extra ``[pkcs11]``; the base install is untouched and the module
is import-safe without the extra (the ``serve``/``bodies``/``scitt``
pattern). No token-zoo support in 0.11: SoftHSM2 is the tested module;
compatibility items for specific HSMs are issues opened on real
demand.

**(a) Anchor — the head as a token object.** A ``CKO_DATA`` object
(``LABEL = "pala-anchor-head"``, ``APPLICATION = "palimpsests"``,
``VALUE`` = the 32-byte head, ``TOKEN = TRUE``).

- *Read* (``Pkcs11Anchor``, ``source_kind = "pkcs11"``): zero matching
  objects is ``None`` — absent is normal, not an error. One object
  with a 32-byte value answers. Anything else — unreachable module,
  missing token, wrong PIN, a value of the wrong length, *multiple*
  matching objects — raises ``AnchorSourceError`` with the source
  identity attached: present but unreadable must never degrade into
  silently absent.
- *Write* (``Pkcs11AnchorStore``): destroy-then-create in one
  read-write session. PKCS#11 has no atomic replace; the window
  between destroy and create is visible to a concurrent reader as
  **absent**, never as a torn value — strictly better failure shape
  than a half-written file, and stated here rather than discovered.
  ``meta`` is accepted for interface compatibility and not persisted:
  the token object is the head, nothing else.

**(b) Signature — part 2, the same plumbing.** The session/extra/CI
harness built for (a) carries the signing operation: an EC P-256
private key generated on-token (``CKA_EXTRACTABLE = FALSE``),
``C_Sign`` over the head, the result riding as a ``WITNESS_RECEIPT`` —
additive, the wire unchanged. The software emission of a COSE_Sign1
over the head already landed via the SCITT bridge; part 2 is the same
operation with a key that cannot leave the token. Verification in the
reader/bundle is advisory-level, never a verdict.

**Failure semantics: inherited, not invented.** Failures are counted,
not swallowed; ``head_anchored = False`` stays honest; a chain of
sources records every link's outcome under its name. ``pkcs11``
becomes one more named source in the attempts list — the report's
anchor-provenance block (and Auditor's rendering of it) gains a second
neighbour next to ``keychain`` with no schema change.

**CI: SoftHSM2 only, and what that does *not* claim.** SoftHSM2 is
deterministic, free, and runs on all three CI OSes — and it is
software. Therefore, everywhere this feature is described:

> The tier-B *mechanism* is shipped and tested. A tier-B *claim* for a
> concrete deployment requires a real token or HSM holding the anchor
> (and, for part 2, the key). SoftHSM in CI proves the code path, not
> the tier.

An acceptance run on a physical token (YubiKey/Nitrokey) follows the
WS-H logic: done when hardware is in hand, off the critical path.

## Stated limits (part 2, said first)

A hardware signature over the head proves **the act of signing by the
key's holder** — a compromised host cannot extract the key, but it can
present the token anything to sign. The signature does not establish
the truthfulness of the log's contents, and it does not establish
"existed by": that is the time witness's job (tier C — SCITT receipt
first, RFC 3161 as the offline fallback), a separate track. In our
words: *the head becomes bound to a hardware identity that cannot be
copied off the host* — not "legal non-repudiation".

## Consequences

- New extra ``[pkcs11]``; new module ``audit/anchors_pkcs11.py``; no
  default-path change; wire untouched.
- Tests run against SoftHSM2 and skip cleanly where no PKCS#11 module
  is present, so a bare checkout stays green; CI gains a SoftHSM setup
  step (separate, mechanical change).
- ANCHOR-SOURCES.md, SECURITY.md and the compliance mapping get the
  claim-honesty wording above when the mechanism lands.
- Part 2 not landing in 0.11 is a calendar fact, not a design change:
  the seam, the extra and this ADR already carry it.
