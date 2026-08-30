# Ambiguity log

Every place a standard or the published material admitted more than one
reading during this run, including the ones resolved correctly on the
first attempt. Ordered roughly by how much they cost.

---

## A1 — "ascending order" is not the same predicate as RFC 8949 §4.2.1

**Where.** `statement_inputs.protected_header_order_note`: *"labels appear
in ascending order (1, 3, 4, 15) - RFC 8949 section 4.2.1 deterministic
form"*.

**The ambiguity.** These are two different rules stated as one. RFC 8949
§4.2.1 sorts map entries by the **bytewise lexicographic order of the
encoded keys**, not by the numeric value of the keys. For the labels
actually present they coincide — `1, 3, 4, 15` encode as
`01, 03, 04, 0f`, ascending both ways — so nothing goes wrong here.

They stop coinciding the moment a negative label appears, because CBOR
encodes negative integers in major type 1: label `-1` encodes as `0x20`,
which sorts **after** `0x0f` (label 15) bytewise, but before every
positive label numerically. A header carrying, say, label `-1` would be
ordered differently by the two readings, and only one of them is §4.2.1.

**How resolved.** Checked both predicates separately and asserted both
hold. See A3 for the case where this distinction actually decides the
answer.

**Suggestion.** State the bytewise rule alone; "ascending" is a
coincidence of this label set, not the rule.

---

## A2 — RFC 9679 required-member set for an OKP key

**The ambiguity.** RFC 9679 computes the thumbprint over the *required*
members of the key. Which members are required is per key type, and an
implementer has to decide whether `kid`, `alg`, or `key_ops` — often
present on a real COSE key — participate. For OKP I took exactly
`kty` (1), `crv` (-1), `x` (-2), excluding everything else including the
private `d`.

**How resolved.** The digest matched, which retroactively confirms the
member set. Before it matched there was no way to tell a wrong member set
from a wrong ordering or a wrong hash — all three fail identically, as 32
bytes that are simply not equal.

---

## A3 — the RFC 9679 map ordering, where A1's distinction bites

**The ambiguity.** Same bytewise-vs-numeric question as A1, but here the
two readings give **different answers**:

| ordering | encoded map | SHA-256 |
|---|---|---|
| §4.2.1 bytewise `{1, -1, -2}` | `a301012006215820d75a98…511a` | `866eefbd…415743` ✅ matches the vector |
| numeric ascending `{-2, -1, 1}` | `a3215820d75a98…511a20060101` | `d21c7849…a2db` ❌ |

The vector's `kid` is the bytewise/§4.2.1 form, which is correct. But an
implementer who reads `kid_note`'s *"RFC 9679 COSE Key Thumbprint
(SHA-256)"* and reaches for the intuitive numeric ordering gets a
non-matching 32-byte value with **no diagnostic that points at ordering**
— the failure looks identical to a wrong key, a wrong hash, or a wrong
member set.

**How resolved.** Computed both candidates and reported which one the
vector used. This is the basis of finding F-4.

---

## A4 — `external_aad` is never stated

**The ambiguity.** RFC 9052 §4.4 puts `external_aad` in the
Sig_structure as a required third element, but the vector never says what
its value is. It is *conventionally* the empty bstr when there is no
external data, and the task file's step 5 quotes the array shape without
naming the value.

**How resolved.** Assumed `h''`. That is the only value consistent with
the published signature — but the confirmation is the signature verifying,
which is circular reasoning if the goal is to check the vector rather
than match it. A one-line statement (`external_aad = h''`, 275-byte
Sig_structure) would make this checkable in its own right.

---

## A5 — whether a *verifier* must reject the untagged form

**The ambiguity.** `byte_stability.3` establishes that this statement **is**
the tagged form and that an untagged re-encoding is a different artifact.
It does not say what a verifier should do on encountering the untagged
form. RFC 9052 permits COSE_Sign1 both tagged and untagged, and the
tamper expectation only requires that a *byte-exact consumer* treat it as
different.

**How resolved.** Implemented `require_tag` as a switch, defaulting to
reject, and reported both: the untagged form is rejected by a
tag-requiring parser (T5c) **and** still carries a cryptographically
valid signature (T5d). Tag presence is an artifact-identity question, not
a crypto one — which is the point of mode 3, made explicit.

---

## A6 — the payload's integer keys collide with CWT claim keys

**The ambiguity.** The payload is `{1: bstr, 2: uint, 3: uint, 4: tstr}`.
CWT (RFC 8392 §3.1.1) assigns 1 = `iss`, 2 = `sub`, 3 = `aud`,
4 = `exp`. A parser that decides "COSE_Sign1 payload ⇒ CWT Claims Set"
— not an unreasonable default in a SCITT context, where CWT claims are
already in play under header label 15 — reads this statement as:

```
iss = <32 raw bytes>      (CWT wants a tstr)
sub = 0                   (CWT wants a tstr)
aud = 11                  (CWT wants a tstr)
exp = "pala-1/v1.0"       (CWT wants a numeric date)
```

Every one of those is type-mismatched, so a strict CWT parser errors out
— but it errors out *confusingly*, and a lax one may not error at all.

**How resolved.** Confirmed the protected content type
(`application/vnd.palimpsests.pala1-head+cbor`) is present and is not
`application/cwt`, which is precisely what forbids the CWT reading. This
validates the rationale behind B1's F2; the vector's
`content_type_note` already says this, and it is correct.

---

## A7 — duplicate map keys have no stated required behaviour

**The ambiguity.** RFC 8949 §5.6 says a map with duplicate keys is
**invalid**, but such an encoding is still *well-formed* — a
length-driven decoder walks it happily. Neither the vector nor the task
says what a verifier must do. It matters here because the duplicated key
could be label 4: which duplicate a decoder keeps decides the `kid`, and
two decoders can disagree about the key a statement names while both
report a valid signature.

**How resolved.** Our decoder preserves all pairs and surfaces the
duplication rather than silently collapsing it (a dict-building decoder
keeps one, typically the last). Reported as adversarial case A11; not
raised to a finding because the vector's statement itself is clean.

---

## A8 — `content_type` may be a tstr or a uint

**The ambiguity.** COSE header label 3 accepts either a text string
(a media type name) or an unsigned integer (a CoAP Content-Format ID).
Both are legal; a verifier must handle whichever arrives.

**How resolved.** Trivially — the vector uses a tstr, and its
`content_type_note` flags "Vendor tree, unregistered", which correctly
implies no CoAP Content-Format ID exists for it. Logged only for
completeness.

---

## A9 — the v1 supersession claim is unverifiable inside the boundary

**Where.** `supersedes`: *"v1 (commit 296f331, sha256 bf81026143d0…9491)"*.

**The ambiguity.** None, semantically — but checking it requires reading
this repository's commit history, which the contamination boundary
forbids until the report is submitted. So it is asserted, not verified,
by this run. Noted so the record does not imply otherwise.

---

## A10 — RFC 8032's `0 <= S < L` check is easy to read as optional

**The ambiguity.** RFC 8032 §5.1.7 states the range check on `S` as part
of verification, but it reads as a decoding precondition rather than a
security-relevant step, and a naive implementation of the verification
equation `[S]B = R + [k]A` works without it — the equation holds for
`S + L` too, since `[L]B` is the identity. The result is a second valid
signature over identical content.

**How resolved.** Implemented the check, made it switchable, and
demonstrated both behaviours (adversarial A5a/A5b). This is the basis of
finding F-2. Logged here as well because the ambiguity is in the *RFC's
presentation*, not in the vector — the vector simply does not mention
malleability, which is what F-2 asks it to fix.
