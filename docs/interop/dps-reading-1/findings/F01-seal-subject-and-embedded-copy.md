# F01. Signatures 0.2.0: does a disagreeing copy fail the seal's `subject`?

**For:** decision-provenance-standard/standard (extension text or cases). Draft; not filed.

## Divergence

Seal cases O06 and O46, at `c904372`.

| Case | Input | This reading | Case expects |
|---|---|---|---|
| O06 | `seal_attachment`; the attachment's `issuer_signature.value_b64` replaced by `seal_attachment_102`'s value | subject verified, embedded_copy failed, status verified | subject failed, embedded_copy failed, status failed |
| O46 | `seal_attachment_copy_other_time`: copy `sealed_at` 09:35, seal 09:30, same value, sealed so by the issuer | subject verified, embedded_copy failed, status verified | subject failed, embedded_copy failed, status failed |

First differing field: `organisation_seals[i].subject.status` (then `status`). Signature, key
state, certificate and `embedded_copy` agree. In both cases the sealed digest (the attachment's
bytes with the copy's value replaced by `A`) equals `sealed.digest`: O06's own description says
"the digest with A still matches", O46's "the digest matches the attachment as issued".

## What the text says

- "A verifier checks a seal as follows, and reports each as its own dimension: `signature` (...),
  `subject` (the sealed digest against the document: ...; the attachment's bytes as issued with the
  copy replaced by `A`; ...) and `key_state` (...). The seal is verified only when all three are."
- "The verifier does the reverse and compares; it also reports whether the copy agrees with the
  seal (`embedded_copy`)".

Read literally, `subject` is the digest comparison and `embedded_copy` is reported beside it, so a
disagreeing copy leaves the seal verified. The cases make the copy's agreement part of `subject`.

## Who is at fault

Either the text or the cases; this reading cannot tell which was intended. If disagreement should
fail the seal, the text does not say so. If it should not, O06 and O46 expect too much.

## Draft issue text

> **Signatures 0.2.0: is a disagreeing `issuer_signature` copy a failure of the seal's `subject`?**
>
> At c904372, the README defines a seal's `subject` as "the sealed digest against the document"
> (for an attachment, its bytes with the copy's value replaced by `A`), reports the copy's
> agreement as a separate `embedded_copy`, and says the seal is verified when `signature`,
> `subject` and `key_state` are. Seal cases O06 and O46 expect `subject: failed` and
> `status: failed` where the sealed digest matches and only the copy disagrees (O06: another
> seal's value in the copy; O46: another `sealed_at`).
>
> An implementation written from the text reports `subject: verified`, `embedded_copy: failed`,
> `status: verified` for both. Could the text say which is meant? For example, under "The
> organisation's seal": "Where the attachment carries a copy, `subject` is verified only when the
> sealed digest matches and the copy agrees (`embedded_copy`)." Or, if the copy is meant to stay
> apart, O06 and O46 could expect `subject: verified`, `status: verified`.
>
> Found by an outside reading of the text (dps-reading-1), carried out by an AI assistant under the
> direction of Andrii Sparysh.
