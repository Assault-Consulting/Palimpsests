# F02. The aqta negatives publish results, not the documents they were computed on

**For:** Laurent-Lemonnier/dps-scitt-decision-layer. Draft; not filed.

## Observation

At `fdc5f63`, each of `interop/aqta/approval-record/out/negatives/N1-…json` to `N7b-…json` holds a
`what` (a sentence) and a `result` (verdicts per dimension, with findings). None holds the changed
action-binding attachment, signatures attachment or trust policy the result was computed on.
`negatives/summary.json` repeats the results.

Consequences for an outside reading:

- The negatives cannot be rerun as published. This reading rebuilt them from the `what` text,
  inventing what the text does not fix (N3's signature by `someone-else-key-1`, N3b's public key,
  N7's other policy digest, N6's exact times).
- Each file is, in the terms of the reading's prompt, "someone else's results": opening a negative
  to find its input shows its verdicts. In this reading they were read before any verdict was
  recorded, so the agreement reported for N1–N7b is not independent.

## Draft issue text

> **interop/aqta negatives: publish the inputs beside the results**
>
> At fdc5f63, `negatives/N*.json` carry a description and the verdicts, not the documents. An
> outside verifier cannot rerun them, and cannot open one to find its input without seeing its
> expected result. Could each negative publish its inputs in their own files (the changed
> `action-binding-attachment.json`, `signatures-attachment.json`, `trust-policy.json` and, for N4
> and N5, `policy.json`), with the verdicts kept in a separate file (or only in
> `negatives/summary.json`)? N3 would need the signature by `someone-else-key-1` itself.
>
> Found by an outside reading (dps-reading-1), carried out by an AI assistant under the direction of
> Andrii Sparysh.
