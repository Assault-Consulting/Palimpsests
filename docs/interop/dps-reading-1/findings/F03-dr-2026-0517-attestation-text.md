# F03. DR-2026-0517 carries text from DR-2026-0412

**For:** Laurent-Lemonnier/dps-scitt-decision-layer. Draft; not filed. Not a divergence in any
check: no dimension of either extension reads these fields.

## Observation

`interop/aqta/approval-record/out/decision-record.json` (DR-2026-0517, a merge of pull request
#4521, inputs "CI run 9142" and "review of the rendered call, view 0517"):

- `mode_classification_attestation.attestation_text_signed` says the release assistant "drafted the
  deploy proposal from CI run 8831 and the dependency audit of 2026-10-23", the inputs of
  DR-2026-0412 (`examples/release-decision`), not of this record.
- `assumptions_depended_on` names "Migration 0042 is reversible within five minutes", and
  `success_criteria` and `re_decision_trigger` are those of DR-2026-0412's release.

## Draft issue text

> **DR-2026-0517 (interop/aqta): attestation text and assumptions name DR-2026-0412's inputs**
>
> At fdc5f63, the aqta record's `attestation_text_signed` names CI run 8831 and the 2026-10-23
> dependency audit, and `assumptions_depended_on` names migration 0042; the record's own
> `required_inputs_used` name CI run 9142 and view 0517, and its decision is a merge. The record is
> sealed as it stands, so changing it means a new seal and, for the person's signature, nothing
> (the approval signs the specification and view digests, not the record). No check of action
> binding or signatures reads these fields; this is a content note only.
>
> Found by an outside reading (dps-reading-1), carried out by an AI assistant under the direction of
> Andrii Sparysh.
