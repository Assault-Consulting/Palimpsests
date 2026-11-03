# F-08 — The reading's input set: a schema the core schema needs

For: the reading's own script (Andrii Sparysh). Not for either repository. Not filed.

**Minimised:** `standard/v5.0/schemas/decision-record.schema.json` refers to `../mode-drift/layer-4-attestation.schema.json`. The file is not among the pinned inputs. Lemonnier's two records carry `mode_classification_attestation`, so their core-schema validation was partial: that member's subschema was unchecked.

**Proposed:** for the next reading, add `standard/schemas/mode-drift/layer-4-attestation.schema.json` (or its path at the pinned commit) to the fetch script, with its SHA-256.
