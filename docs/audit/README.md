# Reading and verifying audit logs — the `AuditReader` API

The writer emits [PALA-1](../specs/pala-1/PALA-1.md); this is the public API
for reading one back. Every fact a tool renders — a CLI, a dashboard, a
deployment gate — comes from here; nothing above this layer parses wire
bytes. The API is header-only and key-free: it verifies and structures a log
without any decryption key, and never opens an encrypted body.

APIs on this layer are stabilising and may change before v1.0. The wire
format they read is **frozen at v1.0** — see [PALA-1](../specs/pala-1/PALA-1.md).

## The three questions

Verification answers three different questions with three different inputs,
and this API keeps them separate rather than collapsing them into one
boolean:

1. **Is what I hold internally consistent?** — the hash chain links, no gaps,
   no violated MUSTs. Needs nothing but the file.
2. **Is what I hold all of it?** — the chain head matches a trusted head
   obtained from **outside** the log. Needs an [anchor](anchors.md); without
   one, tail truncation and wholesale replacement are undetectable, and the
   result says "not checked", never "passed".
3. **Did this history exist at time T?** — needs a witness receipt, verified
   by the witness's own protocol (Rekor, RFC 3161), out of scope here.

`chain_ok` means **internally consistent, nothing more** — question 1 alone.
Completeness (question 2) is a separate, tri-state field.

## The pieces

| Doc | Covers |
|---|---|
| [reader.md](reader.md) | `AuditReader` — verify a whole file, then view its records, spans, boots, and origins. `Verification`, `Diagnosis`, the advisory channel. |
| [anchors.md](anchors.md) | The trust seam: `AnchorSource` (`ManualAnchor`, `FileAnchor`, `ChainedAnchorSource`) and `AnchorStore` (`FileAnchorStore`). |
| [tailing.md](tailing.md) | `TailingReader` — follow a growing log live, one event stream over the same verifier. |
| [cli.md](cli.md) | `palimpsests pala verify` — the batch verifier on the command line. |

## Import surface

```python
from palimpsests.audit.reader import (
    AuditReader, Verification, Diagnosis,
    DecodedRecord, SpanView, BootView, OriginView,
)
from palimpsests.audit.anchors import (
    AnchorReading, AnchorSource, AnchorSourceError, AnchorAttempt,
    ManualAnchor, FileAnchor, ChainedAnchorSource,
    AnchorStore, FileAnchorStore,
)
from palimpsests.audit.tailing import TailingReader, TailEvent
```

## Thirty-second example

```python
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.anchors import FileAnchor

# Verify a file against a head kept outside it.
with AuditReader.open("session.pala", anchor=FileAnchor("anchor.head")) as r:
    v = r.verify()
    print("consistent:", v.chain.chain_ok)
    print("complete:", v.complete_to_anchor)   # True / False / None (not checked)
    if v.diagnosis:
        print("diagnosis:", v.diagnosis.pattern, "—", v.diagnosis.narrative)
    for note in v.advisory.items:
        print("advisory:", note.code)           # signals, never a verdict
```
