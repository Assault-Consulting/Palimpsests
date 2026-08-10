# `AuditReader` — verify and view a PALA-1 file

`AuditReader` scans a container once, verifies its hash chain, and lets you
walk its structure. It is header-only (bodies are decoded lazily, only when
you ask for records) and key-free (an encrypted body is checked against the
digest bound into its header, never opened).

```python
from palimpsests.audit.reader import AuditReader
```

## Constructing

```python
AuditReader.open(path, *, anchor=None)        # mmap a file
AuditReader.from_bytes(data, *, anchor=None)  # wrap an in-memory container
```

Both accept an optional [`anchor`](anchors.md) — an `AnchorSource` supplying
the trusted head for the completeness check. `open()` returns a context
manager; use `with`, or call `close()` to release the mmap.

```python
with AuditReader.open("session.pala") as r:
    v = r.verify()
```

## `verify() -> Verification`

Runs the chain check (question 1), the anchor comparison if an anchor was
supplied (question 2), the advisory pass, and derives a primary diagnosis.
The result is cached; calling `verify()` again is free. `head()` is a
shortcut for `verify().chain.head`.

### `Verification`

| Field | Type | Meaning |
|---|---|---|
| `chain` | `VerifyResult` | The internal-consistency result (see below). |
| `anchor` | `AnchorReading \| None` | The trusted head that was used, with its provenance. |
| `anchor_attempts` | `list[AnchorAttempt]` | Per-source trace of how the anchor was resolved. |
| `complete_to_anchor` | `bool \| None` | Tri-state. `None` = **not checked** (no anchor), never rendered as passing. |
| `anchor_lag` | `int \| None` | Records past the anchored head, when the anchor names an in-chain record. |
| `diagnosis` | `Diagnosis \| None` | The one primary diagnosis, or `None` when nothing failed. |
| `advisory` | `Advisory` | Non-verdict signals; always present. |

### `VerifyResult`

| Field | Meaning |
|---|---|
| `chain_ok` | `True` iff `breaks`, `gaps`, and `violations` are all empty — internal consistency only. |
| `count` | Records verified. |
| `head` | The chain head (32 bytes). |
| `breaks` | Seqs whose `prev_hash` does not name the preceding record. |
| `gaps` | Seqs where the sequence number jumped. |
| `violations` | `(seq, reason)` for normative MUSTs violated on records we understand. |
| `uninterpretable` | Seqs of records with an unknown version/type — chain-checked, reported, never rejected. |
| `complete_to_anchor`, `anchor_lag`, `anchor_reason` | The question-2 fields, mirrored onto `Verification`. |

## `Diagnosis`

When something failed, `verify().diagnosis` names the single most important
pattern (first match wins, in this order). `narrative` states *consistency*
("the evidence is consistent with…"), never intent — a replaced log and a
crash-truncated one can look identical from inside.

| `pattern` | When |
|---|---|
| `truncated_tail` | The container ends mid-record. |
| `prefix_absent` | The first record is not a GENESIS. |
| `seq_gap` | A sequence number is skipped. |
| `chain_break` | A `prev_hash` does not name its predecessor. |
| `record_violation` | A record violates a normative MUST. |
| `unanchored_tail` | The chain extends past the anchored head (a crash between write and anchoring). |
| `replaced_or_rolled_back` | The anchored head names no record in the chain. |

Fields: `pattern`, `at_seq` (`int | None`), `expected` (`str | None`),
`narrative`.

## The advisory channel

`verify().advisory.items` is a list of `AdvisoryItem` — cheap, header-only
signals that **never** affect `chain_ok`, `complete_to_anchor`, or a CLI exit
code. They are hints for a human, not a verdict.

Each item has `code`, `at_seq`, `boot_id`, `detail`. The codes:

- `mono_regression_in_boot` — the monotonic clock went backwards within one boot.
- `wall_regression_in_boot` — the wall clock went backwards within one boot.
- `mid_boot_time_trust_change` — `time_trust` changed mid-boot.
- `anchor_never_written` — the chain carries no ANCHOR record.

A clock reset at a BOOT boundary is normal and is never reported.

## Views

Bodies are decoded the first time you call any of these; `verify()` alone
never touches them.

### `records() -> Iterator[DecodedRecord]`

```python
for rec in r.records():
    print(rec.seq, rec.type_name, rec.kind_name)
```

`DecodedRecord`: `seq`, `index`, `record_type`, `type_name` (`None` for an
unknown type), `header` (`Header | None`), `body_tlvs` (`None` if absent /
encrypted / opaque), `kind` and `kind_name` (resolved only for EVENT/SAFETY
bodies; `None` for an unknown kind).

### `spans() -> list[SpanView]`

`SpanView`: `span_id`, `parent_span_id`, `start_seq`, `end_seq`
(`None` = visibly unclosed — evidence, not an error), `record_seqs`.

### `boots() -> list[BootView]`

`BootView`: `boot_id`, `first_seq`, `last_seq`, `record_count`,
`time_trust_values` (a set; more than one element means a mid-boot change),
`recovery_seq` (the `RECOVERY_TRUNCATED_TAIL` after a resume, or `None`).

### `origin_at(seq) -> OriginView | None`

The model origin in force at a given seq — the latest `MODEL_LOAD` at or
before it, cleared by a `MODEL_UNLOAD`. Origin lives in header TLVs, so this
works even on an encrypted log.

`OriginView`: `role`, `model_digest`, `config_digest`, `since_seq`, `detail`.

## Worked example

```python
from palimpsests.audit.reader import AuditReader
from palimpsests.audit.anchors import ManualAnchor

head_hex = "…64 hex chars from your anchor store…"
with AuditReader.open("session.pala", anchor=ManualAnchor(head_hex)) as r:
    v = r.verify()
    if not v.chain.chain_ok:
        print("tampered:", v.diagnosis.pattern, v.diagnosis.narrative)
    elif v.complete_to_anchor is False:
        print("incomplete:", v.diagnosis.pattern)   # unanchored_tail / replaced_or_rolled_back
    elif v.complete_to_anchor is None:
        print("consistent, but completeness not checked (no anchor)")
    else:
        print(f"verified: {v.chain.count} records, complete to anchor")

    # Structure, once verified.
    for boot in r.boots():
        print("boot", boot.boot_id.hex()[:8], "records", boot.record_count)
```

See [anchors.md](anchors.md) for where the trusted head comes from, and
[tailing.md](tailing.md) for verifying a log that is still being written.
