# `TailingReader` — follow a log as it is written

`TailingReader` is the live counterpart to [`AuditReader`](reader.md). Both
drive the same single verifier, so a chain verified live and the same chain
verified after the fact give identical answers. Use it for a dashboard that
watches an in-flight session, or a supervisor that reacts to records as they
land.

```python
from palimpsests.audit.tailing import TailingReader, TailEvent

TailingReader(path, *, anchor=None, poll_interval=0.5, torn_grace=5.0)
```

It polls with `os.stat` (no inotify/watchdog dependency); `poll_interval` is
your dial. `torn_grace` is how long a partial tail may sit unchanged before it
is called a truncation.

## `events() -> Iterator[TailEvent]`

A blocking generator: iterate it and act on each event. It runs until
`close()`.

```python
tr = TailingReader("live.pala")
for ev in tr.events():
    if ev.kind == "record":
        handle(ev.record)                 # a DecodedRecord
    elif ev.kind == "anchor_seen":
        publish_head(ev.record.seq)       # e.g. hand the head to a witness
    elif ev.kind == "diagnosis":
        alert(ev.detail); break
```

### `TailEvent`

`kind`, `seq` (`int | None`), `record` (`DecodedRecord | None`), `detail`.
The `kind` is the discriminator — the point of the live surface is that it
names *why* the tail moved, which batch mode structurally cannot:

| `kind` | Meaning |
|---|---|
| `record` | A complete record arrived and was verified. |
| `anchor_seen` | That record was an ANCHOR — the hook for "saw head H at T". |
| `pending_tail` | A partial record at the live tail: the writer is mid-write. Not truncation; the torn bytes never enter the verifier. |
| `diagnosis` (`truncated_tail`) | A pending tail stopped growing for `torn_grace` — a writer that crashed mid-write. |
| `shrunk` | The file shrank *within* the pending region — most likely a resume truncating a torn tail. State is kept. |
| `recovered` | The BOOT + `RECOVERY_TRUNCATED_TAIL` after a `shrunk` arrived; the verifier state was never invalidated. |
| `diagnosis` (`replaced_or_rolled_back`) | The file shrank **below the verified head** — the one real alarm; no honest writer rewrites history. |

## `snapshot() -> Verification`

The batch [`Verification`](reader.md#verify---verification) over everything
verified so far — the same three-question result a UI renders in batch mode.
It is literally the `AuditReader` path over the verified prefix, which is why
live and batch cannot disagree.

```python
v = tr.snapshot()
print(v.chain.chain_ok, v.complete_to_anchor)
```

## `close()`

Stops the `events()` loop. Safe to call from another thread or a signal
handler.

## Notes

- The torn bytes of a `pending_tail` are never fed to the verifier, so a
  mid-write partial can never turn into a spurious `chain_break`.
- Pass an `anchor` to have `snapshot()` answer completeness live, exactly as
  `AuditReader` does.
- For a purely after-the-fact check, prefer [`AuditReader`](reader.md); reach
  for tailing only when you need to react while the log is still growing.
