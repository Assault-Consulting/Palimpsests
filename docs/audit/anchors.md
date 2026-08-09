# Anchors — the trusted head, from outside the log

Completeness (question 2) can only be answered against a head obtained from
**outside** the file being checked: a local anchor store, or the head covered
by the newest witness receipt. Without it, dropping the last N records leaves
a perfectly linked chain with a different head and no other trace. Anchors are
that outside input, and the verifier reaches them only through one small
protocol — it never knows where an anchor lives.

```python
from palimpsests.audit.anchors import (
    AnchorReading, AnchorSource, AnchorSourceError, AnchorAttempt,
    ManualAnchor, FileAnchor, ChainedAnchorSource,
    AnchorStore, FileAnchorStore,
)
```

## `AnchorSource` — the read protocol

```python
class AnchorSource(Protocol):
    def current_head(self) -> AnchorReading | None: ...
```

The contract makes an important distinction:

- **returns `AnchorReading`** — a head is available.
- **returns `None`** — no anchor is present, and that is *normal* (a fresh
  deployment, a store not yet written). Completeness stays "not checked".
- **raises `AnchorSourceError`** — an anchor is present but *unreadable* (a
  corrupt file, a permission error). This is a real fault, distinct from
  absence, and carries `source_kind` / `source_detail`.

### `AnchorReading`

`head` (32 bytes), `source_kind` (`"manual"` / `"file"` / `"chained"` / a
consumer's own kind), `source_detail` (path / account / index — display
only), `observed_at_ns` (the reader's wall clock at read time — provenance
for a UI, **not** a time proof; nothing here is chained or signed).

## The built-in sources

### `ManualAnchor(head_hex, *, detail="")`

A head you already hold as hex — from a config value, another tool, a witness
receipt you resolved yourself. Validates the hex and the 32-byte length at
construction.

```python
src = ManualAnchor("9f3c…", detail="from Rekor receipt #4821")
```

### `FileAnchor(path)`

Reads a head from a file: a single lowercase-hex line, with `#` comment lines
tolerated. A missing file → `None` (absent, normal); a present-but-garbage
file → `AnchorSourceError` (present, unreadable).

```python
src = FileAnchor("/var/lib/palimpsests/anchor.head")
```

### `ChainedAnchorSource(sources)`

Tries several sources in order; the first that answers wins. A link that
raises is recorded and skipped rather than aborting the chain — a flaky file
source never masks a good fallback. After resolution, `last_attempts` holds
one `AnchorAttempt` per link tried.

```python
src = ChainedAnchorSource([
    FileAnchor("/run/palimpsests/anchor.head"),   # fast local
    ManualAnchor(pinned_head_hex),                # fallback
])
reading = src.current_head()
for a in src.last_attempts:
    print(a.source_kind, a.outcome, a.error)      # answered / absent / error
```

### `AnchorAttempt`

One link's outcome inside a chained resolution: `source_kind`,
`source_detail`, `outcome` (`"answered"` / `"absent"` / `"error"`), `error`
(`str | None`). `AuditReader.verify()` and the CLI surface this trace so an
operator can see *why* an anchor did or didn't apply.

## Writing anchors — `AnchorStore`

The write side of the same boundary. After a verified run, persist the new
head so the next run can check completeness against it.

```python
class AnchorStore(Protocol):
    def store_head(self, head: bytes, *, meta: Mapping[str, str] | None = None) -> None: ...
```

### `FileAnchorStore(path)`

Persists a head in the `FileAnchor` format, atomically — a torn anchor file
is worse than a stale one, so the write goes to a temp file, is fsync'd, then
`os.replace`d into place. Optional `meta` is written as `# key: value`
comment lines above the hex.

```python
from palimpsests.audit.anchors import FileAnchorStore

store = FileAnchorStore("/var/lib/palimpsests/anchor.head")
store.store_head(reader.head(), meta={"run": "2026-08-09T15:00Z"})
```

`FileAnchor` reads exactly what `FileAnchorStore` writes, so the two are a
matched pair for a local deployment.
