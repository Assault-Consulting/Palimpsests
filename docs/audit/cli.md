# `palimpsests pala verify` — the batch verifier on the command line

The command-line consumer of [`AuditReader`](reader.md). Read-only and
header-only: no decryption key is needed or used, and encrypted bodies are
checked against the digest in their header, never opened.

```
palimpsests pala verify <file> [--anchor HEX] [--anchor-file PATH] [--json]
```

## What it reports

- **consistency** — do the records chain, with no gaps, no violated MUSTs,
  and every body matching its header digest?
- **completeness** — does the chain head match the anchor you supplied?
  Without an anchor this is **NOT CHECKED**, and the command says so.
- **witness** — which records claim external witness receipts? (Verifying a
  receipt follows the witness's own protocol — not this tool.)
- **advisory** — header-only signals (clock regressions within a boot, a
  chain with no anchor record). Signals, not a verdict: they never change the
  exit code.

## Anchors

- `--anchor HEX` — a 64-hex-char expected head, obtained outside the file.
- `--anchor-file PATH` — read the head from a file (one lowercase-hex line,
  `#` comments tolerated).
- Supplying both tries them in the order given, first that answers wins. A
  provenance line reports which source the head came from.

See [anchors.md](anchors.md) for where a trustworthy head comes from.

## Exit codes

The contract for cron and CI — they distinguish the outcomes an operator acts
on differently:

| Code | Name | Meaning |
|---|---|---|
| 0 | verified | chain intact **and** head matches the anchor |
| 1 | TAMPERED | a break, gap, violated MUST, body-digest mismatch, malformed container, or an anchor mismatch |
| 2 | PARTIAL | chain intact, but no anchor was supplied — replacement would not have been detected |
| 3 | UNREADABLE | the file could not be read, or `--anchor` is invalid |

A chain that verifies *without* its anchor (exit 2) is deliberately not the
same fact as a fully-verified one (exit 0): reporting the former as success
would be the silent over-claim the anchor exists to prevent.

## Examples

```bash
# Consistency only — completeness is reported as NOT CHECKED.
palimpsests pala verify session.pala

# Full check against a head from your anchor store.
palimpsests pala verify session.pala --anchor-file /var/lib/palimpsests/anchor.head

# A local file first, a pinned head as fallback; machine-readable output.
palimpsests pala verify session.pala \
    --anchor-file /run/palimpsests/anchor.head \
    --anchor 9f3c… \
    --json
```

## `--json`

Emits the full result: `consistency`, `completeness` (`checked`, `ok`,
`anchor_lag`, `reason`), `witness`, `anchor_attempts` (the per-source
resolution trace), `advisory`, and `exit_code`. Suitable for a CI gate or a
dashboard scraper.

```bash
palimpsests pala verify session.pala --anchor-file anchor.head --json \
  | jq '{ok: .consistency.ok, complete: .completeness.ok, exit: .exit_code}'
```
