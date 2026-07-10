# Threat Model

This document is the structured reference for security reviewers: assets,
trust boundaries, attacker capabilities, and — most importantly — **which
guarantee is in force under which configuration**. It consolidates the
threat model that previously lived in module docstrings
(`src/palimpsests/audit/log.py`, `src/palimpsests/audit/key_manager.py`)
and in [SECURITY.md](../SECURITY.md), which remains the home of the
disclosure policy and the regulatory mapping (EU AI Act Art. 12 / 26(6)).

Reflects the 0.4.1 hardening (internal audit, July 2026 — see
[`docs/security/AUDIT-2026-07.md`](security/AUDIT-2026-07.md)).

The style throughout is the project's *honest boundary* principle: state
what a mechanism guarantees, state what it does not, and never let a
passing check be read as stronger than it is.

---

## 1. Scope and assets

Palimpsests is a local-first inference library. Everything runs on one
host; there is no server component of ours and no third-party service in
the request path. The assets worth protecting:

| Asset | Property to protect | Mechanism |
|---|---|---|
| Audit log **contents** (operation metadata) | Confidentiality | SQLCipher encryption at rest |
| Audit log **history** (what happened, in what order) | Integrity / tamper-evidence | Per-row hash chain + out-of-band head anchor |
| Audit **encryption key** | Confidentiality | OS keychain (Keychain / Credential Manager / Secret Service) |
| **Head anchor** (chain head hash) | Integrity of the replacement check | OS keychain, per-database entry |
| **KV / model state blobs** (level 3) | Integrity of what crosses into C code | In-memory only today — see §7 |
| Inference **content** (prompts, outputs) | Never stored | The log records metadata only; error text is clipped to 200 chars |

Note the last row: prompts and outputs are *deliberately not an asset of
the audit subsystem* because they are never written to it. The clipping
of `error_message` (0.4.1) exists to keep third-party exception text from
smuggling request fragments past that rule.

## 2. Components and trust boundaries

```
┌────────────────────────────── host ──────────────────────────────┐
│                                                                   │
│  application process (embeds palimpsests)                         │
│  ├── AuditLog ── SQLCipher file  (trust boundary: filesystem)     │
│  │        └──── head anchor ──── OS keychain (separate store)     │
│  ├── L1: httpx ─────────────────► Ollama daemon  (localhost HTTP) │
│  ├── L2: spawns ────────────────► llama-server child (localhost   │
│  │                                HTTP, no auth — accepted, §6)   │
│  └── L3: ctypes ────────────────► llama.cpp in-process            │
│                                   (trust boundary: Python → C)    │
└───────────────────────────────────────────────────────────────────┘
```

Boundaries that matter:

- **Database file vs. keychain.** The point of the anchor is that forging
  history requires compromising *two* separate stores, not one file.
  Since 0.4.1 the anchor entry is **scoped per database path**
  (`anchor_scope`), so multiple logs on one machine cannot overwrite each
  other's anchor — a false-alarm source that would have buried real ones.
- **Localhost HTTP (L1/L2).** Anything on the same host can reach these
  ports. For the managed L2 child this is an accepted, documented risk
  during the current phase (§6).
- **Python → C (L3).** Bytes passed to `llama_state_seq_set_data` are
  parsed by C code. Today those bytes are always self-produced and
  in-memory; the rule that keeps this safe is stated in §7.

## 3. Attacker capabilities

Ordered by increasing power. "Detected" refers to `AuditLog.verify()`.

| # | Attacker can… | Outcome |
|---|---|---|
| A1 | Read the database file, without the key | Contents unreadable (encrypted). Plaintext mode is opt-in only, and the file is `chmod 0600` best-effort. |
| A2 | Edit, delete, or reorder rows, **holding the key** | **Detected** — the hash chain breaks at the first altered row (`first_bad_row`). |
| A3 | Replace the whole database with a fresh, internally consistent chain, holding the key | **Detected** — the head anchor names no row in the new chain (reported as replacement/rollback). |
| A4 | Restore an older snapshot of the database (rollback), holding the key | **Detected** — same check as A3: the anchor is newer than the restored head. |
| A5 | Append rows **without** keychain write access | **Detected** — the chain extends past the anchored head (`anchor_lag=N`, reported as an unanchored tail). Ambiguous with a benign crash — see §5. |
| A6 | Hold the key **and** write to the keychain | **Not detected.** Chain and anchor can be forged together. This is the honest boundary: fixing it requires anchoring outside the host (remote append-only log, notary, transparency log), which Palimpsests does not do and does not claim. |
| A7 | Compromise the host / process before events are written | **Not detectable by any local log.** A log attests only to what reached it; timestamps are process-supplied (§6). |

What the design buys is the distance between A2–A5 (detected) and A6
(two-store compromise required). It does not, and cannot, buy A6/A7.

## 4. Guarantees by configuration

The guarantees are **not constant** — they depend on what the deployment
actually has. This table is the contract:

| Configuration | Confidentiality | In-place tampering (A2) | Replacement / rollback (A3/A4) |
|---|---|---|---|
| SQLCipher + keychain (production default) | Yes | Detected | Detected |
| SQLCipher + **no keychain** (headless, no Secret Service) | Yes | Detected | **Not detected** — `verify()` says so via `head_anchored=False` |
| `allow_unencrypted=True` + keychain | **No** | Detected | Detected |
| `allow_unencrypted=True` + no keychain (CI posture) | **No** | Detected | **Not detected** |

Rules that keep this table honest:

- A missing SQLCipher build **fails closed**: the log refuses to open
  rather than silently writing plaintext. Plaintext is a named, explicit
  choice (`allow_unencrypted=True` / `PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1`).
- A wrong key fails **at open** (forced sanity read), not later — and
  cannot silently initialize a new database over an unreadable one.
- A keychain outage **mid-run** no longer degrades silently (0.4.1):
  failed anchor writes are counted (`AuditLog.anchor_failures`) and warned
  about once; the anchor is retried on the next write.
- `anchor_every > 1` (a performance knob, default 1) opens a window in
  which the newest rows are chained but not yet anchored. `close()`
  flushes the anchor — but only for rows *this process* wrote: a
  read-only session (notably `verify`) must never re-anchor whatever
  chain is on disk, or inspection would bless a forged history.

## 5. Interpreting `verify()`

`verify()` recomputes the whole chain and compares its head to the stored
anchor. It is strictly read-only. The result is a diagnosis, not just a
boolean:

| Result | Meaning | Likely cause |
|---|---|---|
| `ok=True, head_anchored=True` | Chain intact **and** it is the anchored history | Healthy |
| `ok=True, head_anchored=False` | Chain internally consistent, but the replacement check could not run | No keychain / never-anchored log. Treat as weaker: wholesale replacement would not have been caught. `--require-anchor` turns this into a failure. |
| `ok=False, first_bad_row=N` | A row was altered, deleted, or reordered | Tampering (A2) — or corruption |
| `ok=False, anchor_lag=N` ("unanchored tail") | Chain intact and *contains* the anchored head, but extends `N` rows past it | Either benign — a crash between commit and anchoring, or a keychain outage (check `anchor_failures`) — **or** rows appended without keychain access (A5). The log cannot distinguish intent; the operator investigates the tail. |
| `ok=False`, anchor names no row ("replaced or rolled back") | This is not the history that was anchored | Replacement (A3) or snapshot rollback (A4) |

The `anchor_lag` case (0.4.1) exists precisely because the previous
behavior reported a benign crash as "history replaced" — a false
accusation that would erode trust in the mechanism, and noise in which a
real alarm could hide.

## 6. Accepted and residual risks

Named here rather than discovered by someone else:

| Risk | Status |
|---|---|
| **Managed llama-server child (L2) runs without `--api-key`**: any same-host process can reach its HTTP API; the free-port race additionally permits local impersonation. | **Accepted for the current testing phase** (audit finding M3, deferred by decision). The planned split of Level 3 into a separate distribution changes the HTTP exposure model and the question is revisited there. Until then, treat the L2 adapter as **single-user-host only**. |
| **Timestamps are process-supplied** (`datetime.now(UTC)`). | Inherent. The chain proves *order and integrity*, not wall-clock accuracy. A compromised process can write truthful-looking times (A7). |
| **`anchor_every` window**: rows chained but not yet anchored between refreshes. | By design (performance knob, default 1 = every write). Bounded by the next write or `close()`. |
| **No remote anchoring / notarization.** | Out of scope by decision (the A6 boundary). Deployments needing it should commit the chain head externally themselves — the head hash is available for exactly that. |
| **Published PyPI artifact predates the OIDC release workflow** (no attestations). | Closes with the next release (0.5.0) through Trusted Publishing. |
| **No independent third-party audit.** | The 2026-07 audit was internal. Stated plainly in SECURITY.md. |

## 7. Forward-looking boundary: KV state blobs (H2)

`NativeSession.save_state` / `load_state` serialize KV state to an opaque
blob whose bytes are ultimately fed into `llama_state_seq_set_data` —
**C-side parsing**. Today this is safe by construction: blobs live only
in the in-memory `KVStore` and are always self-produced within the same
process.

The rule that must hold until stronger protection ships:

> **KV blobs are trusted input.** They must never be loaded from disk,
> the network, or any source outside the producing process.

Before a disk-backed `KVStore` (already anticipated in its docstring) or
any blob sharing lands, persisted blobs must be authenticated —
HMAC-SHA256 with a keychain-derived key, verified *before* the bytes
cross into C. This is also the priority fuzzing boundary: the pure-Python
surfaces (`_canonical`, `content_key`) are trivially safe, while
llama.cpp's state parsing is where malformed input has consequences.

## 8. Non-goals

To prevent the claims from inflating in retellings:

- **Not unforgeable.** An attacker with the key and keychain write access
  (A6) defeats the mechanism. "Tamper-evident" means evident against
  attackers below that line.
- **Not a certified compliance product.** No conformity assessment, no
  finalized Article 12 technical standard exists to certify against (see
  SECURITY.md for the regulatory picture and its caveats).
- **Not multi-tenant.** The threat model assumes one trusted OS user per
  deployment; hostile same-user processes are out of scope (they hold the
  keychain by definition — A6).
- **Not an availability guarantee.** The audit subsystem is fail-closed
  for integrity, not highly available; a keychain or disk failure stops
  guarantees loudly rather than degrading silently.

---

*Maintained alongside the code it describes: changes to the audit
subsystem, the process lifecycle, or the native backend's state handling
should update this document in the same pull request.*
