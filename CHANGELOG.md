# Changelog

All notable changes to Palimpsests are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches v1.0. Before v1.0, minor versions may include breaking
API changes.

## [Unreleased]

### Added

- **PALA-1 submitted to the IETF as an Internet-Draft.**
  `draft-sparysh-pala-audit-00` was uploaded on 2026-09-02 and posted on
  2026-09-03; it expires 2027-03-07.
  <https://datatracker.ietf.org/doc/draft-sparysh-pala-audit/>

  This is an **individual submission**, not an IETF standard and not a
  working-group document. No one has reviewed or approved it; anyone may
  submit an Internet-Draft. What the submission provides is a dated,
  citable, permanent URL for a specification that already existed.

  The document presents the frozen v1.0 wire format as it is and does not
  revise it. `docs/specs/pala-1/PALA-1.md` remains the normative source
  and `test-vectors.json` remains the interoperability artefact; the
  I-D is a presentation of both, in RFC form. Nothing in the wire, the
  vectors or the verification record changes because a publication
  document now exists.

  The source lands in `standards/`, where the CI spec-build job has been
  waiting for it. Rendered `.xml` and `.txt` are build outputs and are
  not committed.

  The submission passed the datatracker's idnits check with no nits.

## [0.11.0] — 2026-09-02

**Additive only — the PALA-1 wire format is unchanged (frozen at v1.0).**
No envelope byte changes, no `format_version` bump; the core
`test-vectors.json` is byte-identical to 0.10.0. Three things happen in
this release. First, the trail stops ending at the device: a chain head
can be exported as a COSE Signed Statement, registered with a
transparency service, and the receipt verified — with the construction
independently reproduced twice and one registration on the public
record. Second, the writer grows its production duty cycle: key-driven
container rotation with a policy for months-long chains, a PKCS#11
anchor store for tier B, bearer auth and real token usage on `serve`,
and a `pala report` attestation document. Third, this release says
plainly what its own verifier costs: `AuditReader.verify()` does more
work than in 0.10.0 on large chains, and that regression is named in
*Changed* below rather than rounded off.

### Added — the transparency path (SCITT bridge)

- **`palimpsests.audit.pala.scitt`** (#176): one COSE_Sign1 Signed
  Statement per published head — attached CBOR payload `{head,
  first_seq, last_seq, "pala-1/v1.0"}`, EdDSA or ES256, built from and
  verified against the referenced standards. Ships with a published
  statement vector and a measured D2.8 comparison of chain hashing
  versus per-record signing. The bridge exports and verifies
  *statements*; receipts follow the service's own protocol — a stated
  boundary, so trust in a service is never silently laundered into
  trust in the format.
- **A verification task anyone can run** (#177): the statement
  construction published as an executable task in `docs/interop/`, with
  the contamination boundary stated — the same discipline the wire
  format's five runs used.
- **Bridge runs B1 and B2 on the record** (#191, #193): the statement
  reproduced byte-for-byte from the RFCs alone, twice, under a stated
  contamination boundary — each run with its own CBOR and Ed25519
  implementation. B1 found a conformance defect (below, *Fixed*); B2
  verified the corrected construction 61/61 and re-derived the `kid`
  thumbprint independently.
- **Statement vector v2 with byte-stability expectations** (#192, #194):
  the reissued vector (331 bytes, EdDSA under the RFC 8032 test key)
  now carries six byte-stability modes and seven tamper expectations,
  including Ed25519 signature non-uniqueness (S+L) pinned by an
  executable test against the exact scalar B2 computed.
- **Registration run 1** (#195): a statement over the #189 operator
  chain head registered with the scitt-community SCITT API emulator,
  receipt verified by the emulator's own verifier **and offline from
  the published artifacts alone**. Scope stated in the run record:
  operator ourselves on localhost, single-use ephemeral key, the
  emulator's own pre-RFC receipt structure. Finding R1-F1: the emulator
  expects the draft-era CWT-Claims header label where RFC 9597
  registered a different one; the statement was not bent to match — the
  emulator received a one-line disclosed patch, and the matter goes
  upstream.
- **`docs/INTEROP-SCITT.md`** (#195): what a verified receipt proves —
  existence-in-time of a head under a named service — and what it does
  not (content, consistency, completeness, endorsement, growth past the
  registered head); the verified/reported split; claim templates
  verbatim, with the words not to use.

### Added — the production duty cycle

- **Container rotation** (#178): `PalaWriter` can cut the container at a
  record boundary into one verifiable chain across files — the cut is a
  chain fact, not a filesystem accident.
- **`RotationPolicy`** (#183): size/record-count triggers with deferral,
  manifest stitching and resume — a chain that lives for months without
  manual surgery. `docs/RETENTION.md` gains the trigger arithmetic for a
  six-month retention duty.
- **PKCS#11 anchor store** (#179, #180): `anchors_pkcs11` behind a
  `[pkcs11]` extra, exercised in CI against SoftHSM2 (ADR-0004), with
  the trust boundary written into `SECURITY.md` and the anchor
  catalogue. The tier-B *claim* language stays honest: SoftHSM proves
  the code path; a hardware-token run is a separate, later record.
- **`serve` hardening for real clients** (#181, #182): opt-in bearer
  auth with an OpenCode config printer, and `usage` now carries the
  engine's reported token counters — zeros only where the engine
  reports nothing, and they stay honest zeros.
- **`pala report`** (#187, #188): the attestation document as JSON and
  a self-contained HTML — the §7 answers, the safety section, external
  pins and digests in one artifact with a single schema owner.

### Added — reader surface for downstream tooling

Driven by the Auditor desktop shell's upstream queue; each is additive
on `DecodedRecord`/`AuditReader`:

- **`DecodedRecord.record_hash`** (#200) — a record's own hash without
  re-deriving the chain.
- **`AuditReader.unloaded_at()`** (#201) — distinguishes a model state
  never declared from one explicitly unloaded.
- **`DecodedRecord.detail`** (#202) — the `EVT_DETAIL` payload,
  surfaced. Found and stated along the way: `KEY_SHRED` carries its own
  `SHRED_DETAIL` TLV schema, distinct from `EVT_DETAIL`.
- **`OVERSIGHT_ACK` operator fields and `shredded_targets()`** (#203) —
  `operator_id`, `disposition`/`disposition_name`, and shred-target
  resolution mirroring `acknowledged_candidates()`.

### Changed — what `verify()` costs, said plainly (U14, phase 0)

- **`AuditReader.verify()` now does more work than in 0.10.0, and these
  notes say so rather than round it off.** With the referential
  advisories added this cycle, `verify()` decodes record bodies across
  the chain to resolve them; the §7.1 chain check itself remains
  header-only. Measured consequence, single environment: on a chain of
  about a million records on a 4 GiB host, the naive full path — open,
  verify, then build a report without passing the reader — was killed
  by the OOM killer where 0.10.0 completed. This is a known regression
  in that configuration. The rework is tracked as U14 with the fix
  scheduled; no version is promised here. The docstrings describe the
  current behaviour exactly (#204), and the full performance
  characterization will be published together with the fix, not before.
- **`build_report(..., reader=)` (#198) removes the second full decode,
  and only that.** Passing an already-open reader stops the report from
  opening and decoding the file again — on large chains the difference
  between finishing and OOM. It does **not** reduce the peak of the one
  reader you pass: `path.read_bytes()` and the body-digest pass still
  run unconditionally inside `build_report()`, as its docstring now
  states. Calling this parameter a performance fix would be an
  overclaim; it is an OOM fix for the duplicate-decode path.

### Fixed

- **`unacknowledged_candidates()` is hash-verified, not seq-only**
  (#199): an `OVERSIGHT_ACK` used to acknowledge whatever record
  currently sits at the referenced `seq`; it now acknowledges only the
  record whose hash it names. An acknowledgement of a record that was
  later replaced no longer counts as an acknowledgement.
- **SCITT statement conformance** (#192, found by bridge run B1): the
  protected header gained the `kid` parameter that Section 6 of
  RFC 9943 requires when neither `x5t` nor `x5chain` is present, plus
  the payload's content type; the CWT subject now carries the full
  chain head instead of a truncated one, because services index by it.
  The statement vector was reissued as v2; both versions and their
  digests remain on the record.
- **`serve` claims only what it observes** (#190): the banner and
  docstrings say *structured* tool loops are recorded, the text-mode
  visibility limit found by the #189 smoke run is documented instead of
  implied away (ADR-0005), and shutdown's cancel-before-close seam is
  covered so a pending call cannot slip out of the chain unrecorded.

### Measured

- **Serialization and integrity cost, independently** (#185): chain
  hashing versus per-record COSE signing, second run by a co-maintainer
  under a stated contamination boundary — the multipliers agree with
  the in-repo harness (45–61× write, 116–168× verify; native
  primitives, workstation upper bound). Reported as a measurement of
  two implementations, not a property of the format.
- **EU AI Act Article 12 recount against main** (#186): 24 of 27
  mapping rows Shipped, 3 Planned, each row pointing at code and tests
  on `main`.

### Documentation and maintenance

- **The verification walkthrough, finished against reality** (#205,
  superseding a parked draft): every command executed against `main`;
  the exit-code contract taught as it is (`0` needs a matching anchor;
  no anchor exits `2` on purpose; a single flipped bit exits `1`,
  demonstrated).
- Site: Gold assurance section, DOI, five wire-format implementations
  (#175).
- Dependency maintenance via the grouped dependabot lane (#196, #197).

## [0.10.0] — 2026-08-24

**Additive only — the PALA-1 wire format is unchanged (frozen at v1.0).** No
envelope byte changes and no `format_version` bump; `test-vectors.json` is
byte-identical. Two things change with this release. First, the value is
visible in one command: `palimpsests demo` writes and verifies an audited
agent turn with no model, no network and no configuration, and
`palimpsests serve` puts an OpenAI-compatible endpoint in front of the engine
whose tool loop is recorded as it runs. Second, the audit trail stops being
something only this package can read: the published vectors ship inside the
wheel, inclusion proofs and evidence bundles are assemblable, the
verification report has one schema owner and a machine-checkable JSON Schema,
and the consumer surface is declared with stability classes rather than
inferred from source.

### Added — developer experience

- **`palimpsests demo`** (#154): one command — an agent turn through the real
  level-3 stack, a PALA-1 chain written, and the production reader verifying
  it, narrated. Built on real seams only (`PalaWriter` → `NativeAudit` →
  `NativeSession` → `AuditReader`), so it is the seed of a future launcher
  rather than a throwaway script; the demo backend is labelled **inside the
  chain** (`injected:` detail), so even the demo artifact does not overstate
  itself.
- **OpenAI-compatible endpoint** (#155, #156): `POST /v1/chat/completions`
  (plain and SSE, standard `chat.completion.chunk` framing and `[DONE]`) and
  `GET /v1/models`, over `core.chat` — so it works at every engine level,
  L1/Ollama included. Ships behind a new `serve` extra (fastapi + uvicorn);
  the base install is unchanged and the module is import-safe without the
  extra. Started with `palimpsests serve` or the `palimpsests-serve` entry
  point. Scope is stated rather than implied: `usage` is reported as honest
  zeros until token accounting is engine-level work, and there is no auth
  because this is a localhost tool — a real gateway goes in front otherwise.
- **Function calling, with the loop on the record** (#159): `tools` are
  declared to the model in one stated convention (Hermes/Qwen
  `<tool_call>{json}</tool_call>`, with a bare-JSON fallback) and returned in
  canonical OpenAI shape (`tool_calls`, `finish_reason: "tool_calls"`,
  indexed SSE chunk); a malformed block stays in the text rather than being
  erased — the model's utterance is not this layer's to rewrite. **The
  recorder sits on the endpoint**, the dispatch boundary this process
  actually observes: handing calls to the client emits `TOOL_CALL`
  (arguments as a canonical digest), the client's posted results emit
  `TOOL_RESULT` hash-bound to their call, and shutdown cancels every pending
  call so the chain never shows a call without a fate. Consequence: the
  auditable tool loop works on **every** engine level, without waiting for
  session affinity. `serve` keeps its own cross-boot chain at
  `<config>/serve.pala`.
- **Engine auto-selection** (#158): `active_engine()` falls back to the best
  *installed* engine for the current run when the configured one is absent,
  and `palimpsests engine use auto` resolves and persists the **concrete**
  id. Two honesty properties, both tested: the fallback never persists, and
  an explicit installed choice is never second-guessed — the registry never
  stores the word "auto", so `engine list` always shows what will run.

### Added — the audit consumer surface

- **The published vectors ship in the wheel** (#160): both the envelope set
  and the profile companion, force-included at build time from
  `docs/specs/pala-1/` — one file in git (the source of truth, pinned by the
  regeneration gate), a build-time copy in the wheel. One canonical accessor,
  `vectors.load("core"|"inference")` over `importlib.resources` — never
  `__file__`, which breaks under zipimport and frozen builds, exactly where a
  self-check matters most. A sdist→wheel round-trip test pins the failure
  mode `twine check` cannot see.
- **`palimpsests pala selftest`** (#161): does this installed build reproduce
  the published expectations? Per-record hashes, chain heads and the verify
  blocks — plus an explicit `__version__`-vs-distribution-metadata check,
  because a vector run alone cannot catch that drift (the 0.8.0 defect). The
  output is paste-able into a bug report.
- **Merkle inclusion proofs** (#162): `inclusion_proof(reader, seq)` and
  `range_proofs(reader, lo, hi)`, taking the reader a consumer already holds
  and returning values. The coverage rule is stated once and needs no new
  TLV: a `MERKLE` record whose `MERKLE_LEAF_COUNT` is *N* covers the *N*
  records immediately preceding it. `None`, never an exception, for an
  unaggregated tail or an absent seq — "not yet aggregated" is not "not
  included", and a bundle must be able to say which.
- **`merkle_checkpoint`** (#163): the writing side, so real chains become
  provable rather than only fixtures. Windows tile by construction — each
  checkpoint aggregates everything since the previous one, that record's own
  hash included — which leaves exactly one unproven record: the final
  checkpoint, the honest tail.
- **`pala bundle`** (#164): the evidence bundle, format `pala-bundle/1` — one
  plain tar with the range's **exact source bytes**, per-seq proofs, the
  verdict at assembly time with anchor provenance and attempts, every time
  claim with its trust level **by name**, and a manifest digesting every
  member. Deterministic (same inputs → byte-identical bundle), derived and
  unsigned: the chain stays authoritative, and a damaged chain bundles too,
  with the verdict inside saying so. The acceptance test reproduces every
  claim in the bundle using spec-level operations only, without a line of the
  assembler module.
- **Time health** (#165): per-boot drift series with a least-squares slope in
  ppm — the clock-quality fingerprint — never crossing a boot boundary, and
  an UNSYNCED boot's drift computed and *labelled* rather than hidden. Plus a
  step catalog classifying `step`, `regression` (signed negative — the one an
  auditor cares about) and `slew`, where a run of sub-threshold corrections
  is one entry, not forty. The 128 ms threshold is ntpd's own step-vs-slew
  line, stated with its reason. Analytics, never verdict inputs.
- **Per-boot statistics** (#166): uptime by monotonic span, span open/closed
  counts with the open rate and median closed duration, and **anchor cadence
  as a first-class field** — `widest_anchor_gap_ns`, **edge gaps included**,
  because a record's "existed by" claim can never be narrower than the gap
  between the anchor writes bracketing it, and that bracket is widest exactly
  when nobody was looking. `None` where there are no anchors at all: an
  unbounded bracket must not read as a perfect one.
- **The verification-report model** (#167, #168): `build_report()` produces
  `pala-verification-report/1` — one schema owner for both this package's
  report and any downstream rendering. `checked_at` is isolated so two
  reports of one file differ by a single line; completeness that was never
  asked stays `None` and is never rendered as passed; the unacknowledged
  incident-candidate count is resolved through `EVT_REF_SEQ` and is the
  loudest number in the report. The verdict rule (`derive_verdict`) is
  exported and embedded in the model, so a renderer reads the field instead
  of re-deriving it. The report's own container walk attests a malformed
  container and checks every body against its header digest — a truncated
  file and a body swap under an intact header chain both now surface, where
  header-only verification is blind by design.
- **A machine-checkable report schema** (#168):
  `docs/specs/report/pala-verification-report-1.schema.json` (JSON Schema
  2020-12, `additionalProperties: false`, CC0), **shipped in the wheel** beside
  the vectors, and validated in CI against every built report — so two
  consumers stop drifting by hand-checked prose.

### Added — retention

- **`pala segment`** (#169): retention needs a knife that keeps the proof.
  `verify_headers(..., start_prev=...)` allows a **declared mid-chain start**,
  so the seam between segments is a checked hash link rather than a
  convention — a forged seed is a detected break, and without the parameter
  verifier behaviour is byte-identical to before. `segment_chain()` and the
  CLI cut fixed-size segments strictly at record boundaries with one
  deterministic `pala-segments/1` manifest. Three pinned properties: every
  segment verifies alone when seeded from the manifest; deleting the first
  segment's bytes leaves a tail that still proves it continues a specific,
  *named* history (so "predecessor deleted under retention" is
  distinguishable from "predecessor missing"); and concatenating all segments
  reproduces the source byte-for-byte.

### Changed

- **`AuditReader` is re-exported from `palimpsests.audit`** (#171). The 0.8
  note that it was reachable only at `palimpsests.audit.reader` no longer
  applies: the package root is the one import a consumer needs, matching how
  `docs/INTEGRATION-SURFACE.md` names channel 1.
- The consumer-facing reading surface is **declared public as of this
  release** (#168); the writer APIs remain experimental.

### Documentation

- **`docs/INTEGRATION-SURFACE.md`** (#168): the consumer contract — seven
  channels with declared stability classes, the copy-then-read rule for live
  files (a malformed tail on a live file is a record in flight, not
  tampering), the golden-test normalization rule, the size envelope stated
  rather than implied, and embedder practice. Its closing line is the
  contract's spirit: if a behaviour matters to a consumer and is not written
  there, it is not promised.
- **`docs/specs/pala-1/CRYPTO-AGILITY.md`** (#170): a non-normative design
  note (CC0) on what is fixed in v1 and why one suite *is* the security
  argument, where the change seams are (`format_version`, §7.6 coexistence,
  opaque witness receipts, TLV lengths that already frame wider digests),
  and what is deliberately not provided — with a table mapping every
  behavioural claim to the test that pins it. Where the note reasons rather
  than asserts, it says so.
- **`CLARIFICATIONS.md` C-6** (#171): `prev_hash` and `body_digest` at their
  frozen 32-byte offsets are **version-invariant** — precisely what lets an
  unknown-version record still chain. A stronger chain digest is framed
  alongside within the PALA-1 envelope, never substituted at the frozen
  offsets; substituting the link is a new envelope. Raised in review of #170;
  credited to Turak.
- **README restructured around trying it first** (#157): install-and-run at
  the top, compliance and architecture one link deep.

### External contributions

- **Cryptographic scope and agility** (#170) — 80 invariant tests plus the
  design note, contributed by Oleksii: known answers traced to the published
  vectors, chain links folded with `hashlib.sha256` directly so no fixture
  inherits the assumption it exists to test, and a hand-built
  `format_version = 2` record proving the coexistence claim end to end (it
  chains, it is reported as uninterpretable, it is hashed into the head, and
  it is not judged). Its review also produced C-6 above. No production-code
  change and no wire change.

### Notes

- Full suite at the release commit: **660 passed, 1 skipped**; coverage
  90.77 % statement / 84.48 % branch against the 90 % / 80 % Gold gates; ruff
  clean on both the current and the CI-pinned version; `reuse lint` clean;
  `test-vectors.json` untouched.

## [0.9.0] — 2026-08-20

**Additive only — the PALA-1 wire format is unchanged (frozen at v1.0).** No
envelope byte changes and no `format_version` bump; the profile kind/tag
spaces grow additively, and `test-vectors.json` is byte-identical. This
release ships the r3 tool-loop profile end to end (spec → vectors → writer →
session wiring → reader), the reading-side advisory channel for tool
references and span pairing, the standards-publication groundwork, and the
record of a fifth independent verification.

### Added (experimental) — the r3 tool loop

- **Profile r3** (#145): `EVENT` kinds `TOOL_CALL` (8) and `TOOL_RESULT` (9)
  with §3.1, `SAFETY` kind `GUARD_TOOL_LOOP_LIMIT` (104), tags
  `EVT_TOOL_NAME` / `EVT_PAYLOAD_DIGEST` / `EVT_OUTCOME`, `AGG_TOOL_CALLS`.
  Arguments and results enter the log only as digests; latency is the
  monotonic delta between a result and its hash-bound call.
- **Companion vectors extended to r3** (#146): four appended records
  exercising every allocation; r2 records byte-identical; the CI
  regeneration gate proves byte-for-byte reproduction.
- **Writer methods** (#147): `tool_call` / `tool_result` /
  `guard_tool_loop_limit` in the oversight-methods style (format validation
  only), plus `canonical_tool_args_digest` — profile open issue §6.4
  resolved (sorted-keys compact JSON, UTF-8, SHA-256; pre-canonical bytes
  digest as-is).
- **Session wiring** (#149): `note_tool_call` records dispatches,
  `append_tool_result` closes the hop (hash-bound, result digest),
  `fail_tool_call` covers error/timeout without feeding, `close()` ends
  pending dispatches as cancelled. `max_tool_hops` (default 64) guards the
  loop — the refusal is recorded (SAFETY 104) and `ToolLoopLimitError`
  raised **before** anything is fed; limit refusals feed the existing r2
  guard-escalation trigger.
- **Reader recognition and advisories** (#150): the r3 kinds resolve by
  name; `TOOL_RESULT` and the loop guard go through hash-bound reference
  resolution plus the r3-specific `tool_target_not_a_call` — advisory,
  never a violation.

### Added

- **Span-pairing advisories** (#150): `span_unclosed` (a `SPAN_START` with
  no `SPAN_END` — §3.1's crash evidence, surfaced) and `span_unopened`
  (a span referenced with no `SPAN_START`), header-only, never a verdict.
  The resolution of independent run #5's finding; see
  `docs/specs/pala-1/CLARIFICATIONS.md` C-1.
- **Header field map export** (#151): the fixed-header layout exported for
  byte-level rendering by reading tools, checked against encoded bytes.
- **CLI/export**: `pala export --from-seq/--to-seq` (#135),
  `palimpsests --version` (#136), `pala verify --json` with
  verdict/counts/first-violation (#138) — all three from external
  contributors.
- **Standards groundwork** (#139): `docs/specs/pala-1/REGISTRIES.md`
  (allocation index and registration procedure),
  `docs/specs/pala-1/ANCHOR-SOURCES.md` (anchor-source catalogue incl. the
  TEE-quote composition), and the `standards/` kramdown-rfc build pipeline
  with a CI render gate.
- **`CITATION.cff`** (#150) with the Zenodo DOI of the regulatory
  whitepaper as the preferred citation.

### Changed

- CI status contexts fan into a single required **`ci-complete`** check
  (#127), removing the class of stuck-"Expected" states.
- Vector-consuming tests derive expected counts from the self-describing
  fixture (#146), so additive profile revisions no longer break them.
- `time_trust` / `assurance_tier` values resolve to names in exports and
  reader output (#144).

### Fixed

- `__version__` drift: 0.8.0 shipped with the constant still reading
  `0.7.0` (found through the `--version` contribution, #136; fixed in
  #142). A smoke test now asserts `pyproject` and `__version__` agree.

### Documentation

- **`docs/specs/pala-1/CLARIFICATIONS.md`**: the post-freeze clarification
  log — C-1 span pairing (deliberately not a verdict check;
  operationalized as the advisories above), C-2…C-5 resolving run-5's
  logged ambiguities; implementation count corrected to five (three
  external).
- **Fifth independent verification run recorded** (#148): Perl 5, core
  modules only, AES-256-GCM implemented from FIPS-197/SP 800-38D and
  self-tested against NIST vectors; 140 checks, all §8 values reproduced.
- **`docs/AUDIT-ARCHITECTURE.md`** (#150): where the audit layer sits —
  the layer diagram, the audit boundary, below-the-TEE-line positioning.
- **`CONTRIBUTING.md`** gains the AI-assisted contributions section
  (#150): disclose the tooling, execute what you submit, DCO certifies
  human responsibility, same review bar.
- `GOVERNANCE.md` records the branch-protection measurement anchor;
  `docs/BADGE-STATUS.md` updated (#127).

### External contributions

This cycle merged work from four external contributors: the export range
flags, the CLI version flag, the JSON verify output and its edge-case
tests (#135–#138), the fifth independent verification (#148), and
dependency updates via Dependabot (#141). The `--version` contribution
also caught the shipped version-constant defect — the funnel working as
designed.

## [0.8.0] — 2026-08-11

**Additive only — the PALA-1 wire format is unchanged (frozen at v1.0).** No
envelope byte changes and no `format_version` bump; the profile kind/tag spaces
grow additively, and the `pala1-v1.0` freeze and `test-vectors.json` are
untouched. This release adds the r2 oversight loop (writer + reader sides), a
JSON export converter, the `AuditReader` public reading API, and retention
guidance.

### Added (experimental)

- **Incident / oversight emit paths (r2).** `PalaWriter.incident_candidate()`
  (`KIND_INCIDENT_CANDIDATE`, a never-shed *observation*, not a determination) and
  `PalaWriter.oversight_ack()` (`KIND_OVERSIGHT_ACK`, the oversight loop's closing
  record), the latter carrying a **pseudonymous `operator_id`** (`EVT_OPERATOR_ID`,
  16 bytes). Writer-level API only — no wire change, frozen vectors untouched.
  `KEY_SHRED` gains a documented crypto-erasure note (the erasure path is the key,
  not the record). (#117)
- **Referential-integrity advisories** in the reader — the verification side of the
  r2 loop, additive to the advisory channel. Header-only §7.1 verification is
  unchanged: by design it cannot see bodies, so these body-referencing checks live
  in the reader and feed the same `Advisory` surface. (#119)
- **`AuditReader` public API** — the reading-side facade: verify a whole file, then
  view its records, spans, boots, and origins; the advisory channel surfaces
  non-verdict signals (referential integrity, boot-scoped monotonic/clock drift).
  Import path as shipped: **`palimpsests.audit.reader.AuditReader`** (not re-exported
  at the `palimpsests.audit` top level). See `docs/audit/reader.md`.
- **`pala export jsonl`** — a deterministic JSONL converter (the `pala2json` tool
  the spec promises in §1.1). It is **derived, never authoritative**: JSON is
  outside the hashing contract, so the export is for inspection only and always
  re-verifiable against the binary it came from. `audit/export.py` +
  `palimpsests pala export` CLI. (#123)
- **Retention guidance (WS5).** `docs/RETENTION.md` — storage math from the measured
  per-kind footprint, archival/pruning at segment boundaries, and resume-cost
  guidance, wired into the ISO/IEC 24970 mapping. (#124)

### Notes

- **Audit emission overhead is indistinguishable from noise** — measured upper
  bound ~1.5 % tokens/s, best estimate ≈ 0 % (lifecycle-level emission against a
  ~10⁵× writer headroom). See `results/audit-overhead-footprint-v0.7.0.md`.

## [0.7.0] — 2026-08-09

**The format is the deliverable — and it is frozen.** PALA-1 ships at
v1.0: an append-only, hash-chained, selectively-disclosable audit wire
format whose freeze was *earned*, not declared — four independent
verifier implementations, two of them external and unaffiliated,
reproduce every published §8 value from the specification text and test
vectors alone; the freeze-candidate run passed blind on its verifier's
first execution; and the exercise is now permanently self-service
(`docs/specs/pala-1/verification-kit/`). The library emits the format
end-to-end: the writer records the inference profile with cross-boot
resume, and `palimpsests pala verify` answers the three questions from
the file alone. The audit subsystem's public API (`AuditReader`) follows
in v0.8 — the lean tag is deliberate: the format needed no more code to
be finished.

### Changed

- **PALA-1 specification frozen at v1.0** (`docs/specs/pala-1/`, core and
  both profiles together). The freeze gate: four independent
  implementations — two of them external and unaffiliated — reproduce
  every §8 value from the text and vectors alone; the freeze-candidate
  run (run #4) passed blind on its verifier's first execution, its
  findings were resolved as text clarifications with `test-vectors.json`
  byte-identical, and the implementer's alignment confirmation is on
  record (`INDEPENDENT-VERIFICATION.md` §5). Frozen means the wire no
  longer changes — a wire change is a new `format_version`; profile
  kind/tag spaces continue to grow additively without touching an
  envelope byte. The `[pala]` codec, writer and CLI remain experimental
  as APIs; the *format* they emit is now stable.

### Added (experimental)

- **PALA-1 verification kit** (`docs/specs/pala-1/verification-kit/`):
  self-service independent verification for anyone, on the same terms as
  the recorded runs — the boundary rules, the task, a sealed-input fetch
  script with digests pinned at the freeze, and the run-record template.
  Submitted runs are recorded in `INDEPENDENT-VERIFICATION.md` §5 and
  archived byte-exact under `independent-runs/`.
- **Writer cross-boot resume.** `PalaWriter.open_existing()` resumes an
  existing chain across process restarts: adopts the tail head and seq
  and requires `BOOT` as the first record (the cross-boot link, core
  §4.2). A torn trailing record left by a crash is truncated and the
  recovery is itself recorded (`RECOVERY_TRUNCATED_TAIL`, profile §3
  kind 7) right after `BOOT`; mid-stream damage is refused, not
  auto-repaired. A fresh `PalaWriter()` on a non-empty file now raises
  instead of silently corrupting the chain with a second GENESIS.
- **PALA-1 draft specification and codec.** A self-describing, byte-level
  audit record format (`docs/specs/pala-1/`, CC0-1.0) with a standalone
  reference implementation, a deterministic vector generator, and committed
  test vectors reproduced byte-for-byte in CI; plus a production codec
  (`palimpsests.audit.pala`) — header/TLV wire codec, RFC 6962 Merkle,
  and a three-question verifier, all stdlib-only, with AES-256-GCM record
  bodies behind a new `[pala]` extra. Added *alongside* the existing
  `AuditLog`; nothing is replaced. The spec is **Draft**: the field set is
  not yet frozen — no stability promise until spec v1.0.
- **`palimpsests pala verify <file> [--anchor HEX] [--json]`.** A
  header-only, key-free verifier for §2.4 file containers. It answers
  the three questions separately: consistency (chain links, sequence
  gaps, violated MUSTs, every body checked against the digest bound into
  its header — never opened), completeness (only against a
  caller-supplied anchor, reported as NOT CHECKED otherwise — never as
  passing), and witness coverage (reported, not verified — receipts
  follow the witness's own protocol). Exit codes carry the same 0/1/2/3
  contract as `palimpsests audit verify`, and a stale anchor is
  diagnosed as an unanchored tail, distinct from a replacement.
- **PALA-1 inference profile**
  (`docs/specs/pala-1/profiles/inference.md`, CC0-1.0) — the dogfooding
  contract for the Phase 3 writer: session spans, model/KV operation
  `EVENT` bodies (metadata-only, with the 200-byte detail clip carried
  over from the audit-row rule), guard refusals recorded as `SAFETY`,
  and serving-statistics `AGGREGATE` tags including `AGG_PREFILL_SAVED`,
  which turns the library's avoided-re-prefill value into an auditable
  time series. `MERKLE` is deferred until the profile defines a leaf
  source. The second profile: the format's width claim now rests on two,
  pending actual emission by the writer.

### Changed (experimental)

- **PALA-1 restructured into a profile-independent core plus a robotics
  profile.** Robotics-specific body semantics that sat in the core draft —
  the optical-flow `AGGREGATE` fields, frame/audio `MERKLE` leaves, the
  `eyes.tier1` role vocabulary, the 30 Hz framing — moved unchanged (same
  tag values, same units) to `docs/specs/pala-1/profiles/robotics.md`. The
  core now carries the envelope, chain, tiers, time, crypto and
  verification, a generic `AGGREGATE` frame (window + sample count are
  core; quantities are profile-allocated from 0x0003 upward; one chain
  follows one profile), and a new §3.4 defining profiles. The committed
  test vectors are unchanged byte-for-byte and now explicitly labeled as
  robotics-profile vectors; an inference profile (KV operations, model
  loads, token counts) is the planned 0.7 dogfooding target. Envelope,
  codec and verifier are untouched.

### Fixed (experimental)

- **Two PALA-1 exit-test defects, found by the independent-verification
  run** (protocol §5 record; run against `776aa15a`, findings cited in
  `docs/specs/pala-1/independent-runs/oleksandr/ambiguity-log.md`).
  (1) The 30 Merkle leaf digests and the index-7 audit path are now
  published in `test-vectors.json` (`merkle.leaves`, `merkle.proof`) —
  previously they existed only inside the reference generator, a file
  the exit test forbids reading, which made the Merkle axis of the §11
  test unpassable by construction: `merkle_tree_hash` could only be
  echoed from the record's own TLV. Record bytes and every published
  hash are unchanged; the fix was validated end-to-end with the run's
  own spec-only implementation (root recomputed from the published
  leaves, leaf-7 proof folded). (2) A first record that is not `GENESIS`
  is now uniformly a *violation*: §4.2 and the §7.1 pseudocode said
  *break* while §8 and the vectors said *violation* — and both the
  reference and the production verifier silently reported *both*.
  Prose, both implementations, and the demo (which now asserts
  `breaks = []` explicitly) agree.

## [0.6.0] — 2026-08-02

**The 0.5 measurement campaign is complete, and `kv_unified` ships
first-class.** This release closes the empirical half of level 3: all three
serving mechanisms — the Tool Loop, Shared Prefix, and KV Persistence — are
now measured on real hardware (Intel Arc iGPU / Vulkan) at two model sizes
(1.5B and 7B), each against a *tuned* `llama-server` baseline, in isolation
and in a composite run with all three enabled. The honest result reshapes
the positioning: **on speed the mechanisms reach parity with a tuned
server, not an edge over it.** The real differentiators are session density
under a shared prefix (an 8.2× crossing on a fixed KV budget), the ~3.5–4×
full-stack value of the mechanisms together on a multi-hop agent, and the
in-process, no-server, auditable deployment model. Full method, numbers,
and limits: `results/CONSOLIDATION-0.5.md` and `docs/POSITIONING.md`.

### Added

- **`kv_unified` as a first-class `LlamaCppBackend` parameter.** The unified
  KV pool (which lets a shared prefix be *shared* across sessions rather
  than copied, enabling the session-density result) is now a supported,
  tested constructor flag, defaulting to split (per-sequence) KV. Previously
  it was only reachable by a benchmark wrapper, so the density figure was
  "demonstrated in a benchmark, not a product property"; it is now a product
  property.
- **Prefix-holder release-ordering guard (`PrefixHolderInUseError`).** In
  unified-KV mode a prefix holder's cells are shared with the sessions
  seeded from it; releasing the holder while a consumer is still live
  perturbs that consumer's logits (measured — a partial shift the greedy
  chain hides). The scheduler now tracks each holder's live consumers and
  refuses an early release rather than corrupt them silently. The guard is
  enforced in code, with a CI test on the fake backend and a hardware
  isolation suite.
- **Composite benchmark harness** (`benchmarks/bench_composite.py`) — the
  incremental-cumulative rung driver that attributes the full-stack value to
  each mechanism and runs the all-mechanisms-enabled corruption gate.

### Fixed

- **Engine teardown order.** `NativeEngine.close()` released prefix holders
  while consumer sessions were still open — harmless under split KV, a
  corruption under unified KV. It now releases consumer sessions before
  their holders (the ordering the guard requires). The guard caught this
  latent bug before it shipped.

### Changed

- **Positioning reflects the measured campaign.** `docs/POSITIONING.md` now
  carries the measured results for all three mechanisms and the composite,
  with the honest framing throughout (mechanism ratio vs re-prefill kept
  separate from the parity result vs a tuned server; the full-stack number
  reported as the full stack, never a cherry-picked best; the integrated-GPU
  disclosure that flatters every prefill-saving mechanism). The shared-prefix
  density claim, previously held out pending the `kv_unified` product work,
  now enters as a measured product property.
- **Roadmap: sleep-time compute deprioritized.** The campaign showed the
  differentiation is audit/compliance and the deployment model, not raw
  speed, so sleep-time compute is no longer scheduled. The next direction is
  a verifiable audit format (a self-describing, byte-level format with test
  vectors and a reference verifier an independent party can implement
  without our code). See `docs/ROADMAP.md`.

### Notes

- No public runtime API changed; `kv_unified` is an additive, opt-in
  parameter. The version is a minor bump for the new capability.
- Standing gates unchanged: `state_set` gains a MAC before any disk-backed
  KV store ships, and a discrete-GPU run is owed before any speed ratio is
  presented as hardware-general.

## [0.5.0] — 2026-07-11

The audit log becomes **genuinely** tamper-evident. Prior versions
described it that way, but provided only encryption at rest and an
append-only API surface: anyone holding the key could open the database
and rewrite or delete rows leaving no trace. Encryption is
confidentiality, not integrity. This release closes the gap between the
claim and the code — and hardens the surrounding supply chain: a
reproducible SBOM and a signed GitHub Release, coverage-guided fuzzing of
the untrusted-input path, and a documented governance model and security
assurance case.

### Security (0.4.1 hardening, from the 2026-07 internal audit)

- **Per-database head anchors.** The keychain anchor entry is now scoped
  to the log's resolved path (`anchor_scope`). Previously the anchor was
  machine-global: two audit logs on one host overwrote each other's
  anchor, making an honest log verify as "replaced" — and burying a real
  alarm in false ones. Existing logs re-anchor under the scoped name on
  their first post-upgrade write; until then `verify()` reports
  `head_anchored=False` for them.
- **Anchor write failures are counted, not swallowed.** `record()` now
  tracks failed keychain writes (`AuditLog.anchor_failures`) and logs a
  one-time warning, instead of silently dropping the wholesale-replacement
  guarantee mid-run.
- **`verify()` distinguishes an unanchored tail from a replacement.** A
  stale anchor that names a row *inside* the chain is now reported as
  `anchor_lag=N` ("chain extends N rows beyond the anchor" — a crash
  between commit and anchoring, or appends without keychain access),
  while an anchor naming no row in the chain is reported as a
  replacement/rollback. Both remain `ok=False`; the diagnosis differs.
- **Error messages in audit rows are clipped** (200 chars). Exception
  text from other libraries can embed URLs with tokens or payload
  fragments, which does not belong in a metadata-only log.
- **Audit DB file permissions** tightened to owner-only (best-effort
  `0600`), which matters most for the explicitly-permitted plaintext path.
- **First-run key race closed.** `load_or_create_key` reads back the
  stored key after writing, so two processes racing through first run
  converge on one key instead of encrypting with a loser's key.
- **`set_audit_log` now takes the singleton lock** (it was declared and
  unused).
- **llama-server stderr no longer uses an unread `PIPE`** (a child that
  logs > 64 KiB would block on write and hang); stderr goes to a temp
  file whose tail is included in startup-failure errors.
- **All GitHub Actions pinned to commit SHAs** (tags are mutable refs;
  `pypa/gh-action-pypi-publish@release/v1` was a moving branch).
- **Version metadata synced**: `__version__` said 0.2.0 while
  `pyproject.toml` said 0.4.0; both now 0.4.1.

Deferred by decision: local llama-server child runs without `--api-key`
(any same-host process can reach it). Accepted for the current testing
phase; the planned split of Level 3 into a separate distribution changes
the HTTP exposure model and will revisit this.

### Added

- **Hash-chained audit records.** Every row now carries `prev_hash` and
  `row_hash = SHA-256(prev_hash || canonical(fields))`. Altering,
  deleting, or reordering any row breaks the chain. The canonical
  encoding is length-prefixed, so no field value can forge a record
  boundary, and `NULL` encodes distinctly from the empty string.
- **`AuditLog.verify()`** — walks the chain oldest-first and returns a
  `VerifyResult` naming the first row whose recorded hash or predecessor
  link fails.
- **Out-of-band head anchor.** A chain alone cannot detect *wholesale
  replacement* — an attacker with the key can rebuild a consistent chain
  from scratch. The chain head is therefore also stored in the OS
  keychain, refreshed every `anchor_every` rows (default: every write)
  and flushed on `close()`. `verify()` compares chain head to anchor.
- **`VerifyResult.head_anchored`** — states whether the replacement check
  actually ran. A passing verification with `head_anchored=False` means
  the chain is internally consistent but replacement would not have been
  caught (for example, on a host with no keychain). The flag exists so a
  passing result is never read as stronger than it is.
- **`AuditIntegrityError`** — raised when the store cannot be opened in a
  trustworthy state, distinct from a verification *result*.
- **`palimpsests audit verify` CLI.** Runs verification from the command
  line with distinct exit codes (clean / tampered / unanchored /
  operational error), so integrity can be checked in a script or a
  scheduled job, not only from the API.
- **KV-state blob validation.** `load_state` now frames and validates a
  persisted blob's header (size and version bounds) in Python *before* its
  bytes reach llama.cpp's C `state_set`, so a malformed or truncated blob
  is rejected rather than parsed in C. The C parser it guards remains out
  of scope until a disk-backed store ships — at which point persisted
  blobs must also be MAC'd (see `SECURITY.md`).
- **CycloneDX SBOM and a signed GitHub Release.** The release workflow now
  generates a reproducible CycloneDX SBOM of the base install (from a
  clean environment, so build tooling never enters the bill of materials),
  and publishes a GitHub Release carrying the wheel, sdist, and SBOM as
  assets — which also makes this changelog's per-version release links
  resolve. See `RELEASING.md`.

### Breaking

- **A missing SQLCipher build no longer degrades silently to plaintext.**
  Previously, if `sqlcipher3` (the optional `[encryption]` extra) was not
  installed, the audit log accepted the encryption key, ignored it, and
  wrote an unencrypted database. It now raises `AuditIntegrityError`.

  To keep the previous behavior, choose it explicitly:

  ```bash
  pip install 'palimpsests[encryption]'      # preferred: actually encrypt
  # or, accepting a plaintext audit log:
  export PALIMPSESTS_ALLOW_UNENCRYPTED_AUDIT=1
  ```

  In the API, pass `AuditLog(..., allow_unencrypted=True)`. A plaintext
  log is still hash-chained: tampering remains evident, only
  confidentiality is given up.

### Fixed

- **A wrong encryption key now fails at open.** SQLCipher does not
  validate `PRAGMA key` when it is set, so a wrong key previously sailed
  past the constructor — and could initialize a *new* encrypted database
  over what looked like an unreadable one. A sanity read now forces the
  failure immediately.

### Notes

- **The honest boundary is documented, not implied.** An attacker holding
  the encryption key *and* write access to the keychain can forge the
  chain and its anchor together. Detecting that requires committing the
  chain head outside the host's trust boundary — a remote append-only
  log, a notary, a transparency log. Palimpsests does not do this and
  does not claim it. See the audit-log threat model in `SECURITY.md`,
  which also names the residual weaknesses (process-supplied timestamps,
  the `anchor_every` window, no independent audit).
- Tests for this work attack the database file directly with `sqlite3`,
  bypassing `AuditLog` entirely — an attacker does not politely go
  through a class whose API offers no mutation.
- **Coverage-guided fuzzing.** An Atheris (libFuzzer) harness now fuzzes
  the KV-state validator that guards `load_state` — a short deterministic
  regression on every change and a budget nightly
  (`.github/workflows/fuzz.yml`). The C parser the validator guards is
  deliberately out of the harness's scope.
- **Governance and an assurance case are documented.** `GOVERNANCE.md`
  states how decisions are made and where release authority sits;
  `docs/ASSURANCE-CASE.md` is a Claims–Arguments–Evidence argument for the
  security and record-keeping properties, with each claim's residual named
  and a table of the conditions that would defeat it.

## [0.4.0] — 2026-07-08

The **empirical half of level 3**: the real in-process backend now runs a
real model on hardware, and the first benchmark our strongest claim rests
on — the server-side tool loop vs a re-prefill baseline — has been measured.
0.3.0 shipped the level-3 skeleton on a fake backend and claimed no
performance; 0.4.0 brings up the real backend and produces the first number
we can call our own. That number is a **CPU-only 1.5B mechanism sanity
check, not a representative performance figure** — see **Notes**.

### Added

- **Real `LlamaCppBackend` (the `[native]` extra).** The ctypes backend
  that maps `NativeBackend` (the ADR-0002 seam) onto llama.cpp's low-level
  C API — batched `decode`, per-sequence `seq_copy` / `seq_remove`,
  `state_get` / `state_set`, tokenize/detokenize — is now brought online
  and validated on hardware (llama-cpp-python 0.3.33, Qwen2.5-1.5B Q4_K_M,
  CPU). Construction, a tokenize round-trip, and a scheduler/session smoke
  test passed; the vocab / memory / state_seq cross-version shims resolved
  cleanly against the pinned build. The same scheduler, session, and engine
  that 0.3 tested against a fake backend now drive a real model unchanged —
  the point of the ADR-0002 seam.
- **First on-hardware measurement — tool loop (N5) vs re-prefill**
  (`benchmarks/bench_tool_loop.py`, `results/report.md`,
  `results/REPRODUCE.md`). Both arms decode the same content through the
  same backend/model/sampling; the only variable is state control (live KV
  vs re-prefilling the conversation each hop). Result: near-parity at the
  control (1.08× at ~27 prefix tokens, 1 hop) growing to ~7× at ~2979
  prefix tokens / 12 hops, with TTFT near-identical between arms — the win
  comes from avoided re-prefill, and it scales with the re-prefill work
  removed. Expectations were pre-registered before the first number, per
  `BENCHMARKING.md` Rule 0.
- **`benchmarks/RUNBOOK.md` and `benchmarks/config.html`.** The
  hardware-bring-up checklist (primitive-by-primitive backend validation,
  then the benchmark sweep, control first) and a dependency-free static
  command builder for the benchmark.

### Fixed

- **`n_batch` on context creation (`LlamaCppBackend`).** On the first
  hardware run, a large single-call prefill (~3000 tokens) aborted the
  process with `GGML_ASSERT(n_tokens_all <= cparams.n_batch)` inside
  `llama_decode`, because the logical batch size was left at llama.cpp's
  default (2048). The context is now created with `n_batch = n_ctx` so the
  logical batch admits the largest prefill the context can hold. The
  measured decode logic is untouched; smaller configs were unaffected.
- **`_seq_op` version shim (`LlamaCppBackend`).** The newer/older KV
  symbol fallback (`llama_memory_seq_*` vs `llama_kv_cache_seq_*`) is now
  resolved through a small `_first_attr(lib, *names)` helper that looks up
  a runtime-chosen name, replacing a constant-attribute `getattr` chain
  (ruff B009) while preserving the cross-version dispatch intent.

### Notes

- **The measured numbers are a mechanism sanity check, not representative
  performance.** The first run was **CPU-only** (Docker, no GPU) on a
  **1.5B** model with greedy sampling. The *direction and shape* of the
  result — near-parity when there is no prefix to reuse, a growing win as
  the avoided re-prefill work grows — are the finding. Absolute magnitudes
  will differ on GPU and larger models. We do **not** present "7×" as a
  headline; a GPU / larger-model run is the pending next step, and the
  KV-persistence and shared-prefix numbers in `POSITIONING.md` remain
  external **targets** until measured the same way.
- **Cite the measured prefix, not the nominal label.** The benchmark's
  filler heuristic produces fewer tokens than the nominal config name
  (e.g. "4000" is ~2979 measured); the measured column is the honest one.
- **Positioning and roadmap** updated: `POSITIONING.md` gains a "What we
  have measured ourselves" section (clearly separated from the external
  targets), and `ROADMAP.md` moves the real-backend/first-measurement step
  into Done with a GPU/larger-model run as the next measurement priority.

## [0.3.0] — 2026-07-07

The **level-3 serving skeleton is structurally complete**: all six of the
`pal-native` capability flags — `streaming`, `stateful_sessions`,
`continuous_batching`, `server_side_tools`, `shared_prefix`,
`kv_persistence` — are now `True`, implemented and test-covered against a
fake backend behind the ADR-0002 seam. This closes the *architectural*
half of level 3; the *empirical* half (a real backend and measured
performance) is deliberately deferred to 0.4 — see **Notes** below.

### Added

- **Native scheduler (`Scheduler`).** A batch-ready decode loop written
  entirely against the `NativeBackend` protocol (ADR-0002), so it is pure
  Python and fully CI-tested with a fake backend. Structure is
  `queue → batched decode-step → demux`; one `step` builds one batch from
  all active slots and calls `decode` once.
- **Stateless streaming (N1).** `chat_stream` drives a single-slot
  scheduler to completion — the level-3 `streaming` flag.
- **Stateful sessions (N3a).** `NativeSession` holds a scheduler slot
  across turns (`open_slot` / `feed` / `run_turn` / `close_slot`), so
  later turns append to live KV instead of re-prefilling — the
  `stateful_sessions` flag.
- **Concurrent session batching (N3b).** `run_sessions` /
  `Scheduler.run_batch` advance several sessions' turns in one shared
  decode loop — true continuous batching, synchronous, no async imposed
  on callers — the `continuous_batching` flag.
- **Server-side tool loop (N5).** `NativeSession.append_tool_result`
  continues the same turn after an external tool by feeding only the
  result into live KV, with no re-prefill — the `server_side_tools` flag.
- **Per-slot KV position substrate (N-pos).** Each slot tracks `n_past`;
  every decode carries `start_pos`. The invisible substrate shared-prefix
  and persistence both build on — a copied or restored KV simply starts
  at a nonzero position.
- **Shared-prefix KV (N4).** A prefix holder decodes a system prompt once
  and copies it into each session's slot instead of recomputing it
  (scheduler primitives `reserve_prefix_holder` / `warm_prefix` /
  `copy_prefix_to_slot`; engine-side registry keyed by exact prefix
  tokens, opt-in via `share_prefixes`) — the `shared_prefix` flag.
- **KV persistence (N6).** `NativeSession.save_state` / `load_state`
  serialize a session's KV to a self-contained blob (the position packed
  into a header) and restore it without re-prefilling — the
  `kv_persistence` flag.
- **Content-addressed KV store (N6b).** `KVStore` / `InMemoryKVStore`
  address a saved state by a hash of the tokens that produced it, not by
  an opaque path — "LMCache for edge," layered over N6.
- **ADR-0001 / ADR-0002.** The two decisions the level rests on: the
  backend is llama.cpp's low-level C API, and it runs in-process with the
  scheduler/session tested via a fake backend, the real one validated on
  hardware.
- **`docs/BENCHMARKING.md`, `docs/ROADMAP.md`, `docs/POSITIONING.md`.**
  The measurement protocol, the working plan, and the honest positioning
  (audiences, the regulated-sector angle, and a target-vs-measured
  performance table).
- **`SECURITY.md`, `CODE_OF_CONDUCT.md`.** A private-disclosure policy
  with a regulated-sector security posture (EU AI Act Art. 12 / 26(6)
  mapping), and the Contributor Covenant 2.1.

### Changed

- **`NativeEngine` is no longer a placeholder.** In 0.2.0 it was a
  registered stub: `control_level=3` with every flag `False` and every
  operation refusing. It now implements the full serving skeleton behind
  the fake-backend seam, with all six capability flags `True`,
  `open_session` returning a live `NativeSession`, and the prefix registry
  wired in. (This corrects the 0.2.0 note that described level 3 as "not
  implemented yet.")
- **README, roadmap, and positioning** updated to reflect the completed
  skeleton and the gap-forward positioning (a composition claim — no
  single system combines continuous batching + shared-prefix KV +
  KV-persistence under one abstraction for agentic edge workloads,
  cross-platform — with the mechanism scope stated honestly).

### Notes

- **This release is the skeleton, not a running level-3 engine on
  hardware.** Every capability flag being `True` means the *mechanism* is
  implemented and tested against a fake backend — it does **not** mean a
  real model runs through level 3, nor that any speedup has been measured.
  The real in-process `LlamaCppBackend` (behind the `[native]` extra) is
  not shipped here and is validated only on hardware with a GGUF model.
- **No performance numbers are claimed.** The figures in
  `docs/POSITIONING.md` are external published results used as orientation
  targets, explicitly labeled as such. Producing our own numbers, against
  a tuned baseline under `docs/BENCHMARKING.md`, is the point of **0.4**.
- **0.4 will be the empirical release:** the real backend, the first
  on-hardware benchmarks (starting with the tool-loop-vs-re-prefill case,
  our strongest claimed advantage), and any capability the measurements
  justify keeping or cutting.

## [0.2.0] — 2026-07-06

The three-level architecture is now structurally complete: all three
control levels exist behind one `InferenceEngine` contract.

### Added

- **Level 2 — llama.cpp adapter (`LlamaCppEngine`).** The first *control*
  level: Palimpsests spawns and owns a `llama-server` subprocess, so the
  full `EngineMemoryConfig` (context size, GPU offload, flash attention,
  KV-cache quantization, mmap, draft model) is applied as real launch
  flags rather than ignored. Two modes: spawn (own the server from a
  model path) and attach (talk to a user-run server by URL). Opt-in via
  `PALIMPSESTS_LLAMACPP_MODEL`.
- **Managed subprocess lifecycle (`LlamaServerProcess`).** Free-port
  allocation, spawn, readiness by health poll, early-death detection, and
  idempotent shutdown — scoped to `llama-server` for now.
- **Level 3 slot — `NativeEngine`.** A registered, honest placeholder:
  `control_level=3` with every feature flag `False`, every operation
  refusing with `CapabilityUnsupported`, and `is_available()` `False`.
  The serving service (continuous batching, shared-prefix KV, server-side
  tool loop, KV persistence) is not implemented yet.
- **Block-memory retrieval (`BlockMemory`).** Evicted context is embedded
  and stored in SQLite; the most relevant blocks are retrieved back on
  demand (numpy cosine, no vector DB). Injectable embedder, defaulting
  through the active engine's `/api/embeddings`. Backing store shared with
  future KV persistence under `<workspace>/.context-memory/`.
- **Block memory wired into the chat flow.** `chat` now stores evicted
  messages and, lazily (only when eviction happened), retrieves relevant
  blocks back as a single prepended system message. Graceful: without an
  embed-capable engine or numpy, chat behaves exactly as before.
- **Ollama embeddings.** `OllamaEngine.embed()` exposes `/api/embeddings`,
  the default source for block-memory vectors.
- **`docs/USAGE.md`** — a run + settings guide for the current state.

### Changed

- `AppContext.engines` widened from `OllamaEngine` to the `InferenceEngine`
  protocol now that multiple adapters coexist. Callers read capabilities,
  never the concrete type, so nothing downstream changed.
- The `[llamacpp]` extra is now empty and documented: the server-subprocess
  approach needs the `llama-server` binary out-of-band, not a Python
  package. `numpy` moved to its own `[embeddings]` extra (and `[dev]`).
- Development status classifier is Beta; README, roadmap, and install
  instructions updated to reflect levels 1–2 shipped and the level-3 slot.

## [0.1.0] — 2026-07-06

Initial release.

### Added

- **Level 1 — Ollama adapter (`OllamaEngine`).** Thin HTTP client to an
  external Ollama daemon: streaming chat, model listing, availability
  probe, and the subset of `EngineMemoryConfig` Ollama honors.
- **The engine contract.** `InferenceEngine` protocol, `BaseInferenceEngine`
  (derives `chat` from `chat_stream`, refuses sessions by default),
  `EngineCapabilities`, `EngineMemoryConfig` (with the flash-attention
  prerequisite for KV-quant enforced), and the level-3 `InferenceSession`
  protocol.
- **Context-window manager.** Sink/window/evict fitting to a token budget,
  reporting what it evicted.
- **Registry** — one active engine globally (radio, not checkbox).
- **Audit log** — append-only, encrypted at rest (SQLCipher) with a key
  from the OS keychain, falling back to an ephemeral key headless.
- **CLI** — `chat`, `models`, `engine list` / `engine use`.

[Unreleased]: https://github.com/Assault-Consulting/Palimpsests/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.11.0
[0.10.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.10.0
[0.9.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.9.0
[0.8.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.8.0
[0.7.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.7.0
[0.6.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.6.0
[0.5.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.5.0
[0.4.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.4.0
[0.3.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.3.0
[0.2.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.2.0
[0.1.0]: https://github.com/Assault-Consulting/Palimpsests/releases/tag/v0.1.0
