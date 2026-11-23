### Added

- **The verification kit has a second track: the inference profile at
  r9.** `docs/specs/pala-1/verification-kit/PROFILE-R9.md` is the task —
  six input files pinned by SHA-256 at the `v0.15.0` tag, a pass bar of
  eight items over the profile's 32-record vector chain and its 37
  payload-digest cases, four cases to construct, and what the vectors do
  not exercise. `fetch-inputs.sh profile` assembles the package;
  `RUN-RECORD-PROFILE-TEMPLATE.md` is the record. The task is registered
  in `INDEPENDENT-VERIFICATION.md` §8 before any run; none is on record.

### Documentation

- Verification kit: the project's website, notes and Internet-Draft are
  no longer off limits during a run. An implementer lists what they read;
  the repository, the package, the documents beside the specification and
  other people's implementations stay off limits.
