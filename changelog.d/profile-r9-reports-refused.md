### Security

- **Reports that the serve refused are now on the chain** (inference profile
  **r9**). A client that reported without the key, with an empty one or with
  the wrong one was answered 401 and the calls it meant to report were simply
  absent from the chain; the refusals were counted only in the memory of the
  serving process. A new `EVENT` kind 14 `REPORTS_REFUSED` records, per
  reporting route, how many reports were refused (empty credential apart from
  a wrong one) and how many were accepted: one record at the first refusal on
  a route, at once, and one with the counts when the serve stops. A report
  that was read and rejected — a body that is not a report the route takes,
  one that cannot be read, one that broke the handler — is counted in the
  same record (`EVT_REJECTED`), and the first on a route is recorded at once
  as well. At most three records per route per run, so a request that fails
  cannot grow the chain. Nothing of the refused or rejected request is
  recorded; a dry run writes nothing. The reader states each
  such record as the advisory `reports_refused`; the verdict does not move.

### Added

- `PalaWriter.reports_refused(route, *, empty, wrong, accepted=0, rejected=0)`,
  `NativeAudit.reports_refused`, `ReportsRefusedView` and
  `decode_reports_refused` in `palimpsests.audit.reader`,
  `KIND_REPORTS_REFUSED` and the tags `EVT_ROUTE`, `EVT_REFUSED_EMPTY`,
  `EVT_REFUSED_WRONG`, `EVT_ACCEPTED`, `EVT_REJECTED`. The JSONL export carries the counts
  under `reports_refused`.

### Changed

- The inference profile vectors hold a third boot with the two records
  (32 records, `profile_revision` `r9`); the first 27 records are
  byte-identical to r8. A consumer that pins the number of records, boots or
  advisory codes has to move.
- A refused request on a reporting route now writes one record at its first
  occurrence per route per run, and so does a rejected one; earlier they
  wrote none.
