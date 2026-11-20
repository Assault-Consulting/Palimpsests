### Security

- **A payload digest stands for one value, or there is none** (inference
  profile §11). Two values could share an `EVT_PAYLOAD_DIGEST`:
  `{"id": 9007199254740992}` and `{"id": 9007199254740993}`, because
  RFC 8785 writes every number as a double; and `{"a": 1, "a": 2}` had the
  digest of `{"a": 2}`, because the repetition was gone before the value was
  digested, while a reader that keeps the first value reads another call.
  Now an integer beyond ±(2^53 − 1) and an object that repeats a key have no
  canonical form (RFC 7493 §2.2, §2.3): the event is recorded without a
  digest, as for NaN.
- A report whose own object repeats a key — two tool names, two call ids —
  is rejected (400) on the hook routes, per event on `/v1/pala/events`, and
  for an OTLP/JSON export: there is no one event to record.

### Added

- `palimpsests.audit.canonical_json.loads` — `json.loads` that returns a
  `DuplicateKeys` (a `dict`) for an object that repeats a key, so the
  repetition is still in sight when the value is digested;
  `has_duplicate_keys`; `MAX_SAFE_INTEGER`.
- `docs/specs/pala-1/profiles/payload-digest-vectors.json`: 37 cases as JSON
  text — 22 with their canonical bytes and digest, 15 that have none, with
  the reason — for another implementation to check itself against.

### Changed

- `canonical_json`, `canonical_tool_args_digest` and
  `canonical_config_digest` raise `ValueError` for an integer beyond
  ±(2^53 − 1); before, it was digested as the nearest double. A number
  written with a fraction or an exponent is a double as it stands and is
  digested as before.
- The reporting routes read the request body themselves. A body that is not
  JSON, or not one object, is answered 400 in the serve's error shape
  (`{"error": {"message", "type"}}`); before, the framework answered 422
  with its own. A report is read whatever its `Content-Type`.
