### Security

- **A deeply nested tool argument or result no longer removes the record of
  the call.** The canonicalizer recursed once per level, and a value nested
  past about a thousand levels raised `RecursionError`, which the digest
  helper did not catch. On the hook routes a deep `tool_input` left nothing
  on the chain, and a deep `tool_response` left a call without its result —
  and no longer closed as cancelled when the serve stopped. A tool's output
  comes from outside (a page, an API, a file), so whoever controlled it
  could erase the record of the call that fetched it. Now such a value has
  no canonical form and the event is recorded without a digest, as for NaN.
- On the hook routes and on `/v1/pala/events` a call leaves the pending
  table only once its result is written. A result event refused for a
  digest that is not hex used to consume the call; a corrected report now
  lands.

### Changed

- **Inference profile §11: a value nested deeper than 128 arrays and objects
  has no canonical form.** `canonical_json`, `canonical_tool_args_digest`
  and `canonical_config_digest` raise `ValueError` for one;
  `palimpsests.audit.canonical_json.MAX_DEPTH` is the limit. RFC 8785 sets
  none and canonicalizers differ past their own.
- An OTLP/JSON body nested too deeply to read is answered 400, and a span
  attribute that is such JSON is recorded without a digest rather than
  digested as a string.
