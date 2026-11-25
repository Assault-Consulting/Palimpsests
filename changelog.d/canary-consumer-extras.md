### Fixed

- **The consumer canary installs this checkout with the extras the
  consumer asks for.** The workflow named `[pala]` itself. When the
  consumer began to use the SCITT bridge and required
  `palimpsests[pala,scitt]`, its new tests failed here for a missing
  `cbor2` and the canary reported a break that this commit had not made.
  `scripts/consumer_canary.py extras` now reads the extras from the
  consumer's own requirement; an extra this checkout does not define stops
  the canary as broken, not as red.
- The canary's ledger of expected failures is empty: the consumer follows
  0.15, and all 41 lines pass.
