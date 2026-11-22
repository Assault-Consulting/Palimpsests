### Fixed

- The server's start-up line printed a size threshold as `1.67772e+07`.
  It prints `16777216`: an operator compares that line with what they set.

### Documentation

- **Runbook: seven more pages**, each run against 0.15.0 from PyPI. A new
  group, "Check and keep the record": check a log for tampering; keep a log
  for six months without filling the disk; hand an auditor one file of
  evidence; prove that a log was only added to. In "Record what an AI agent
  does": LiteLLM, OpenTelemetry traces, the OpenCode plugin. The pages on
  verification, Article 12 and integrations link to them.
