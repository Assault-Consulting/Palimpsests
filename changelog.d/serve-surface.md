### Documentation

- **The serve's HTTP surface has a contract:** `docs/SERVE-SURFACE.md`. The
  reporting routes (`/v1/pala/events`, the two hook routes), the bearer
  check, the dry run, `GET /v1/pala/status` (`pala-serve-status/1`) and the
  doctor's JSON (`pala-doctor/1`) are **public** from 0.15, with their
  request and reply shapes written down and held by
  `tests/test_serve_surface.py`. `POST /v1/traces` is **provisional**: it
  reads the OpenTelemetry GenAI conventions, which are not stable. The
  OpenAI-shaped routes are **compatibility**: what is promised about them
  is what the document states. No behaviour of the serve changes.
