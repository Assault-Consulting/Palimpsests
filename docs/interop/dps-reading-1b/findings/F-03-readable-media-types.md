# F-03 — Action binding 0.3.0: which media types a verifier reads

For: the Standard's repository. Not filed.

**Minimised:** L40, `specification_statements`. The case expects `not_checked` for `media_type` `application/octet-stream` over JSON bytes.

**At fault:** the text is silent.

**Draft:**
"Where it cannot read them, it reports them as not checked" does not say which `representation.media_type` values a verifier reads as a specification. A reading that parses the bytes whatever the media type verifies L40. Proposed: list the media types the reference check reads (e.g. `application/json` and `+json`), or say that a verifier states which it reads.
