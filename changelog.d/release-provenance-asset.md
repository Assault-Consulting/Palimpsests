### Security

- **A release carries its provenance as a file.** From this version the
  GitHub Release has a `palimpsests.intoto.jsonl` asset beside the wheel,
  the sdist and the SBOM: a Sigstore bundle with a SLSA provenance
  statement naming both distributions by SHA-256, made by a new last job of
  `release.yml`. `gh attestation verify <file> --repo
  Assault-Consulting/Palimpsests` checks a downloaded file against it. The
  PyPI attestations are unchanged; earlier releases have only those.
  `RELEASING.md` has the commands.
