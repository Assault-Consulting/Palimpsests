### Fixed

- **Generators write LF on every platform.** The six generators of
  committed, byte-compared artifacts — the core, inference and consistency
  vectors, the SCITT statement v3 vector, the site's notes and the
  compatibility table — wrote text with the
  platform's newline, so on Windows a regenerated file was CRLF and no longer
  equal to the committed one; for the vectors, whose digests are pinned in
  recorded verification runs, a commit of it would have changed published
  digests. Each write now names `newline="\n"`; a test checks the source, and
  finds every `gen_*.py` / `build_*.py` itself so none is left off the list.
  Regenerating on Linux changes no byte. Found during the 0.14.0 release.
- **Every generated, byte-compared artifact checks out unconverted.** The
  other half of the same defect: `.gitattributes` exempted the core and
  inference vectors from line-ending conversion, but not the consistency
  vectors, the SCITT statement vectors (bridge run B3 had recorded a CRLF
  checkout's digest beside the real one), the generated site or
  `COMPATIBILITY.md` — so a Windows runner (autocrlf on) checked them out as
  CRLF and the comparison failed against LF output. They are now `-text` or
  `eol=lf`, and a test checks the attributes. Reproduced with an autocrlf
  checkout on Linux: the two Windows CI failures before, the full suite green
  after.
- **Two lock tests named the wrong process on Windows.** They expected the
  `Popen` pid in the lock's message; a venv's `python.exe` on Windows is a
  launcher whose child takes the lock. The holder now reports its own pid and
  the tests compare with that, exactly as before on every platform.
- **`.gitignore` covers any venv name** (`.venv*/`, `venv*/`). Hatchling builds
  the sdist from these rules, and a local build in `.venv-something/` put it in
  the archive (81 MB). Published artifacts are built by CI from a clean
  checkout and were not affected.
