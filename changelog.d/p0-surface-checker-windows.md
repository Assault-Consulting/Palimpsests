### Fixed

- **The MCP proxy starts `npx` and `uvx` servers on Windows.** It started
  the server by bare name, and on Windows those launchers are `.cmd`
  shims that `subprocess` can start only by full path — `npx …` failed
  while `where npx` found it. The command is now resolved the way a shell
  resolves it; one that is not on `PATH` stops the proxy with one line on
  stderr and exit code 127.
- **The surface checker on Windows**: npm-installed clients (OpenCode,
  Claude Code) are launched by full path, for the same reason; a client
  that cannot be launched, or a Python without the `[serve]` extra, is
  SKIP rather than RED; the report file is written before anything is
  printed, and printing no longer fails on a console without the status
  marks.

### Changed

- **The surface checker has a fourth state, 🟠 ERROR**: the checker
  failed after the client had started, so the surface is unchecked. It
  used to be reported RED — a change in the surface — which it is not.
  ERROR fails the run like RED (exit 1); `docs/SURFACE-CHECKER.md` §4a
  says what to do with it.
- **The LiteLLM probe passes `tools`**, as an application does. LiteLLM
  imports the `mcp` package for any request with tools and does not
  install it; the probe is SKIP with that sentence when it is missing, and
  the LiteLLM README says to install it.
