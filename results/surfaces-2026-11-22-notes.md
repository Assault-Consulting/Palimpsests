<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Surface check 2026-11-22 — notes on the two SKIPs

Companion to `surfaces-2026-11-22.md`, which is the checker's own output and
is reproduced there unedited. Machine: workstation, Windows 11 10.0.26200,
Python 3.12.10, palimpsests 0.14.1 (git `e44fe8f`), run from `main` with
`f9ed15f` in its history. Exit code 0, no 🔴 and no 🟠.

## litellm ⚪ SKIP — the detail is wrong, the state is right

The report says `litellm not installed`. **litellm 1.110.2 is installed.**
What fails is importing it: that version ships a 52 MB native extension,
`litellm/rust_bridge/_native.pyd`, and this machine blocks it.

```
>>> import palimpsests, litellm, uvicorn
  File "...\litellm\rust_bridge\bindings.py", line 6, in <module>
    from litellm.rust_bridge import _native
ImportError: DLL load failed while importing _native: An Application Control
policy has blocked this file.
```

The machine's policy state, for the record:

```
(Get-MpComputerStatus).SmartAppControlState        -> On
Win32_DeviceGuard CodeIntegrityPolicyEnforcement   -> 2
```

Smart App Control is on and code-integrity enforcement is active, so an
unattested binary does not load. This is a condition of the machine, not of
the LiteLLM surface and not of anything in this repository. The LiteLLM
surface is therefore **unchecked on Windows in this run**; the Linux check of
2026-11-20 is where its verdict for 0.15 comes from.

**The checker's part in it is a reporting defect, not a wrong verdict.**
`probe_litellm` wraps the import and the metadata lookup in one
`try` / `except Exception` and answers `litellm not installed`
(`scripts/check_surfaces.py:290–297`). Two different situations — the package
absent, and the package present but unimportable — reach the same sentence,
and the Version column is left empty even though
`importlib.metadata.version("litellm")` returns `1.110.2` and would have
succeeded. A reader of the report cannot tell which happened.

Suggested direction, for whoever fixes it: read the version first, then import
inside its own `except ImportError`, and put the exception's message in the
detail — "installed but not importable: <message>" is a different fact from
"not installed", and on this machine it is the true one. Not changed here: the
checker is not touched in a report pull request.

## claude-code ⚪ SKIP — expected by construction

`not isolable on Windows yet — the client cannot be pointed at a temporary
home without failing to start a turn`. This is the known Windows limitation,
unchanged since it was first recorded on 2026-11-02; the client's real verdict
for 0.15 is the 🟢 GREEN on Linux in `surfaces-2026-11-20-2.md`.

## What the run does confirm on Windows

`mcp`, `opencode` 1.19.6 and `otel` (pydantic-ai 2.71.0) all 🟢 GREEN after the
ingestion routes were rewritten to read the request body themselves. The otel
row now reads `sources [2]`, the telemetry-derived mark, rather than `[1]`.
