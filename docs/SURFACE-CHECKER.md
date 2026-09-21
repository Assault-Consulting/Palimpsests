<!-- SPDX-FileCopyrightText: Assault Consulting -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Surface checker — how to run it

`scripts/check_surfaces.py` checks, every week or two, whether the
outside clients we integrate with still deliver what our adapters
depend on. It takes about five minutes, three of them OpenCode.

It does **not** test our adapters' logic — `pytest` does. It tests the
*client's* surface, on the version installed today. Those surfaces
change without notice; this is how we find out from a red line rather
than from a user.

---

## 1. One-time setup (≈15 min)

You need, on the machine that runs it: **Python 3.11+**,
**Node.js + npm**, **git**, and ordinary internet access (OpenCode
contacts `models.opencode.ai` at startup).

```bash
git clone https://github.com/Assault-Consulting/Palimpsests.git
cd Palimpsests
python -m venv .venv

# Linux / macOS
source .venv/bin/activate
# Windows (PowerShell)
.venv\Scripts\Activate.ps1

pip install -e ".[serve]" litellm
npm install -g opencode-ai
```

Check everything is in place:

```bash
python -c "import palimpsests, litellm, uvicorn; print('ok')"
opencode --version
```

If `opencode` is not found after `npm install -g`, npm's global
directory is not on your `PATH`. `npm config get prefix` shows where it
is; add `<prefix>/bin` (Linux/macOS) or `<prefix>` (Windows) to `PATH`.

**The checker uses none of your accounts.** OpenCode is started with a
temporary `HOME`, its own config and a stub model; your real
`~/.config/opencode` is not touched.

---

## 2. Running it

From the repository root, with the venv active:

```bash
git pull
python scripts/check_surfaces.py --report results/
```

Individual probes:

```bash
python scripts/check_surfaces.py litellm mcp
python scripts/check_surfaces.py opencode
```

**Exit status:** `0` — no red; `1` — at least one red. SKIP never
changes the exit status.

> In PowerShell the exit status is in `$LASTEXITCODE`; in bash, `$?`.
> Do not pipe the output through `| tail` or `| Select-Object` when you
> need the status: the pipe replaces it with its own. (This bit us while
> testing the checker — a red run reported exit 0 through a `tail`.)

---

## 3. Reading the result

```
| Surface  | State    | Version              | Detail                              |
|----------|----------|----------------------|-------------------------------------|
| litellm  | 🟢 GREEN | 1.102.0              | 1 call(s), 1 result(s), sources [1] |
| mcp      | 🟢 GREEN | stdio / JSON-RPC 2.0 | 1 call(s), 1 result(s), sources [1] |
| opencode | ⚪ SKIP  | 1.18.31              | the client never reached the serve… |
```

| State | Meaning | What to do |
|---|---|---|
| 🟢 **GREEN** | the surface delivered a call/result pair with the right source mark | nothing |
| 🔴 **RED** | the client **reached** the serve and the record did not follow, or the wrong one did — **the surface changed** | §4 |
| ⚪ **SKIP** | the client is not installed, **or never reached the serve at all** — a problem with this machine, not the surface | §5 |

**SKIP is not green.** It means "not checked". A client that is SKIP two
runs in a row is a question about the machine, not a reassurance.

---

## 4. When a probe is red 🔴

1. **Run that probe again on its own.** A single red can be a network
   blip: `python scripts/check_surfaces.py opencode`.
2. **If it repeats, record it the same day:**
   - the client version (the Version column);
   - the Detail line, verbatim;
   - commit the report `results/surfaces-YYYY-MM-DD.md`.
3. **The integration's README gets a warning the same day** — one
   paragraph: "on version X as of date Y, no record arrives; see the
   report". Do not wait for a fix before warning.
4. **Diagnose separately, not in a hurry.** For OpenCode: put
   [`integrations/opencode/probe-hooks.js`](../integrations/opencode/probe-hooks.js)
   beside the plugin and see which callbacks arrive (instructions in
   [the plugin README](../integrations/opencode/README.md)).
5. **Fix the adapter in its own PR**, with a checker re-run in the
   description.

What the Detail line usually means on red:

| Detail | Most likely |
|---|---|
| `1 call(s), 0 result(s)` | the client stopped delivering the result (e.g. LiteLLM no longer passes `role: tool` messages to the hook) |
| `0 call(s), 0 result(s)` with completions reached | the client's hooks do not fire — the OpenCode 1.18 case |
| `sources [0]` instead of `[1]` | the record arrived without the reported-by-client mark — a defect in **our** code, not the surface |
| `probe crashed: …` | the probe itself failed — probably the client API it calls has changed |

---

## 5. When a probe is grey ⚪

| Detail | What to do |
|---|---|
| `litellm not installed` | `pip install litellm` in the same venv |
| `opencode not on PATH` | see §1, `npm config get prefix` |
| `the client never reached the serve (0 completions)` | OpenCode could not start a session. Most often: no access to `models.opencode.ai` (VPN, corporate proxy, firewall). Check with `curl -I https://models.opencode.ai` |

A SKIP is never fixed by changing an adapter. If you find yourself
editing an adapter because of a SKIP — stop: the problem is the machine.

---

## 6. Cadence and what to commit

- **Every week or two**, on the same day as
  `scripts/distribution_metrics.py` — both reports go to `results/`.
- **Always commit the report, green ones too.** A dated green is
  evidence the surface was checked rather than assumed.
- After **every client update you notice** (OpenCode updates itself),
  run that client's probe out of cycle.
- Before **a release**, a run is mandatory and the report is cited in
  the release notes.

```bash
git checkout -b results/surfaces-$(date +%F)
git add results/surfaces-*.md
git commit -m "results: surface check $(date +%F)"
git push -u origin HEAD
```

---

## 7. What the checker does NOT check

- **Our adapters' logic** — `pytest` does. The checker can be green
  while the tests are red, and the other way round.
- **A real model.** Every probe uses a stub that always asks for one
  tool. Whether *your* model emits structured tool calls is a separate
  question, answered only by a run on real traffic.
- **Load, long sessions, subagents.** One pair per probe, nothing more.

A green checker means exactly one thing: **today, on this version, the
surface delivers what we rely on.** Nothing more.

---

## 8. Adding probes

Every new integration arrives **together with its probe** in
`scripts/check_surfaces.py`. An integration without a probe in the
checker is not merged. After the merge, the first run on a maintainer's
machine goes to `results/` as the baseline.
