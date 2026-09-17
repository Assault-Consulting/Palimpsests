// SPDX-FileCopyrightText: Assault Consulting
// SPDX-License-Identifier: Apache-2.0
//
// Diagnostic probe — which OpenCode plugin surfaces actually fire?
//
// The traffic run (independent-runs/opencode-traffic-1) found the audit
// plugin loading and announcing itself on OpenCode 1.18.25 and 1.18.31,
// then never emitting an event: no `tool.execute.before`, no
// `tool.execute.after`, and no `message.part.updated` fallback. Upstream
// has moved plugin loading toward a v2 envelope (`export default {id,
// effect|setup}`) while the legacy directory path still *executes* the
// plugin function — which is exactly the shape of what we observed: our
// function ran, the hooks it returned were never dispatched.
//
// Rather than rewrite the audit plugin against a guess, run this probe
// for five minutes on the same client and let it say what is true there.
// It touches nothing: no network, no serve, no reporting. It appends one
// JSON line per observed callback to a file.
//
//   cp probe-hooks.js ~/.config/opencode/plugins/
//   export PALIMPSESTS_PROBE_LOG=~/opencode-probe.jsonl
//   # start OpenCode, ask the model to read a file and run a command
//   cat ~/opencode-probe.jsonl
//
// Then read it: if `hook:tool.execute.before` lines appear, the legacy
// map still dispatches and the audit plugin's silence has another cause.
// If only `loaded` and `event:*` lines appear, hook dispatch is gone on
// that version and the audit plugin must be authored against the v2 API.
// If the file is empty or absent, the plugin function itself never ran.

import { appendFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

const LOG =
  process.env.PALIMPSESTS_PROBE_LOG || join(homedir(), "opencode-probe.jsonl");

const note = (what, detail) => {
  try {
    appendFileSync(
      LOG,
      JSON.stringify({ at: new Date().toISOString(), what, detail }) + "\n",
    );
  } catch {
    // A probe that throws is worse than a probe that misses a line.
  }
};

export const PalimpsestsProbe = async (context) => {
  note("loaded", {
    // What the host handed us — the shape of the context is itself a
    // version signal, and it is the thing a v2 rewrite has to target.
    contextKeys: Object.keys(context || {}).sort(),
    opencodeVersionEnv: process.env.OPENCODE_VERSION || null,
    node: process.version,
  });

  const hook = (name) => async (input, output) => {
    note(`hook:${name}`, {
      inputKeys: Object.keys(input || {}).sort(),
      outputKeys: Object.keys(output || {}).sort(),
      tool: (input && input.tool) || null,
      callID: (input && input.callID) || null,
    });
  };

  return {
    "tool.execute.before": hook("tool.execute.before"),
    "tool.execute.after": hook("tool.execute.after"),
    "chat.message": hook("chat.message"),
    "permission.ask": hook("permission.ask"),

    event: async ({ event }) => {
      // Every event type, counted once per type with its part shape —
      // enough to tell whether the fallback surface still exists.
      const part =
        (event && event.properties && event.properties.part) || undefined;
      note(`event:${event && event.type}`, {
        partType: part ? part.type : null,
        partStatus: part && part.state ? part.state.status : null,
        callID: part ? part.callID || null : null,
      });
    },
  };
};
