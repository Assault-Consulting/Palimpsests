// SPDX-FileCopyrightText: Assault Consulting
// SPDX-License-Identifier: Apache-2.0
//
// Palimpsests audit reporter for OpenCode.
//
// The constructive half of ADR-0005: OpenCode runs its tool loop on the
// client side, so a text-mode loop is invisible to `palimpsests serve`
// (profile §3.1). This plugin reports every executed tool to the serve's
// ingestion surface, `POST /v1/pala/events`, where each call and result
// lands on the same chain as kinds 8/9 carrying `EVT_SOURCE =
// reported-by-client` (profile r5). The mark is an evidence-quality
// label, never a trust upgrade: the chain proves the report and its
// digests, not that the tool ran.
//
// Install: copy this file to `.opencode/plugins/` (project) or
// `~/.config/opencode/plugins/` (global). No dependencies.
//
// Configure (environment):
//   PALIMPSESTS_SERVE_URL      base URL of the serve (default
//                              http://127.0.0.1:11435 — the serve default)
//   PALIMPSESTS_SERVE_API_KEY  bearer key, when the serve runs with
//                              --api-key (same variable the serve reads)
//   PALIMPSESTS_AUDIT_REPORT   set to "0" to disable the plugin
//
// Contract, stated plainly:
//   * The plugin never blocks or alters a tool. A report failure is
//     logged and the tool proceeds; the audit layer records what it is
//     told, it does not gate the client.
//   * Arguments and outputs are sent to the serve, which stores only
//     their digests (`EVT_PAYLOAD_DIGEST`); the serve is local by default.
//   * `tool.execute.before` reports the call; `tool.execute.after`
//     reports the result. Because `after` has not fired for every call
//     on every OpenCode version (see the upstream notes in README.md),
//     the plugin also watches `message.part.updated` for the tool part
//     reaching `completed` or `error` and reports the result from there
//     if the hook did not. One result per call, whichever arrives first.
//   * A call whose result never arrives stays pending on the serve and
//     is recorded `cancelled` when the serve shuts down — an honest
//     "abandoned", never an invented outcome.

const DEFAULT_URL = "http://127.0.0.1:11435";

export const PalimpsestsAudit = async ({ client }) => {
  if (process.env.PALIMPSESTS_AUDIT_REPORT === "0") return {};

  const base = (process.env.PALIMPSESTS_SERVE_URL || DEFAULT_URL).replace(
    /\/+$/,
    "",
  );
  const apiKey = process.env.PALIMPSESTS_SERVE_API_KEY || "";

  // callID -> promise of the call report; a result report awaits it so
  // the serve sees the call before the result even if events race.
  const pending = new Map();

  const log = async (level, message, extra) => {
    try {
      await client.app.log({
        body: { service: "palimpsests-audit", level, message, extra },
      });
    } catch {
      // logging is best-effort; never let it surface into the tool loop
    }
  };

  const post = async (events) => {
    const headers = { "content-type": "application/json" };
    if (apiKey) headers.authorization = `Bearer ${apiKey}`;
    const res = await fetch(`${base}/v1/pala/events`, {
      method: "POST",
      headers,
      body: JSON.stringify({ events }),
    });
    if (!res.ok) throw new Error(`serve answered ${res.status}`);
    const data = await res.json();
    const bad = (data.results || []).filter((r) => r.error);
    if (bad.length) throw new Error(bad.map((r) => r.error).join("; "));
    return data;
  };

  const reportCall = (callID, tool, args) => {
    if (!callID || pending.has(callID)) return;
    const p = post([
      {
        type: "tool_call",
        id: callID,
        name: String(tool),
        arguments: args && typeof args === "object" ? args : {},
      },
    ]).catch((err) => log("warn", `call report failed: ${err.message}`, { callID, tool }));
    pending.set(callID, p);
  };

  const reportResult = async (callID, outcome, content) => {
    const p = pending.get(callID);
    if (!p) return; // unknown to us, or already reported
    pending.delete(callID);
    await p;
    try {
      await post([
        {
          type: "tool_result",
          call_id: callID,
          outcome,
          content: content == null ? "" : String(content),
        },
      ]);
    } catch (err) {
      await log("warn", `result report failed: ${err.message}`, { callID, outcome });
    }
  };

  await log("info", `reporting tool events to ${base}/v1/pala/events`);

  return {
    "tool.execute.before": async (input, output) => {
      reportCall(input.callID, input.tool, output && output.args);
    },

    "tool.execute.after": async (input, output) => {
      await reportResult(input.callID, "ok", output && output.output);
    },

    event: async ({ event }) => {
      // Fallback path: the tool part's terminal state, for the versions
      // where `tool.execute.after` does not fire (or not on failure).
      if (event.type !== "message.part.updated") return;
      const part = event.properties && event.properties.part;
      if (!part || part.type !== "tool" || !part.callID) return;
      const state = part.state || {};
      if (state.status === "completed") {
        await reportResult(part.callID, "ok", state.output);
      } else if (state.status === "error") {
        await reportResult(part.callID, "error", state.error);
      }
    },
  };
};
