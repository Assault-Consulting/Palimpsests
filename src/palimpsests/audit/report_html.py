# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The package's HTML rendering of ``pala-verification-report/1``.

One of the two renderings the U6 contract names (the other is
Auditor's PDF/JSON): this module turns the report *model* into a
single self-contained static page — no JavaScript, no external
assets, stdlib only — that opens offline in any browser and can be
attached to an email.

Discipline, inherited from the model and enforced here: the page is
an attestation of a check, never a certification; the verdict is read
from the report's ``verdict`` field (produced by ``derive_verdict``)
and never re-derived; everything except the checked-at line is
deterministic for the same report data, and the checked-at timestamp
sits alone on its own output line so two renderings of the same file
diff to one line — exactly like the JSON.
"""
from __future__ import annotations

from datetime import UTC, datetime
from html import escape as _e

_VERDICT_MEANING = {
    "sound": "everything checked, held",
    "partial": (
        "sound as far as checked — completeness was NOT checked (no "
        "anchor), so truncation or wholesale replacement would not have "
        "been detected"
    ),
    "violation": (
        "the chain broke, the container is malformed, a body does not "
        "match its header digest, or the head missed the supplied anchor"
    ),
}

_CSS = """
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#1a1a1a;
max-width:52rem;margin:2rem auto;padding:0 1rem}
h1{font-size:1.3rem;margin-bottom:.2rem}
h2{font-size:1.05rem;margin:1.4rem 0 .4rem;border-bottom:1px solid #ddd;
padding-bottom:.15rem}
code{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;
word-break:break-all}
table{border-collapse:collapse;width:100%;font-size:14px}
td,th{padding:.25rem .5rem;border:1px solid #e3e3e3;text-align:left;
vertical-align:top}
th{background:#f6f6f6;font-weight:600}
.kv td:first-child{width:14rem;color:#555}
.verdict{display:inline-block;padding:.25rem .7rem;border-radius:.3rem;
color:#fff;font-weight:700;letter-spacing:.03em}
.v-sound{background:#2e7d32}.v-partial{background:#b26a00}
.v-violation{background:#b71c1c}
.muted{color:#666;font-size:13px}
footer{margin-top:2rem;padding-top:.6rem;border-top:1px solid #ddd;
color:#666;font-size:13px}
"""


def _kv(rows: list[tuple[str, str]]) -> str:
    body = "".join(
        f"<tr><td>{_e(k)}</td><td>{v}</td></tr>" for k, v in rows
    )
    return f'<table class="kv">{body}</table>'


def _table(headers: list[str], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_e(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{c}</td>" for c in row) + "</tr>"
        for row in rows
    )
    return f"<table><tr>{head}</tr>{body}</table>"


def _seqs(values: list) -> str:
    return _e(", ".join(str(v) for v in values)) if values else "&mdash;"


def render_html(data: dict) -> str:
    """Render the report model as one self-contained HTML page (str)."""
    subject = data["subject"]
    container = data["container"]
    chain = data["chain"]
    anchor = data["anchor"]
    completeness = data["completeness"]
    verdict = data["verdict"]
    checked_ns = data["checked_at"]["wall_ns"]
    checked = datetime.fromtimestamp(
        checked_ns / 1e9, tz=UTC
    ).strftime("%Y-%m-%d %H:%M:%S UTC")

    if anchor is not None:
        anchor_clause = (
            f"against an anchor obtained from <code>"
            f"{_e(anchor['source_kind'])}</code>"
        )
    else:
        anchor_clause = (
            "with <strong>no anchor supplied</strong> &mdash; completeness "
            "was not checked"
        )

    parts: list[str] = []
    parts.append("<!DOCTYPE html>")
    parts.append('<html lang="en"><head><meta charset="utf-8">')
    parts.append(
        f"<title>PALA-1 verification report &mdash; "
        f"{_e(subject['filename'])}</title>"
    )
    parts.append(f"<style>{_CSS}</style></head><body>")
    parts.append("<h1>PALA-1 verification report</h1>")
    parts.append(
        f'<p class="muted">Format <code>{_e(data["format"])}</code> &middot; '
        f'spec <code>{_e(data["verifier"]["spec"])}</code></p>'
    )
    parts.append(
        f'<p><span class="verdict v-{_e(verdict)}">{_e(verdict.upper())}'
        f"</span> &mdash; {_e(_VERDICT_MEANING.get(verdict, ''))}</p>"
    )
    parts.append(
        f"<p>This tool verified <code>{_e(subject['filename'])}</code> "
        f"{anchor_clause}."
    )
    # The one non-deterministic line, alone, so two renderings diff to it.
    parts.append(
        f'<span class="muted">Checked at {_e(checked)} '
        f"(the auditing machine&rsquo;s clock).</span></p>"
    )

    parts.append("<h2>Subject</h2>")
    parts.append(_kv([
        ("filename", f"<code>{_e(subject['filename'])}</code>"),
        ("sha256", f"<code>{_e(subject['sha256'])}</code>"),
        ("bytes", str(subject["bytes"])),
        ("records", str(subject["records"])),
        ("boots / spans", f"{subject['boots']} / {subject['spans']}"),
        ("seq range",
         f"{subject['first_seq']} &ndash; {subject['last_seq']}"),
    ]))

    parts.append("<h2>Container (&sect;2.4)</h2>")
    rows = [
        ("well-formed", "yes" if container["well_formed"] else
         f"<strong>NO</strong>: {_e(str(container['malformed']))}"),
        ("bytes parsed / total",
         f"{container['bytes_parsed']} / {container['bytes_total']}"),
        ("body-digest mismatches",
         _seqs(container["body_digest_mismatches"])),
    ]
    parts.append(_kv(rows))

    parts.append("<h2>Chain (&sect;7.1)</h2>")
    parts.append(_kv([
        ("chain_ok", "yes" if chain["chain_ok"] else "<strong>NO</strong>"),
        ("head", f"<code>{_e(chain['head'])}</code>"),
        ("breaks", _seqs(chain["breaks"])),
        ("gaps", _seqs(chain["gaps"])),
        ("violations",
         _seqs([tuple(v) for v in chain["violations"]])),
        ("uninterpretable", _seqs(chain["uninterpretable"])),
    ]))

    parts.append("<h2>Anchor &amp; completeness (&sect;7.2)</h2>")
    if anchor is not None:
        parts.append(_kv([
            ("anchor head", f"<code>{_e(anchor['head'])}</code>"),
            ("source",
             f"<code>{_e(anchor['source_kind'])}</code> "
             f"{_e(str(anchor['source_detail']))}"),
        ]))
        if anchor["attempts"]:
            parts.append(_table(
                ["source", "outcome", "error"],
                [[f"<code>{_e(a['source_kind'])}</code>",
                  _e(a["outcome"]),
                  _e(a["error"]) if a["error"] else "&mdash;"]
                 for a in anchor["attempts"]],
            ))
    else:
        parts.append("<p>No anchor was supplied.</p>")
    comp = completeness["complete_to_anchor"]
    parts.append(_kv([
        ("complete to anchor",
         "not checked" if comp is None else ("yes" if comp else
                                             "<strong>NO</strong>")),
        ("anchor lag", str(completeness["anchor_lag"])),
        ("reason", _e(str(completeness["anchor_reason"]))),
    ]))

    parts.append("<h2>Existence pins</h2>")
    parts.append(_kv([
        ("external pins", _seqs(data["existence"]["external_pins"])),
        ("note", _e(data["existence"]["note"])),
    ]))

    if data["diagnosis"] is not None:
        d = data["diagnosis"]
        parts.append("<h2>Diagnosis</h2>")
        parts.append(_kv([
            ("pattern", _e(str(d["pattern"]))),
            ("at seq", str(d["at_seq"])),
            ("expected", f"<code>{_e(str(d['expected']))}</code>"),
            ("narrative", _e(str(d["narrative"]))),
        ]))

    adv = data["advisory"]
    parts.append("<h2>Advisories</h2>")
    parts.append(f'<p class="muted">{_e(adv["note"])}.</p>')
    if adv["items"]:
        parts.append(_table(
            ["code", "at seq", "detail"],
            [[_e(i["code"]), str(i["at_seq"]), _e(str(i["detail"]))]
             for i in adv["items"]],
        ))

    safety = data["safety"]
    parts.append("<h2>Safety records</h2>")
    parts.append(_kv([
        ("count", str(safety["count"])),
        ("unacknowledged candidates",
         str(safety["unacknowledged_candidates"])),
    ]))
    if safety["items"]:
        parts.append(_table(
            ["seq", "kind", "kind name"],
            [[str(i["seq"]), str(i["kind"]), _e(str(i["kind_name"]))]
             for i in safety["items"]],
        ))

    parts.append("<h2>Verifier</h2>")
    parts.append(_kv([
        ("tool", _e(data["verifier"]["tool"])),
        ("package", _e(data["verifier"]["package"])),
        ("time basis",
         f"{_e(data['time_basis']['axis'])}; wall claims qualified by "
         f"<code>{_e(data['time_basis']['wall_claims_qualified_by'])}</code>"),
    ]))

    parts.append(
        "<footer>This document attests a check performed at the stated "
        "time; it does not certify anything. Derived rendering of "
        "<code>pala-verification-report/1</code> &mdash; the chain itself "
        "is authoritative and re-verifiable without this page.</footer>"
    )
    parts.append("</body></html>")
    return "\n".join(parts) + "\n"
