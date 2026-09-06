#!/usr/bin/env python3
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
"""Distribution metrics — the monthly vantage on whether anyone is there.

One command, standard library only:

    python scripts/distribution_metrics.py --out results/distribution-2026-09.md

Pulls what can be pulled and reports what cannot, by name, rather than
printing a blank:

* PyPI — downloads for the last day / week / month (pypistats.org) and
  the release list (pypi.org).
* GitHub — stars, forks, watchers, open issues; with ``GITHUB_TOKEN``
  also the 14-day traffic (views, unique visitors, clones) and the
  inbound count: issues and pull requests opened by anyone outside the
  team (``--team`` logins).
* The hand-kept ledger ``results/distribution-ledger.json`` — listings,
  external verifier runs, integrators — the things no API can count.

The note is written in the same discipline as the benchmark notes: a
snapshot with its date, every number attributed to its source, and a
line per source that could not be reached. Numbers are the month's
observation, never a claim about a trend; the trend is the diff between
two notes.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

PACKAGE = "palimpsests"
REPO = "Assault-Consulting/Palimpsests"
UA = "palimpsests-distribution-metrics/1 (+https://github.com/Assault-Consulting/Palimpsests)"
DEFAULT_TEAM = ("andreysparish", "olksandrvertel-arch")


def _get(url: str, token: str | None = None) -> tuple[dict | list | None, str | None]:
    headers = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        return None, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, str(e)


def pypi(package: str) -> dict:
    out: dict = {"source": "pypistats.org + pypi.org"}
    recent, err = _get(f"https://pypistats.org/api/packages/{package}/recent")
    if recent is None:
        out["downloads_error"] = err
    else:
        out["downloads"] = recent.get("data", {})
    meta, err = _get(f"https://pypi.org/pypi/{package}/json")
    if meta is None:
        out["releases_error"] = err
    else:
        rels = meta.get("releases", {})
        out["version"] = meta.get("info", {}).get("version")
        out["releases"] = len(rels)
        latest = out["version"]
        files = rels.get(latest, []) if latest else []
        out["latest_uploaded"] = files[0]["upload_time_iso_8601"][:10] if files else None
    return out


def github(repo: str, token: str | None, team: tuple[str, ...]) -> dict:
    out: dict = {"source": "api.github.com"}
    meta, err = _get(f"https://api.github.com/repos/{repo}", token)
    if meta is None:
        out["repo_error"] = err
    else:
        out.update(
            stars=meta.get("stargazers_count"),
            forks=meta.get("forks_count"),
            watchers=meta.get("subscribers_count"),
            open_issues=meta.get("open_issues_count"),
            description=meta.get("description"),
        )
    if token:
        for name in ("views", "clones"):
            data, err = _get(f"https://api.github.com/repos/{repo}/traffic/{name}", token)
            if data is None:
                out[f"{name}_error"] = err
            else:
                out[f"{name}_14d"] = {"count": data.get("count"), "uniques": data.get("uniques")}
        refs, err = _get(f"https://api.github.com/repos/{repo}/traffic/popular/referrers", token)
        if refs is not None:
            out["referrers_14d"] = [(r["referrer"], r["count"], r["uniques"]) for r in refs[:5]]
    else:
        out["traffic_error"] = "GITHUB_TOKEN not set (traffic and inbound need it)"
    # inbound: issues + PRs by non-team authors, all time (cheap: one page of 100 per type)
    lower = {t.lower() for t in team}
    inbound = {"issues": 0, "pulls": 0, "authors": set()}
    for kind in ("issues", "pulls"):
        items, err = _get(
            f"https://api.github.com/repos/{repo}/{kind}?state=all&per_page=100", token
        )
        if items is None:
            inbound[f"{kind}_error"] = err
            continue
        for it in items:
            if kind == "issues" and "pull_request" in it:
                continue
            login = (it.get("user") or {}).get("login", "").lower()
            if login and login not in lower and not login.endswith("[bot]"):
                inbound[kind] += 1
                inbound["authors"].add(login)
    inbound["authors"] = sorted(inbound["authors"])
    out["inbound"] = inbound
    return out


def ledger(path: Path) -> dict:
    if not path.exists():
        return {"error": f"{path} not found — create it from the template in the docstring"}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except ValueError as e:
        return {"error": f"{path}: {e}"}


def _row(metric: str, value, source: str) -> str:
    return f"| {metric} | {value} | {source} |"


def render(snapshot: dict) -> str:
    py, gh, led = snapshot["pypi"], snapshot["github"], snapshot["ledger"]
    L: list[str] = []
    # The generated note carries its own REUSE header; the tag is assembled
    # so this source file does not itself contain a second, quoted tag.
    tag = "SPDX-" + "License-Identifier"
    L.append("<!-- " + "SPDX-" + "FileCopyrightText: Assault Consulting -->")
    L.append(f"<!-- {tag}: Apache-2.0 -->")
    L.append("")
    L.append(f"# Distribution — {snapshot['month']}")
    L.append("")
    L.append(
        f"Snapshot taken {snapshot['taken']} by `scripts/distribution_metrics.py`. "
        "Numbers are this month's observation from the named source; the trend is "
        "the diff against last month's note, never a claim inside one."
    )
    L.append("")
    L.append("## PyPI")
    L.append("")
    L.append("| Metric | Value | Source |")
    L.append("|---|---|---|")
    d = py.get("downloads")
    if d:
        for k in ("last_day", "last_week", "last_month"):
            L.append(f"| downloads, {k.replace('_', ' ')} | {d.get(k)} | pypistats.org |")
    else:
        L.append(_row("downloads", f"unavailable — {py.get('downloads_error')}", "pypistats.org"))
    if "releases" in py:
        latest = f"{py['releases']} (latest {py['version']}, {py['latest_uploaded']})"
        L.append(_row("releases on PyPI", latest, "pypi.org"))
    else:
        L.append(_row("releases", f"unavailable — {py.get('releases_error')}", "pypi.org"))
    L.append("")
    L.append("## GitHub")
    L.append("")
    L.append("| Metric | Value | Source |")
    L.append("|---|---|---|")
    if "stars" in gh:
        sfw = f"{gh['stars']} / {gh['forks']} / {gh['watchers']}"
        L.append(_row("stars / forks / watchers", sfw, "api.github.com"))
        L.append(_row("open issues (incl. PRs)", gh["open_issues"], "api.github.com"))
    else:
        unavailable = f"unavailable — {gh.get('repo_error')}"
        L.append(_row("stars / forks / watchers", unavailable, "api.github.com"))
    for name in ("views", "clones"):
        v = gh.get(f"{name}_14d")
        if v:
            L.append(
                _row(
                    f"{name}, 14 days (count / unique)",
                    f"{v['count']} / {v['uniques']}",
                    "traffic API",
                )
            )
        else:
            why = gh.get(f"{name}_error") or gh.get("traffic_error")
            L.append(_row(f"{name}, 14 days", f"unavailable — {why}", "traffic API"))
    if gh.get("referrers_14d"):
        refs = ", ".join(f"{r} ({c}/{u})" for r, c, u in gh["referrers_14d"])
        L.append(f"| top referrers, 14 days | {refs} | traffic API |")
    inb = gh.get("inbound", {})
    if "issues_error" in inb or "pulls_error" in inb:
        why = inb.get("issues_error") or inb.get("pulls_error")
        L.append(_row("inbound (non-team issues / PRs)", f"unavailable — {why}", "api.github.com"))
    else:
        who = ", ".join(inb.get("authors", [])) or "—"
        value = f"{inb.get('issues')} / {inb.get('pulls')} — {who}"
        L.append(_row("inbound, all time (non-team issues / PRs)", value, "api.github.com"))
    if gh.get("description"):
        L.append("")
        L.append(f"Repository description as shown to a visitor: *{gh['description']}*")
    L.append("")
    L.append("## Hand-kept ledger")
    L.append("")
    if "error" in led:
        L.append(f"unavailable — {led['error']}")
    else:
        L.append("| What | Count | Items |")
        L.append("|---|---|---|")
        for key, label in (
            ("listings", "listings (upstream docs, awesome-lists, registries)"),
            ("external_runs", "external verifier runs on record"),
            ("integrators", "integrators (someone embedded an adapter)"),
            ("publications", "publications / talks"),
        ):
            items = led.get(key, [])
            names = "; ".join(i if isinstance(i, str) else i.get("name", "?") for i in items) or "—"
            L.append(f"| {label} | {len(items)} | {names} |")
    L.append("")
    L.append("## Not claimed")
    L.append("")
    L.append(
        "Downloads include mirrors and CI installs; stars are not users; traffic is 14 "
        "days, not the month. None of these is evidence of adoption — an integrator on "
        "the ledger or an external run on record is."
    )
    L.append("")
    return "\n".join(L)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, help="write the note here (default: stdout)")
    ap.add_argument("--json", type=Path, help="also write the raw snapshot as JSON")
    ap.add_argument("--ledger", type=Path, default=Path("results/distribution-ledger.json"))
    ap.add_argument(
        "--team", nargs="*", default=list(DEFAULT_TEAM), help="GitHub logins that are not inbound"
    )
    ap.add_argument("--month", default=dt.date.today().strftime("%Y-%m"))
    args = ap.parse_args(argv[1:])
    token = os.environ.get("GITHUB_TOKEN")
    snapshot = {
        "month": args.month,
        "taken": dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "pypi": pypi(PACKAGE),
        "github": github(REPO, token, tuple(args.team)),
        "ledger": ledger(args.ledger),
    }
    text = render(snapshot)
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")
    else:
        sys.stdout.write(text)
    if args.json:
        args.json.write_text(json.dumps(snapshot, indent=1, default=list), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
