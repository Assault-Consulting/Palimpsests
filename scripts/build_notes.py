#!/usr/bin/env python3
"""Build the /notes/ section of palimpsests.dev from notes/*.md.

Each note is a markdown file with a small front-matter block. The script
writes site/notes/<slug>/index.html, the list page site/notes/index.html
and the RSS feed site/notes/feed.xml, regenerates site/sitemap.xml, and
rewrites the notes block of site/llms.txt. Output is deterministic: dates
come from the front matter, never from the clock, so a re-run on unchanged
sources changes nothing. tests/test_notes_build.py holds that.

The markdown dialect is deliberately small, because the same text is also
pasted by hand into other platforms: paragraphs, "## " and "### "
headings, "- " lists, fenced code blocks, `code`, **bold**, *italic* and
[links](url). Anything beyond that is a mistake in the note.

Usage: python3 scripts/build_notes.py
"""
# ruff: noqa: E501  (the HTML and RSS templates are kept on single lines, as they are emitted)
from __future__ import annotations

import html
import json
import re
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

SITE = "https://palimpsests.dev"
REPO = "https://github.com/Assault-Consulting/Palimpsests"
AUTHOR = "Andrii Sparysh"

# Static pages and the date each last changed. Update a date when its page changes.
STATIC_PAGES = [
    ("/", "2026-10-04", "weekly", "1.0"),
    ("/pala-1/", "2026-09-30", "monthly", "0.9"),
    ("/verify-without-reading/", "2026-09-30", "monthly", "0.8"),
    ("/eu-ai-act-article-12/", "2026-09-30", "monthly", "0.8"),
    ("/air-gapped/", "2026-09-30", "monthly", "0.8"),
    ("/integrations/", "2026-09-30", "monthly", "0.8"),
]

NAV = [
    ("/#caps", "Capabilities"),
    ("/pala-1/", "PALA-1"),
    ("/verify-without-reading/", "Verify"),
    ("/eu-ai-act-article-12/", "EU AI Act"),
    ("/air-gapped/", "Air-gapped"),
    ("/integrations/", "Integrations"),
]

MONTHS = ["January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December"]
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

LLMS_START = "<!-- notes:start -->"
LLMS_END = "<!-- notes:end -->"


@dataclass
class Note:
    title: str
    slug: str
    published: date
    description: str
    tags: list[str] = field(default_factory=list)
    body: str = ""

    @property
    def url(self) -> str:
        return f"{SITE}/notes/{self.slug}/"


# ---------------------------------------------------------------- parsing

def parse_note(path: Path) -> Note:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        raise ValueError(f"{path}: missing front matter")
    head, sep, body = text[4:].partition("\n---\n")
    if not sep:
        raise ValueError(f"{path}: unterminated front matter")
    meta: dict[str, str] = {}
    for line in head.splitlines():
        if line.strip():
            key, _, value = line.partition(":")
            meta[key.strip()] = value.strip()
    for key in ("title", "slug", "date", "description"):
        if not meta.get(key):
            raise ValueError(f"{path}: front matter needs '{key}'")
    if not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", meta["slug"]):
        raise ValueError(f"{path}: slug must be lowercase words joined by '-'")
    tags = [t.strip() for t in meta.get("tags", "").split(",") if t.strip()]
    return Note(
        title=meta["title"],
        slug=meta["slug"],
        published=date.fromisoformat(meta["date"]),
        description=meta["description"],
        tags=tags,
        body=body.strip() + "\n",
    )


def load_notes(notes_dir: Path) -> list[Note]:
    notes = [parse_note(p) for p in sorted(notes_dir.glob("*.md"))]
    slugs = [n.slug for n in notes]
    if len(slugs) != len(set(slugs)):
        raise ValueError("two notes share a slug")
    return sorted(notes, key=lambda n: (-n.published.toordinal(), n.title))


# ---------------------------------------------------------------- markdown

_CODE = re.compile(r"`([^`]+)`")
_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")
_BOLD = re.compile(r"\*\*([^*]+)\*\*")
_ITALIC = re.compile(r"(?<![*\w])\*([^*\n]+)\*(?![*\w])")
_STASHED = re.compile("\x00(\\d+)\x00")


def inline(text: str) -> str:
    """Inline markup for one line of text. Code spans are left untouched."""
    codes: list[str] = []

    def stash(match: re.Match[str]) -> str:
        codes.append(match.group(1))
        return f"\x00{len(codes) - 1}\x00"

    text = _CODE.sub(stash, text)
    text = html.escape(text, quote=False)
    text = _LINK.sub(lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>', text)
    text = _BOLD.sub(r"<b>\1</b>", text)
    text = _ITALIC.sub(r"<i>\1</i>", text)
    return _STASHED.sub(
        lambda m: f"<code>{html.escape(codes[int(m.group(1))], quote=False)}</code>", text
    )


def anchor_id(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def render(md: str) -> str:
    """The small markdown dialect described in the module docstring, as HTML."""
    out: list[str] = []
    para: list[str] = []
    lines = md.splitlines()

    def flush() -> None:
        if para:
            out.append(f"<p>{inline(' '.join(para))}</p>")
            para.clear()

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            i += 1
            code: list[str] = []
            while i < len(lines) and not lines[i].startswith("```"):
                code.append(lines[i])
                i += 1
            if i == len(lines):
                raise ValueError("unclosed code block")
            out.append("<pre><code>" + html.escape("\n".join(code), quote=False) + "</code></pre>")
            i += 1
        elif line.startswith(("## ", "### ")):
            flush()
            level = 2 if line.startswith("## ") else 3
            text = line[level + 1:].strip()
            out.append(f'<h{level} id="{anchor_id(text)}">{inline(text)}</h{level}>')
            i += 1
        elif line.startswith("- "):
            flush()
            items: list[str] = []
            while i < len(lines) and lines[i].startswith("- "):
                items.append(lines[i][2:].strip())
                i += 1
            out.append("<ul>\n" + "\n".join(f"  <li>{inline(t)}</li>" for t in items) + "\n</ul>")
        elif not line.strip():
            flush()
            i += 1
        elif line.startswith("#"):
            raise ValueError(f"only '## ' and '### ' headings are allowed: {line!r}")
        else:
            para.append(line.strip())
            i += 1
    flush()
    return "\n".join(out)


# ---------------------------------------------------------------- pages

def human_date(d: date) -> str:
    return f"{d.day} {MONTHS[d.month - 1]} {d.year}"


def rfc822(d: date) -> str:
    return f"{DAYS[d.weekday()]}, {d.day:02d} {MONTHS[d.month - 1][:3]} {d.year} 09:00:00 +0000"


BRAND_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" aria-hidden="true">
          <rect width="128" height="128" fill="#15151f"/>
          <g stroke="#e6dfce" stroke-width="8" stroke-linecap="round" fill="none">
            <path d="M32 37h32"/><path d="M74 37h6" opacity="0.45"/><path d="M88 37h4" opacity="0.28"/>
            <path d="M32 55h26"/><path d="M66 55h10" opacity="0.55"/><path d="M84 55h5" opacity="0.32"/>
            <path d="M32 73h34"/><path d="M74 73h4" opacity="0.4"/><path d="M86 73h6" opacity="0.22"/>
            <path d="M32 91h22"/><path d="M62 91h8" opacity="0.5"/><path d="M78 91h4" opacity="0.28"/>
          </g>
        </svg>"""


def page(path: str, title: str, description: str, graph: list[dict], body: str) -> str:
    esc_title = html.escape(title)
    esc_desc = html.escape(description)
    ld = json.dumps({"@context": "https://schema.org", "@graph": graph},
                    ensure_ascii=False, indent=2)
    links = "\n".join(f'      <a class="hide-sm" href="{href}">{label}</a>' for href, label in NAV)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{esc_title}</title>
<meta name="description" content="{esc_desc}" />
<link rel="canonical" href="{SITE}{path}" />
<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1" />
<meta name="author" content="{AUTHOR}" />
<meta name="theme-color" content="#15151f" />
<meta property="og:type" content="article" />
<meta property="og:site_name" content="Palimpsests" />
<meta property="og:title" content="{esc_title}" />
<meta property="og:description" content="{esc_desc}" />
<meta property="og:url" content="{SITE}{path}" />
<meta property="og:locale" content="en" />
<meta name="twitter:card" content="summary" />
<meta name="twitter:title" content="{esc_title}" />
<meta name="twitter:description" content="{esc_desc}" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="manifest" href="/site.webmanifest" />
<link rel="alternate" type="application/rss+xml" title="Palimpsests notes" href="{SITE}/notes/feed.xml" />
<script type="application/ld+json">
{ld}
</script>
<link rel="preconnect" href="https://fonts.googleapis.com" />
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
<link href="https://fonts.googleapis.com/css2?family=Archivo+Expanded:wght@600;700;800&family=Archivo:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet" />
<link rel="stylesheet" href="/site.css" />
</head>
<body>

<nav>
  <div class="wrap nav">
    <a class="brand" href="/" aria-label="Palimpsests home">
      <span class="brand__mark">
        {BRAND_SVG}
      </span>
      Palimpsests
    </a>
    <div class="nav__links">
{links}
      <a class="btn" href="{REPO}" rel="noopener">GitHub ↗</a>
    </div>
  </div>
</nav>

<main class="doc">
  <div class="wrap">
    <div class="doc__in">
{body}
    </div>
  </div>
</main>

<footer>
  <div class="wrap foot">
    <a class="brand" href="/" aria-label="Palimpsests">
      <span class="brand__mark">
        {BRAND_SVG}
      </span>
      Palimpsests
    </a>
    <div class="foot__links">
      <a href="/notes/">Notes</a>
      <a href="{REPO}" rel="noopener">GitHub</a>
      <a href="https://pypi.org/project/palimpsests/" rel="noopener">PyPI</a>
      <a href="https://doi.org/10.5281/zenodo.21978107" rel="noopener">Paper</a>
      <a href="https://datatracker.ietf.org/doc/draft-sparysh-pala-audit/" rel="noopener">Internet-Draft</a>
      <a href="{REPO}/blob/main/LICENSE" rel="noopener">License</a>
      <a href="{REPO}/blob/main/SECURITY.md" rel="noopener">Security</a>
    </div>
    <div class="foot__meta">
      Assault Consulting · Kyiv<br/>
      Apache-2.0 · Python 3.11+ · latest on PyPI
    </div>
  </div>
</footer>

</body>
</html>
"""


def note_page(note: Note) -> str:
    path = f"/notes/{note.slug}/"
    graph = [
        {
            "@type": "BlogPosting",
            "@id": note.url + "#post",
            "headline": note.title,
            "description": note.description,
            "url": note.url,
            "mainEntityOfPage": note.url,
            "datePublished": note.published.isoformat(),
            "dateModified": note.published.isoformat(),
            "inLanguage": "en",
            "keywords": note.tags,
            "author": {"@type": "Person", "name": AUTHOR},
            "publisher": {"@id": SITE + "/#org"},
            "isPartOf": {"@id": SITE + "/notes/#blog"},
        },
        {
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "Palimpsests", "item": SITE + "/"},
                {"@type": "ListItem", "position": 2, "name": "Notes", "item": SITE + "/notes/"},
                {"@type": "ListItem", "position": 3, "name": note.title, "item": note.url},
            ],
        },
    ]
    body = f"""<p class="crumbs"><a href="/">Palimpsests</a> / <a href="/notes/">Notes</a></p>
<span class="eyebrow">Note · {human_date(note.published)} · {AUTHOR}</span>
<h1 class="display">{html.escape(note.title)}</h1>
{render(note.body)}
<div class="related">
  <a class="btn" href="/notes/">All notes →</a>
  <a class="btn" href="/">Palimpsests →</a>
</div>"""
    return page(path, f"{note.title} — Palimpsests notes", note.description, graph, body)


def index_page(notes: list[Note]) -> str:
    entries = "\n".join(
        f"""<h2><a href="/notes/{n.slug}/">{html.escape(n.title)}</a></h2>
<p class="crumbs">{human_date(n.published)}</p>
<p>{html.escape(n.description)}</p>"""
        for n in notes
    )
    graph = [{
        "@type": "Blog",
        "@id": SITE + "/notes/#blog",
        "name": "Palimpsests notes",
        "url": SITE + "/notes/",
        "inLanguage": "en",
        "publisher": {"@id": SITE + "/#org"},
        "blogPost": [
            {"@type": "BlogPosting", "headline": n.title, "url": n.url,
             "datePublished": n.published.isoformat()}
            for n in notes
        ],
    }]
    description = ("Short notes on audit logs for AI systems, the EU AI Act and running "
                   "language models on your own hardware.")
    body = f"""<p class="crumbs"><a href="/">Palimpsests</a> / Notes</p>
<span class="eyebrow">Notes</span>
<h1 class="display">Notes</h1>
<p class="lede">{description} New notes also go out through the <a href="/notes/feed.xml">RSS feed</a>.</p>
{entries}"""
    return page("/notes/", "Notes — Palimpsests (PALA-1)", description, graph, body)


def feed(notes: list[Note]) -> str:
    items = []
    for n in notes:
        content = render(n.body)
        if "]]>" in content:
            raise ValueError(f"{n.slug}: ']]>' cannot appear inside the feed")
        categories = "".join(f"\n    <category>{html.escape(t)}</category>" for t in n.tags)
        items.append(f"""  <item>
    <title>{html.escape(n.title)}</title>
    <link>{n.url}</link>
    <guid isPermaLink="true">{n.url}</guid>
    <pubDate>{rfc822(n.published)}</pubDate>{categories}
    <description>{html.escape(n.description)}</description>
    <content:encoded><![CDATA[{content}]]></content:encoded>
  </item>""")
    newest = notes[0].published if notes else date(2026, 10, 4)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>Palimpsests notes</title>
  <link>{SITE}/notes/</link>
  <atom:link href="{SITE}/notes/feed.xml" rel="self" type="application/rss+xml" />
  <description>Short notes on audit logs for AI systems, the EU AI Act and running language models on your own hardware.</description>
  <language>en</language>
  <lastBuildDate>{rfc822(newest)}</lastBuildDate>
{chr(10).join(items)}
</channel>
</rss>
"""


def sitemap(notes: list[Note]) -> str:
    rows = list(STATIC_PAGES)
    if notes:
        rows.append(("/notes/", notes[0].published.isoformat(), "weekly", "0.7"))
        rows += [(f"/notes/{n.slug}/", n.published.isoformat(), "monthly", "0.6") for n in notes]
    urls = "\n".join(
        f"""  <url>
    <loc>{SITE}{loc}</loc>
    <lastmod>{mod}</lastmod>
    <changefreq>{freq}</changefreq>
    <priority>{prio}</priority>
  </url>"""
        for loc, mod, freq, prio in rows
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{urls}
</urlset>
"""


def llms_block(notes: list[Note]) -> str:
    lines = [f"- [{n.title}]({n.url}): {n.description}" for n in notes]
    return "\n".join([LLMS_START, "## Notes", "", *lines, LLMS_END])


# ---------------------------------------------------------------- build

def build(notes_dir: Path, site_dir: Path) -> None:
    notes = load_notes(notes_dir)
    out = site_dir / "notes"
    out.mkdir(parents=True, exist_ok=True)
    for n in notes:
        (out / n.slug).mkdir(exist_ok=True)
        (out / n.slug / "index.html").write_text(note_page(n), encoding="utf-8")
    (out / "index.html").write_text(index_page(notes), encoding="utf-8")
    (out / "feed.xml").write_text(feed(notes), encoding="utf-8")
    (site_dir / "sitemap.xml").write_text(sitemap(notes), encoding="utf-8")

    llms = site_dir / "llms.txt"
    text = llms.read_text(encoding="utf-8")
    start, end = text.find(LLMS_START), text.find(LLMS_END)
    if start < 0 or end < start:
        raise ValueError("site/llms.txt needs the notes:start / notes:end markers")
    llms.write_text(text[:start] + llms_block(notes) + text[end + len(LLMS_END):],
                    encoding="utf-8")


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    build(root / "notes", root / "site")
