#!/usr/bin/env python3
"""Build the /notes/ and /runbook/ sections of palimpsests.dev.

Each note (notes/*.md) and each runbook page (runbook/*.md) is a markdown
file with a small front-matter block. The script writes
site/notes/<slug>/index.html, the list page site/notes/index.html and the
RSS feed site/notes/feed.xml; site/runbook/<slug>/index.html and the
runbook's own page site/runbook/index.html, made from runbook/index.md
plus the list of runbook pages; regenerates site/sitemap.xml; and rewrites
the notes and runbook blocks of site/llms.txt and the latest-notes block of
the home page. Output is deterministic: dates
come from the front matter, never from the clock, so a re-run on unchanged
sources changes nothing. tests/test_notes_build.py holds that.

A link to a page of this site, written as https://palimpsests.dev/<path>,
must name a page that exists — a static page, a note or a runbook page —
and a runbook page's `next` list must name runbook pages; the build stops
otherwise, so a reader never follows a link to a page that is not there.

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
    ("/", "2026-11-22", "weekly", "1.0"),
    ("/pala-1/", "2026-11-22", "monthly", "0.9"),
    ("/verify-without-reading/", "2026-11-22", "monthly", "0.8"),
    ("/eu-ai-act-article-12/", "2026-11-22", "monthly", "0.8"),
    ("/air-gapped/", "2026-11-20", "monthly", "0.8"),
    ("/integrations/", "2026-11-22", "monthly", "0.8"),
]

NAV = [
    ("/#caps", "Capabilities"),
    ("/pala-1/", "PALA-1"),
    ("/verify-without-reading/", "Verify"),
    ("/eu-ai-act-article-12/", "EU AI Act"),
    ("/air-gapped/", "Air-gapped"),
    ("/integrations/", "Integrations"),
    ("/runbook/", "Runbook"),
    ("/notes/", "Notes"),
]

#: The product pages a note may name as the page it belongs to (`page:` in
#: its front matter), with the name shown for each.
PRODUCT_PAGES = {
    "/pala-1/": "PALA-1: the record format",
    "/verify-without-reading/": "Verify a log without reading it",
    "/eu-ai-act-article-12/": "EU AI Act Article 12 logging",
    "/air-gapped/": "Air-gapped LLM inference",
    "/integrations/": "Integrations: recording agent tool calls",
}
READMORE_START = "<!-- read-more:start -->"
READMORE_END = "<!-- read-more:end -->"

#: Search results cut a title near 60 characters and a description near 155.
#: A page whose own title or description is longer gives a shorter one for
#: the head (`seo_title`, `seo_description`); the page itself shows the full
#: one. The build stops on a head that is too long.
TITLE_MAX = 60
DESCRIPTION_MAX = 155

OG_IMAGE = SITE + "/og.png"
OG_IMAGE_ALT = ("Palimpsests: a tamper-evident audit log for AI agents, verifiable "
                "without the key")
AUTHOR_LD = {
    "@type": "Person",
    "@id": SITE + "/#andrii-sparysh",
    "name": AUTHOR,
    "url": SITE + "/",
    "jobTitle": "Co-founder, Assault Consulting",
    "worksFor": {"@id": SITE + "/#org"},
    "sameAs": ["https://datatracker.ietf.org/doc/draft-sparysh-pala-audit/"],
}

# The runbook's groups, in the order its page lists them. A runbook page names
# its group in front matter; a group with no page yet is not shown.
RUNBOOK_GROUPS = [
    ("run", "Run a model on your own machine"),
    ("record", "Record what an AI agent does"),
    ("check", "Check and keep the record"),
]
RUNBOOK_START = "<!-- runbook:start -->"
RUNBOOK_END = "<!-- runbook:end -->"

MONTHS = ["January", "February", "March", "April", "May", "June", "July",
          "August", "September", "October", "November", "December"]
DAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]

LLMS_START = "<!-- notes:start -->"
LLMS_END = "<!-- notes:end -->"
HOME_START = "<!-- latest-notes:start -->"
HOME_END = "<!-- latest-notes:end -->"
HOME_LATEST = 3


@dataclass
class Note:
    title: str
    slug: str
    published: date
    description: str
    tags: list[str] = field(default_factory=list)
    body: str = ""
    seo_title: str = ""
    seo_description: str = ""
    page: str = ""  # the product page this note belongs to
    related: list[str] = field(default_factory=list)  # slugs of the notes to read next

    @property
    def url(self) -> str:
        return f"{SITE}/notes/{self.slug}/"


@dataclass
class Recipe:
    """One runbook page: a single task, in steps."""

    title: str
    slug: str
    group: str
    order: int
    updated: date
    description: str
    next: list[str] = field(default_factory=list)
    body: str = ""
    seo_title: str = ""
    seo_description: str = ""

    @property
    def url(self) -> str:
        return f"{SITE}/runbook/{self.slug}/"


@dataclass
class RunbookIntro:
    """The runbook's own page: runbook/index.md, before the list of pages."""

    title: str
    updated: date
    description: str
    body: str = ""
    seo_title: str = ""
    seo_description: str = ""


# ---------------------------------------------------------------- parsing

def _front_matter(path: Path, required: tuple[str, ...]) -> tuple[dict[str, str], str]:
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
    for key in required:
        if not meta.get(key):
            raise ValueError(f"{path}: front matter needs '{key}'")
    if "slug" in required and not re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", meta["slug"]):
        raise ValueError(f"{path}: slug must be lowercase words joined by '-'")
    return meta, body.strip() + "\n"


def _listed(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_note(path: Path) -> Note:
    meta, body = _front_matter(path, ("title", "slug", "date", "description"))
    return Note(
        title=meta["title"],
        slug=meta["slug"],
        published=date.fromisoformat(meta["date"]),
        description=meta["description"],
        tags=_listed(meta.get("tags", "")),
        body=body,
        seo_title=meta.get("seo_title", ""),
        seo_description=meta.get("seo_description", ""),
        page=meta.get("page", ""),
        related=_listed(meta.get("related", "")),
    )


def parse_recipe(path: Path) -> Recipe:
    meta, body = _front_matter(
        path, ("title", "slug", "group", "order", "updated", "description"))
    groups = [key for key, _ in RUNBOOK_GROUPS]
    if meta["group"] not in groups:
        raise ValueError(f"{path}: group must be one of {', '.join(groups)}")
    return Recipe(
        title=meta["title"],
        slug=meta["slug"],
        group=meta["group"],
        order=int(meta["order"]),
        updated=date.fromisoformat(meta["updated"]),
        description=meta["description"],
        next=_listed(meta.get("next", "")),
        body=body,
        seo_title=meta.get("seo_title", ""),
        seo_description=meta.get("seo_description", ""),
    )


def parse_runbook_intro(path: Path) -> RunbookIntro:
    meta, body = _front_matter(path, ("title", "updated", "description"))
    return RunbookIntro(
        title=meta["title"],
        updated=date.fromisoformat(meta["updated"]),
        description=meta["description"],
        body=body,
        seo_title=meta.get("seo_title", ""),
        seo_description=meta.get("seo_description", ""),
    )


def load_runbook(runbook_dir: Path) -> tuple[RunbookIntro | None, list[Recipe]]:
    """The runbook's own page and its pages, in the order its page lists them."""
    if not runbook_dir.is_dir():
        return None, []
    intro_path = runbook_dir / "index.md"
    recipes = [parse_recipe(p) for p in sorted(runbook_dir.glob("*.md")) if p != intro_path]
    if recipes and not intro_path.exists():
        raise ValueError(f"{intro_path} is missing: the runbook needs its own page")
    slugs = [r.slug for r in recipes]
    if len(slugs) != len(set(slugs)):
        raise ValueError("two runbook pages share a slug")
    for r in recipes:
        unknown = [s for s in r.next if s not in slugs or s == r.slug]
        if unknown:
            raise ValueError(f"runbook/{r.slug}: 'next' names no other runbook page: {unknown}")
    group_rank = {key: i for i, (key, _) in enumerate(RUNBOOK_GROUPS)}
    recipes.sort(key=lambda r: (group_rank[r.group], r.order, r.title))
    intro = parse_runbook_intro(intro_path) if intro_path.exists() else None
    return intro, recipes


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


def site_paths(notes: list[Note], recipes: list[Recipe]) -> set[str]:
    """Every path of this site a note or a runbook page may link to."""
    paths = {loc for loc, *_ in STATIC_PAGES}
    paths |= {"/notes/", "/notes/feed.xml"} | {f"/notes/{n.slug}/" for n in notes}
    if recipes:
        paths |= {"/runbook/"} | {f"/runbook/{r.slug}/" for r in recipes}
    return paths


def check_site_links(sources: dict[str, str], known: set[str]) -> None:
    """Refuse a link to a page of this site that does not exist.

    ``sources`` maps a name for the error message to markdown. Only links
    written as https://palimpsests.dev/... are checked; the anchor and the
    query are not part of the page.
    """
    broken: list[str] = []
    for name, text in sources.items():
        for match in _LINK.finditer(text):
            url = match.group(2)
            if url != SITE and not url.startswith(SITE + "/"):
                continue
            path = re.split(r"[#?]", url[len(SITE):], maxsplit=1)[0] or "/"
            if path not in known:
                broken.append(f"{name}: {url}")
    if broken:
        raise ValueError("links to pages this site does not have:\n  " + "\n  ".join(broken))


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


def page(path: str, title: str, description: str, graph: list[dict], body: str, *,
         og_type: str = "article", extra_meta: str = "", index: bool = True) -> str:
    if len(title) > TITLE_MAX:
        raise ValueError(f"{path}: the title is {len(title)} characters, over {TITLE_MAX}: "
                         f"give the page a seo_title ({title!r})")
    if len(description) > DESCRIPTION_MAX:
        raise ValueError(f"{path}: the description is {len(description)} characters, over "
                         f"{DESCRIPTION_MAX}: give the page a seo_description")
    esc_title = html.escape(title)
    esc_desc = html.escape(description)
    if index:
        indexing = (f'<link rel="canonical" href="{SITE}{path}" />\n<meta name="robots" '
                    'content="index, follow, max-image-preview:large, max-snippet:-1, '
                    'max-video-preview:-1" />')
    else:
        indexing = '<meta name="robots" content="noindex" />'
    extra = extra_meta + "\n" if extra_meta else ""
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
{indexing}
<meta name="author" content="{AUTHOR}" />
<meta name="theme-color" content="#15151f" />
<meta property="og:type" content="{og_type}" />
<meta property="og:site_name" content="Palimpsests" />
<meta property="og:title" content="{esc_title}" />
<meta property="og:description" content="{esc_desc}" />
<meta property="og:url" content="{SITE}{path}" />
<meta property="og:locale" content="en" />
<meta property="og:image" content="{OG_IMAGE}" />
<meta property="og:image:width" content="1200" />
<meta property="og:image:height" content="630" />
<meta property="og:image:alt" content="{html.escape(OG_IMAGE_ALT)}" />
{extra}<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:image" content="{OG_IMAGE}" />
<meta name="twitter:title" content="{esc_title}" />
<meta name="twitter:description" content="{esc_desc}" />
<link rel="icon" href="/favicon.ico" sizes="32x32" />
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
<link rel="apple-touch-icon" href="/apple-touch-icon.png" />
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
<a class="skip" href="#main">Skip to content</a>

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

<main class="doc" id="main">
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
      <a href="/runbook/">Runbook</a>
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


def note_page(note: Note, by_slug: dict[str, Note] | None = None) -> str:
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
            "image": OG_IMAGE,
            "author": AUTHOR_LD,
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
    iso = note.published.isoformat()
    body = f"""<p class="crumbs"><a href="/">Palimpsests</a> / <a href="/notes/">Notes</a></p>
<article>
<span class="eyebrow">Note · <time datetime="{iso}">{human_date(note.published)}</time> · {AUTHOR}</span>
<h1 class="display">{html.escape(note.title)}</h1>
{render(note.body)}
</article>
{read_next(note, by_slug or {})}<div class="related">
  <a class="btn" href="/notes/">All notes →</a>
  <a class="btn" href="/">Palimpsests →</a>
</div>"""
    meta = (f'<meta property="article:published_time" content="{iso}" />\n'
            f'<meta property="article:author" content="{AUTHOR}" />')
    return page(path, note.seo_title or f"{note.title} — Palimpsests notes",
                note.seo_description or note.description, graph, body, extra_meta=meta)


def read_next(note: Note, by_slug: dict[str, Note]) -> str:
    """Where a reader of this note goes next: the product page it belongs
    to and the notes nearest to it. Named in the note's front matter
    (`page`, `related`), so the essay itself is not rewritten to carry links."""
    items = []
    if note.page:
        items.append(f'  <li><a href="{note.page}">{html.escape(PRODUCT_PAGES[note.page])}</a>'
                     " — the page this note belongs to</li>")
    for slug in note.related:
        other = by_slug[slug]
        items.append(f'  <li><a href="/notes/{slug}/">{html.escape(other.title)}</a></li>')
    if not items:
        return ""
    return ('<div class="readmore">\n<h2 id="read-next">Read next</h2>\n<ul>\n'
            + "\n".join(items) + "\n</ul>\n</div>\n")


def index_page(notes: list[Note]) -> str:
    entries = "\n".join(
        f"""<h2 id="{n.slug}"><a href="/notes/{n.slug}/">{html.escape(n.title)}</a></h2>
<p class="crumbs"><time datetime="{n.published.isoformat()}">{human_date(n.published)}</time></p>
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
    return page("/notes/", "Notes — Palimpsests (PALA-1)", description, graph, body,
                og_type="website")


def _group_title(key: str) -> str:
    return dict(RUNBOOK_GROUPS)[key]


def recipe_page(recipe: Recipe, recipes: list[Recipe]) -> str:
    path = f"/runbook/{recipe.slug}/"
    by_slug = {r.slug: r for r in recipes}
    graph = [
        {
            "@type": "TechArticle",
            "@id": recipe.url + "#article",
            "headline": recipe.title,
            "description": recipe.description,
            "url": recipe.url,
            "mainEntityOfPage": recipe.url,
            "datePublished": recipe.updated.isoformat(),
            "dateModified": recipe.updated.isoformat(),
            "inLanguage": "en",
            "proficiencyLevel": "Beginner",
            "image": OG_IMAGE,
            "author": AUTHOR_LD,
            "publisher": {"@id": SITE + "/#org"},
            "isPartOf": {"@id": SITE + "/runbook/#runbook"},
        },
        {
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "Palimpsests", "item": SITE + "/"},
                {"@type": "ListItem", "position": 2, "name": "Runbook", "item": SITE + "/runbook/"},
                {"@type": "ListItem", "position": 3, "name": recipe.title, "item": recipe.url},
            ],
        },
    ]
    following = ""
    if recipe.next:
        items = "\n".join(
            f'  <li><a href="/runbook/{s}/">{html.escape(by_slug[s].title)}</a> — '
            f"{html.escape(by_slug[s].description)}</li>"
            for s in recipe.next
        )
        following = f'<h2 id="next">Next</h2>\n<ul>\n{items}\n</ul>\n'
    body = f"""<p class="crumbs"><a href="/">Palimpsests</a> / <a href="/runbook/">Runbook</a></p>
<span class="eyebrow">Runbook · {html.escape(_group_title(recipe.group))} · updated <time datetime="{recipe.updated.isoformat()}">{human_date(recipe.updated)}</time></span>
<h1 class="display">{html.escape(recipe.title)}</h1>
<p class="lede">{html.escape(recipe.description)}</p>
{render(recipe.body)}
{following}<div class="related">
  <a class="btn" href="/runbook/">All runbook pages →</a>
  <a class="btn" href="/">Palimpsests →</a>
</div>"""
    return page(path, recipe.seo_title or f"{recipe.title} — Palimpsests runbook",
                recipe.seo_description or recipe.description, graph, body)


def runbook_page(intro: RunbookIntro, recipes: list[Recipe]) -> str:
    sections = []
    for key, heading in RUNBOOK_GROUPS:
        members = [r for r in recipes if r.group == key]
        if not members:
            continue
        entries = "\n".join(
            f"""<h3><a href="/runbook/{r.slug}/">{html.escape(r.title)}</a></h3>
<p>{html.escape(r.description)}</p>"""
            for r in members
        )
        sections.append(f'<h2 id="{key}">{html.escape(heading)}</h2>\n{entries}')
    graph = [
        {
            "@type": "CollectionPage",
            "@id": SITE + "/runbook/#runbook",
            "name": intro.title,
            "description": intro.description,
            "url": SITE + "/runbook/",
            "inLanguage": "en",
            "dateModified": intro.updated.isoformat(),
            "publisher": {"@id": SITE + "/#org"},
            "hasPart": [
                {"@type": "TechArticle", "headline": r.title, "url": r.url}
                for r in recipes
            ],
        },
        {
            "@type": "BreadcrumbList",
            "itemListElement": [
                {"@type": "ListItem", "position": 1, "name": "Palimpsests", "item": SITE + "/"},
                {"@type": "ListItem", "position": 2, "name": "Runbook", "item": SITE + "/runbook/"},
            ],
        },
    ]
    body = f"""<p class="crumbs"><a href="/">Palimpsests</a> / Runbook</p>
<span class="eyebrow">Runbook · updated {human_date(intro.updated)}</span>
<h1 class="display">{html.escape(intro.title)}</h1>
<p class="lede">{html.escape(intro.description)}</p>
{render(intro.body)}
{chr(10).join(sections)}
<div class="related">
  <a class="btn" href="/integrations/">Integrations →</a>
  <a class="btn" href="/">Palimpsests →</a>
</div>"""
    return page("/runbook/", intro.seo_title or f"{intro.title} — Palimpsests",
                intro.seo_description or intro.description, graph, body, og_type="website")


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


def sitemap(notes: list[Note], intro: RunbookIntro | None = None,
            recipes: list[Recipe] | None = None) -> str:
    rows = list(STATIC_PAGES)
    if intro is not None and recipes:
        newest = max([intro.updated, *(r.updated for r in recipes)])
        rows.append(("/runbook/", newest.isoformat(), "weekly", "0.8"))
        rows += [(f"/runbook/{r.slug}/", r.updated.isoformat(), "monthly", "0.7")
                 for r in recipes]
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


def home_block(notes: list[Note]) -> str:
    """The newest notes, as cards for the home page."""
    cards = "\n".join(
        f"""    <div class="prov__item" data-reveal>
      <h3><a href="/notes/{n.slug}/">{html.escape(n.title)}</a></h3>
      <p>{html.escape(n.description)}</p>
    </div>"""
        for n in notes[:HOME_LATEST]
    )
    return f"{HOME_START}\n  <div class=\"prov\">\n{cards}\n  </div>\n  {HOME_END}"


def replace_block(path: Path, start_marker: str, end_marker: str, block: str) -> None:
    text = path.read_text(encoding="utf-8")
    start, end = text.find(start_marker), text.find(end_marker)
    if start < 0 or end < start:
        raise ValueError(f"{path} needs the {start_marker} / {end_marker} markers")
    path.write_text(text[:start] + block + text[end + len(end_marker):], encoding="utf-8",
                    newline="\n")


def llms_block(notes: list[Note]) -> str:
    lines = [f"- [{n.title}]({n.url}): {n.description}" for n in notes]
    head = (f"All [notes]({SITE}/notes/), newest first; the same list as an "
            f"[RSS feed]({SITE}/notes/feed.xml).")
    return "\n".join([LLMS_START, "## Notes", "", head, "", *lines, LLMS_END])


def llms_runbook_block(recipes: list[Recipe]) -> str:
    lines = [f"- [{r.title}]({r.url}): {r.description}" for r in recipes]
    head = (f"The [runbook]({SITE}/runbook/): one task per page, in steps, each with "
            "what it does not do.")
    return "\n".join([RUNBOOK_START, "## Runbook", "", head, "", *lines, RUNBOOK_END])


def not_found_page() -> str:
    """What the host serves for a path that is not a page."""
    pages = "\n".join(f'  <li><a href="{href}">{html.escape(name)}</a></li>'
                      for href, name in PRODUCT_PAGES.items())
    body = f"""<p class="crumbs"><a href="/">Palimpsests</a> / Not found</p>
<span class="eyebrow">404</span>
<h1 class="display">This page is not here</h1>
<p class="lede">The address may be mistyped, or the page may have moved. Nothing on this site is behind a login, so everything is reachable from the pages below.</p>
<h2 id="pages">Pages</h2>
<ul>
  <li><a href="/">Palimpsests</a> — what it is and how to install it</li>
{pages}
  <li><a href="/runbook/">Runbook</a> — one task per page, in steps</li>
  <li><a href="/notes/">Notes</a> — essays on audit logs, AI agents and the EU AI Act</li>
</ul>
<div class="related">
  <a class="btn" href="/">Palimpsests →</a>
  <a class="btn" href="{REPO}" rel="noopener">GitHub ↗</a>
</div>"""
    return page("/404.html", "Page not found — Palimpsests",
                "This page is not on palimpsests.dev. Links to the pages that are.",
                [], body, og_type="website", index=False)


def read_more_block(page_path: str, notes: list[Note]) -> str:
    """The notes that belong to a product page, for the end of that page."""
    mine = [n for n in notes if n.page == page_path]
    items = "\n".join(
        f'          <li><a href="/notes/{n.slug}/">{html.escape(n.title)}</a> — '
        f"{html.escape(n.seo_description or n.description)}</li>" for n in mine)
    return (f'{READMORE_START}\n      <div class="readmore">\n        <h2 id="read-more">Read more</h2>\n'
            f"        <ul>\n{items}\n        </ul>\n      </div>\n      {READMORE_END}")


_RELEASE = re.compile(r"^## \[(\d+\.\d+\.\d+)\] — (\d{4}-\d{2}-\d{2})$", re.M)


def latest_release(changelog: Path) -> tuple[str, str] | None:
    """The newest released version and its date, as the changelog states them."""
    if not changelog.is_file():
        return None
    found = _RELEASE.search(changelog.read_text(encoding="utf-8"))
    return (found.group(1), found.group(2)) if found else None


def stamp_release(home: Path, release: tuple[str, str]) -> None:
    """Write the released version and its date into the home page's
    structured data. The release writes them, not a hand: the changelog
    gains its section in the release pull request, this build is run, and
    the test that the committed site matches a fresh build fails until it is."""
    text = home.read_text(encoding="utf-8")
    version, when = release
    text, a = re.subn(r'"softwareVersion": "[^"]*"', f'"softwareVersion": "{version}"', text)
    text, b = re.subn(r'("softwareVersion": "[^"]*",\n\s*"datePublished": "[^"]*",\n\s*'
                      r'"dateModified": )"[^"]*"', rf'\g<1>"{when}"', text)
    if a != 1 or b != 1:
        raise ValueError(f"{home}: softwareVersion / dateModified not found once in the "
                         "home page's structured data")
    home.write_text(text, encoding="utf-8", newline="\n")


# ---------------------------------------------------------------- build

def build(notes_dir: Path, site_dir: Path, runbook_dir: Path | None = None) -> None:
    notes = load_notes(notes_dir)
    intro, recipes = load_runbook(runbook_dir or notes_dir.parent / "runbook")
    sources = {f"notes/{n.slug}": n.body for n in notes}
    sources |= {f"runbook/{r.slug}": r.body for r in recipes}
    if intro is not None:
        sources["runbook/index"] = intro.body
    check_site_links(sources, site_paths(notes, recipes))

    if intro is not None and recipes:
        book = site_dir / "runbook"
        book.mkdir(parents=True, exist_ok=True)
        for r in recipes:
            (book / r.slug).mkdir(exist_ok=True)
            (book / r.slug / "index.html").write_text(
                recipe_page(r, recipes), encoding="utf-8", newline="\n")
        (book / "index.html").write_text(
            runbook_page(intro, recipes), encoding="utf-8", newline="\n")
        replace_block(site_dir / "llms.txt", RUNBOOK_START, RUNBOOK_END,
                      llms_runbook_block(recipes))

    out = site_dir / "notes"
    out.mkdir(parents=True, exist_ok=True)
    by_slug = {n.slug: n for n in notes}
    for n in notes:
        if n.page and n.page not in PRODUCT_PAGES:
            raise ValueError(f"notes/{n.slug}: page {n.page!r} is not a product page")
        for slug in n.related:
            if slug not in by_slug or slug == n.slug:
                raise ValueError(f"notes/{n.slug}: related {slug!r} is not another note")
        (out / n.slug).mkdir(exist_ok=True)
        (out / n.slug / "index.html").write_text(note_page(n, by_slug), encoding="utf-8",
                                                 newline="\n")
    (out / "index.html").write_text(index_page(notes), encoding="utf-8", newline="\n")
    (out / "feed.xml").write_text(feed(notes), encoding="utf-8", newline="\n")
    (site_dir / "sitemap.xml").write_text(sitemap(notes, intro, recipes), encoding="utf-8",
                                          newline="\n")

    replace_block(site_dir / "llms.txt", LLMS_START, LLMS_END, llms_block(notes))
    replace_block(site_dir / "index.html", HOME_START, HOME_END, home_block(notes))
    (site_dir / "404.html").write_text(not_found_page(), encoding="utf-8", newline="\n")
    for page_path in PRODUCT_PAGES:
        target = site_dir / page_path.strip("/") / "index.html"
        if target.is_file() and READMORE_START in target.read_text(encoding="utf-8"):
            replace_block(target, READMORE_START, READMORE_END,
                          read_more_block(page_path, notes))
    release = latest_release(notes_dir.parent / "CHANGELOG.md")
    if release is not None:
        stamp_release(site_dir / "index.html", release)


if __name__ == "__main__":
    root = Path(__file__).resolve().parents[1]
    build(root / "notes", root / "site")
