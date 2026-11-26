# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0

"""The /notes/ section is generated from notes/*.md; the committed site must match a fresh build."""
from __future__ import annotations

import filecmp
import importlib.util
import pytest
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "build_notes", ROOT / "scripts" / "build_notes.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(module)
    return module


def test_committed_site_matches_a_fresh_build(tmp_path):
    build = _load()
    site = tmp_path / "site"
    shutil.copytree(ROOT / "site", site)
    build.build(ROOT / "notes", site)
    for path in sorted(site.rglob("*")):
        if path.is_file():
            committed = ROOT / "site" / path.relative_to(site)
            assert committed.exists(), f"{committed} is generated but not committed"
            assert filecmp.cmp(path, committed, shallow=False), (
                f"{committed} is stale: run python3 scripts/build_notes.py"
            )


def test_inline_markup_escapes_html_and_leaves_code_spans_alone():
    build = _load()
    out = build.inline("a <b> & `x **y** <z>` and **bold** [l](https://e.x/?a=1&b=2)")
    assert "a &lt;b&gt; &amp;" in out
    assert "<code>x **y** &lt;z&gt;</code>" in out
    assert "<b>bold</b>" in out
    assert '<a href="https://e.x/?a=1&amp;b=2">l</a>' in out


def test_render_rejects_what_the_dialect_does_not_have():
    build = _load()
    with pytest.raises(ValueError):
        build.render("# a top-level heading")
    with pytest.raises(ValueError):
        build.render("```\nunclosed")


def test_a_link_to_a_page_this_site_does_not_have_stops_the_build():
    build = _load()
    known = {"/", "/runbook/", "/runbook/a/", "/air-gapped/"}
    build.check_site_links(
        {"ok": "[a](https://palimpsests.dev/runbook/a/) [b](https://palimpsests.dev/air-gapped/#anchors)"
               " [c](https://palimpsests.dev/) [d](https://example.org/nope/)"},
        known,
    )
    with pytest.raises(ValueError, match="runbook/b/"):
        build.check_site_links({"bad": "[x](https://palimpsests.dev/runbook/b/)"}, known)


def _recipe(slug: str, nxt: str = "") -> str:
    return (f"---\ntitle: {slug}\nslug: {slug}\ngroup: run\norder: 1\nupdated: 2026-11-16\n"
            f"description: d\nnext: {nxt}\n---\n\nbody\n")


def test_runbook_next_must_name_another_runbook_page(tmp_path):
    build = _load()
    (tmp_path / "index.md").write_text(
        "---\ntitle: t\nupdated: 2026-11-16\ndescription: d\n---\n\nbody\n", encoding="utf-8")
    (tmp_path / "a.md").write_text(_recipe("a", "b"), encoding="utf-8")
    (tmp_path / "b.md").write_text(_recipe("b", "a"), encoding="utf-8")
    intro, recipes = build.load_runbook(tmp_path)
    assert intro is not None and [r.slug for r in recipes] == ["a", "b"]
    (tmp_path / "b.md").write_text(_recipe("b", "missing"), encoding="utf-8")
    with pytest.raises(ValueError, match="missing"):
        build.load_runbook(tmp_path)
    (tmp_path / "b.md").write_text(_recipe("b", "b"), encoding="utf-8")
    with pytest.raises(ValueError, match="'next' names no other runbook page"):
        build.load_runbook(tmp_path)


def test_every_runbook_page_is_listed_and_in_the_sitemap():
    build = _load()
    _, recipes = build.load_runbook(ROOT / "runbook")
    assert recipes, "the runbook has pages"
    listing = (ROOT / "site" / "runbook" / "index.html").read_text(encoding="utf-8")
    sitemap = (ROOT / "site" / "sitemap.xml").read_text(encoding="utf-8")
    for r in recipes:
        assert f'href="/runbook/{r.slug}/"' in listing
        assert f"<loc>{r.url}</loc>" in sitemap


# -- what a search result, a link preview and an assistant see ------------------

def _pages():
    return sorted((ROOT / "site").rglob("*.html"))


def test_no_head_is_longer_than_a_search_result_shows():
    """A title is cut near 60 characters and a description near 155. A page
    whose own title is longer gives a shorter one for its head."""
    import html
    import re

    build = _load()
    for path in _pages():
        text = path.read_text(encoding="utf-8")
        title = html.unescape(re.search(r"<title>(.*?)</title>", text, re.S).group(1))
        description = html.unescape(
            re.search(r'<meta name="description" content="(.*?)" />', text, re.S).group(1))
        assert len(title) <= build.TITLE_MAX, (path, len(title), title)
        assert len(description) <= build.DESCRIPTION_MAX, (path, len(description))
        assert text.count("<h1") == 1, path


def test_the_build_stops_on_a_head_that_is_too_long():
    build = _load()
    with pytest.raises(ValueError, match="seo_title"):
        build.page("/x/", "t" * 61, "d", [], "")
    with pytest.raises(ValueError, match="seo_description"):
        build.page("/x/", "t", "d" * 156, [], "")


def test_every_page_carries_valid_structured_data_a_preview_image_and_the_menu():
    import json
    import re

    for path in _pages():
        text = path.read_text(encoding="utf-8")
        blocks = re.findall(r'<script type="application/ld\+json">\n(.*?)\n</script>',
                            text, re.S)
        assert len(blocks) == 1, path
        graph = json.loads(blocks[0])["@graph"]
        assert all("@type" in node for node in graph), path
        types = [node["@type"] for node in graph]
        assert types.count("FAQPage") <= 1, path  # one per page, or readers take neither
        assert '<meta property="og:image" content="https://palimpsests.dev/og.png" />' in text
        assert '<meta name="twitter:card" content="summary_large_image" />' in text
        assert '<link rel="apple-touch-icon" href="/apple-touch-icon.png" />' in text
        assert '<a class="hide-sm" href="/notes/">Notes</a>' in text, path
        assert text.count("<main") == 1 and 'id="main"' in text, path
        assert '<a class="skip" href="#main">' in text, path
    for name in ("og.png", "apple-touch-icon.png", "favicon.ico", "favicon.svg"):
        assert (ROOT / "site" / name).stat().st_size > 0


def test_the_questions_a_page_marks_up_are_the_questions_it_shows():
    """Structured data that says what the page does not is worse than none."""
    import html
    import json
    import re

    seen = 0
    for path in _pages():
        text = path.read_text(encoding="utf-8")
        graph = json.loads(re.search(
            r'<script type="application/ld\+json">\n(.*?)\n</script>', text, re.S).group(1))
        visible = html.unescape(re.sub(r"<[^>]+>", " ", text.split("</head>", 1)[1]))
        visible = re.sub(r"\s+", " ", visible)
        for node in graph["@graph"]:
            if node["@type"] != "FAQPage":
                continue
            seen += 1
            for q in node["mainEntity"]:
                assert q["name"] in visible, (path, q["name"])
                assert q["acceptedAnswer"]["text"][:60] in visible, (path, q["name"])
    assert seen >= 6


def test_headings_do_not_skip_a_level():
    import re

    for path in _pages():
        levels = [int(n) for n in re.findall(r"<h([1-6])[\s>]", path.read_text(encoding="utf-8"))]
        for before, after in zip(levels, levels[1:], strict=False):
            assert after <= before + 1, (path, before, after)


def test_a_note_names_where_to_read_next_and_its_page_lists_it():
    build = _load()
    notes = build.load_notes(ROOT / "notes")
    by_slug = {n.slug: n for n in notes}
    for n in notes:
        assert n.related, n.slug
        text = (ROOT / "site" / "notes" / n.slug / "index.html").read_text(encoding="utf-8")
        assert '<h2 id="read-next">Read next</h2>' in text
        for slug in n.related:
            assert slug in by_slug and f'href="/notes/{slug}/"' in text
        if n.page:
            page = (ROOT / "site" / n.page.strip("/") / "index.html").read_text(encoding="utf-8")
            assert f'href="/notes/{n.slug}/"' in page.split("read-more:start")[1].split(
                "read-more:end")[0], (n.slug, n.page)
            assert f'href="{n.page}"' in text


def test_the_home_page_states_the_release_the_changelog_states():
    import json
    import re

    build = _load()
    version, when = build.latest_release(ROOT / "CHANGELOG.md")
    text = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    graph = json.loads(re.search(
        r'<script type="application/ld\+json">\n(.*?)\n</script>', text, re.S).group(1))
    software = next(n for n in graph["@graph"] if n["@type"] == "SoftwareApplication")
    assert (software["softwareVersion"], software["dateModified"]) == (version, when)


def test_the_site_answers_for_robots_security_and_a_missing_page():
    site = ROOT / "site"
    robots = (site / "robots.txt").read_text(encoding="utf-8")
    for agent in ("Claude-SearchBot", "Claude-User", "ClaudeBot", "OAI-SearchBot", "GPTBot",
                  "PerplexityBot", "Googlebot", "Bingbot"):
        assert f"User-agent: {agent}\nAllow: /" in robots
    assert "Disallow" not in robots and "your-domain" not in robots
    assert robots.rstrip().endswith("Sitemap: https://palimpsests.dev/sitemap.xml")
    security = (site / ".well-known" / "security.txt").read_text(encoding="utf-8")
    assert "Contact: mailto:as@assault.consulting" in security and "Expires: 20" in security
    contact = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    assert "as@assault.consulting" in contact and "security/advisories/new" in contact
    missing = (site / "404.html").read_text(encoding="utf-8")
    assert '<meta name="robots" content="noindex" />' in missing and "canonical" not in missing
    assert "/404.html" not in (site / "sitemap.xml").read_text(encoding="utf-8")
    manifest = (site / "site.webmanifest").read_text(encoding="utf-8")
    assert "audit log for AI agents" in manifest and "/apple-touch-icon.png" in manifest


def test_visible_update_date_of_a_product_page_is_its_sitemap_date() -> None:
    """A page that says "Updated <date>" says the date the sitemap gives it.

    Both are written by hand when a page changes; this holds them together.
    """
    import re

    site = ROOT / "site"
    module = _load()
    checked = 0
    for path, lastmod, *_ in module.STATIC_PAGES:
        if path == "/":
            continue
        page = (site / path.strip("/") / "index.html").read_text(encoding="utf-8")
        shown = re.findall(r'Updated <time datetime="(\d{4}-\d{2}-\d{2})">', page)
        assert shown == [lastmod], (path, shown, lastmod)
        checked += 1
    assert checked == 5


# --- one footer, pages in markdown, the mapping on the site ---------------


def _site_pages() -> list:
    site = ROOT / "site"
    return [*sorted(site.rglob("index.html")), site / "404.html"]


def test_every_page_of_the_site_has_the_same_footer() -> None:
    import re

    module = _load()
    for path in _site_pages():
        found = re.findall(r"<footer>.*?</footer>", path.read_text(encoding="utf-8"), re.S)
        assert found == [module.FOOTER], path
    for label in ("Notes", "Runbook", "GitHub", "PyPI", "Internet-Draft", "Security headers"):
        assert f">{label}</a>" in module.FOOTER, label


def test_the_mapping_on_the_site_is_the_document_in_the_repository() -> None:
    import html
    import re

    module = _load()
    source = (ROOT / module.MAPPING_SOURCE).read_text(encoding="utf-8")
    blocks, rows = module.parse_mapping(source)
    shipped, total = module.mapping_counts(source)
    assert (shipped, total) == (sum(r.shipped for r in rows), len(rows))
    assert total >= 27 and 0 < shipped <= total

    page = (ROOT / "site" / "eu-ai-act-article-12" / "index.html").read_text(encoding="utf-8")
    block = page.split(module.MAPPING_START, 1)[1].split(module.MAPPING_END, 1)[0]
    assert module.MAPPING_START + block + module.MAPPING_END == module.mapping_block(source)
    assert block.count("<tr><td>") == total
    assert f"{shipped} of {total} rows" in block
    for row in rows:
        assert module.inline(row.capability) in block, row.capability
    # Pull-request numbers stay in the repository document.
    assert not re.search(r"#\d", html.unescape(re.sub(r"<[^>]+>", " ", block)))
    # The sections that are not the Act's requirements stay there too.
    assert "Beyond the requirements" not in block and "Other frameworks" not in block


def test_the_row_count_is_quoted_the_same_everywhere() -> None:
    module = _load()
    source = (ROOT / module.MAPPING_SOURCE).read_text(encoding="utf-8")
    shipped, total = module.mapping_counts(source)
    quote = f"{shipped} of {total} rows"
    for name in ("index.html", "llms.txt", "eu-ai-act-article-12/index.html"):
        assert quote in (ROOT / "site" / name).read_text(encoding="utf-8"), name


def test_a_mapping_status_the_site_cannot_show_is_refused() -> None:
    module = _load()
    assert module.MappingRow("s", "c", "m", "Shipped (v0.12)").status_label == "Shipped in 0.12"
    assert module.MappingRow("s", "c", "m", "Planned (post-0.8)").status_label == "Planned"
    for bad in ("Shipped (main)", "Shipped", "Done"):
        with pytest.raises(ValueError):
            _ = module.MappingRow("s", "c", "m", bad).status_label


def test_pages_written_in_markdown_are_built_listed_and_dated() -> None:
    import json
    import re

    module = _load()
    docs = module.load_doc_pages(ROOT / "pages")
    assert [d.slug for d in docs] == ["ai-agent-audit-trail"]
    sitemap = (ROOT / "site" / "sitemap.xml").read_text(encoding="utf-8")
    llms = (ROOT / "site" / "llms.txt").read_text(encoding="utf-8")
    for doc in docs:
        built = (ROOT / "site" / doc.slug / "index.html").read_text(encoding="utf-8")
        assert built == module.doc_page(doc, module.load_notes(ROOT / "notes"))
        assert f'Updated <time datetime="{doc.updated.isoformat()}">' in built
        assert f"<loc>{doc.url}</loc>" in sitemap and doc.url in llms
        found = re.search(r'<script type="application/ld\+json">\n(.*?)\n</script>', built, re.S)
        assert found is not None
        graph = json.loads(found.group(1))["@graph"]
        faq = [node for node in graph if node["@type"] == "FAQPage"]
        asked = re.findall(r"(?m)^### (.+)$", doc.body.split("## Questions", 1)[1])
        assert len(faq) == 1 and [q["name"] for q in faq[0]["mainEntity"]] == asked
        for question in faq[0]["mainEntity"]:
            answer = question["acceptedAnswer"]["text"]
            assert answer and "](" not in answer and "`" not in answer
        # a page of the site links to it, or nobody finds it
        link = f'href="{doc.path}"'
        linked_from = [p for p in _site_pages() if link in p.read_text(encoding="utf-8")]
        assert len(linked_from) >= 2, doc.path


def test_the_scorecard_figure_carries_its_date() -> None:
    import re

    home = (ROOT / "site" / "index.html").read_text(encoding="utf-8")
    llms = (ROOT / "site" / "llms.txt").read_text(encoding="utf-8")
    figure = re.findall(r"(\d\.\d) of 10 on (\d{1,2} \w+ \d{4})", re.sub(r"<[^>]+>", "", home))
    assert len(figure) == 1, "one dated figure on the home page, so there is one place to update"
    assert re.findall(r"(\d\.\d) of 10 on (\d{1,2} \w+ \d{4})", llms) == figure
    assert "scorecard.dev/viewer/?uri=github.com/Assault-Consulting/Palimpsests" in home
