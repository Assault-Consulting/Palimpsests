### Documentation

- **palimpsests.dev: one pass for search engines, link previews and
  assistants.** The menu no longer disappears on a phone; small text is at
  least 12.8 px and its contrast at least 4.5:1; every page has a `main`
  landmark, a skip link and headings that do not skip a level. Titles fit
  60 characters and descriptions 155, checked by the build. Product pages
  open with an answer, state when they were updated, carry three to five
  questions with matching structured data, and list the notes that belong
  to them; each note says what to read next. A link preview image, a
  favicon and a touch icon exist; `robots.txt` names the crawlers it means;
  there is a 404 page and a `security.txt`.
- The home page's structured data states the released version and its date,
  written from `CHANGELOG.md` by `scripts/build_notes.py` — a step in
  `RELEASING.md`, held by a test.
