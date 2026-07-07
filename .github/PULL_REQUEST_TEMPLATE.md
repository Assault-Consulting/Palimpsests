<!--
  Thanks for contributing. Keep this PR focused; small reviewable changes
  merge faster. See CONTRIBUTING.md for the ground rules.
-->

## What this changes

<!-- One or two sentences. Link the issue it closes, if any (e.g. Closes #12). -->

## Why

<!-- The problem this solves, or the capability it adds. -->

## Checklist

- [ ] Python code lands via this PR, not a direct push to `main`.
- [ ] Tests added or updated in the same PR for any behavioural change.
- [ ] `ruff check .` is clean (E/F/I/B/UP, line length 100, py311).
- [ ] CI is green on all three platforms (macOS / Linux / Windows).
- [ ] The change respects scope: **above the attention kernel**, library +
      CLI, no `isinstance` on engines (callers read `capabilities`).
- [ ] Docs/CHANGELOG updated if user-facing behaviour changed.

## Notes for reviewers

<!-- Anything non-obvious: a design trade-off, a follow-up left for later,
     a place you are unsure about. -->
