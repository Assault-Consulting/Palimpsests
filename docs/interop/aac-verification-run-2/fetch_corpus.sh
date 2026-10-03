#!/usr/bin/env bash
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: CC0-1.0
# Fetch ONLY the files the run-2 boundary allows, one at a time, from the pinned commit,
# and verify them against the authors' SHA256SUMS. No clone, no archive, no tree browsing.
set -euo pipefail
PIN=13a1f4534c31369e927db73af6298e8b9ffdc36a
BASE=https://raw.githubusercontent.com/action-state-group/agent-action-capsule/$PIN
OUT=${1:-corpus}
mkdir -p "$OUT" && cd "$OUT"
get() { mkdir -p "$(dirname "$1")"; curl -sf "$BASE/$1" -o "$1"; }

for f in vectors/SHA256SUMS vectors/manifest.json vectors/README.md LICENSE; do get "$f"; done

# every path under capsule/ that vectors/SHA256SUMS lists (190 files at this pin)
grep '  capsule/' vectors/SHA256SUMS | awk '{print $2}' | while read -r p; do get "vectors/$p"; done
(cd vectors && grep -E '  (capsule/|README\.md$|manifest\.json$)' SHA256SUMS | sha256sum -c - | grep -c ': OK')

# provenance-mode-vectors/ lives at the repository root at this pin; it has its own SHA256SUMS
get provenance-mode-vectors/SHA256SUMS
awk '{print $2}' provenance-mode-vectors/SHA256SUMS | while read -r p; do get "provenance-mode-vectors/$p"; done
(cd provenance-mode-vectors && sha256sum -c SHA256SUMS | grep -c ': OK')
