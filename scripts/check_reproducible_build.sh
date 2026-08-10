#!/usr/bin/env bash
# SPDX-FileCopyrightText: Assault Consulting
# SPDX-License-Identifier: Apache-2.0
#
# OpenSSF Gold build_reproducible gate: build the sdist and wheel twice and
# require bit-for-bit identical artifacts. A reproducible build is a pure
# function of the source tree; if two independent builds disagree, something
# non-reproducible (a wall-clock timestamp, a file ordering, an absolute
# path) has leaked into the output.
#
# SOURCE_DATE_EPOCH is pinned to the HEAD commit date, so any party who
# rebuilds from the same commit gets the same bytes regardless of when or
# where they build — and independent of the build backend's default epoch.
#
# Requires: python, `pip install build`, and a git checkout.
set -euo pipefail

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
export LC_ALL="${LC_ALL:-C.UTF-8}"
export TZ=UTC
umask 0022

echo "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} ($(date -u -d "@${SOURCE_DATE_EPOCH}" 2>/dev/null || echo '?'))"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

python -m build --outdir "${work}/a" . >/dev/null
python -m build --outdir "${work}/b" . >/dev/null

status=0
for artifact in "${work}"/a/*; do
    name="$(basename "${artifact}")"
    ha="$(sha256sum "${artifact}" | cut -d' ' -f1)"
    hb="$(sha256sum "${work}/b/${name}" | cut -d' ' -f1)"
    if [ "${ha}" = "${hb}" ]; then
        echo "reproducible      ${name}  ${ha}"
    else
        echo "NON-REPRODUCIBLE  ${name}"
        echo "  build A: ${ha}"
        echo "  build B: ${hb}"
        status=1
    fi
done

if [ "${status}" -ne 0 ]; then
    echo "build_reproducible gate FAILED"
    exit 1
fi
echo "build_reproducible gate passed (sdist + wheel bit-for-bit identical)"
