#!/bin/sh
# PALA-1 verification kit — assemble the sealed input package.
#
# Fetches ONLY the allowed inputs of the independent-verification
# protocol (spec + profiles + vectors) at the frozen v1.0 tag, into
# ./pala1-package/, and verifies their SHA-256 digests. Do not clone
# the repository: it contains the reference implementation and earlier
# runs' verifiers, which a fresh run must not read.
#
# Usage:  sh fetch-inputs.sh
# Override the ref (e.g. to a commit SHA):  PALA1_REF=<sha> sh fetch-inputs.sh

set -eu

REF="${PALA1_REF:-pala1-v1.0}"
BASE="https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/${REF}/docs/specs/pala-1"
OUT="pala1-package"

# file  expected-sha256
MANIFEST="
PALA-1.md b4ea536bec5d4a52cf1f2bbbd20ee8ea25b627bab41d7fa5da4012bd114381d5
profiles/robotics.md 20093ccd12075aef2062603b5282df83e70ce3a59944173d930183ca6e36fe56
profiles/inference.md 3ef8feb3017bd24ca117710c7983641ee5a3803272b6dea82937d60735449a0f
test-vectors.json 476c05ce8ef765c57b0b67bea8ac4ddf73a85d8e0435aac38b19831ae20a8193
"

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1   # macOS
    fi
}

mkdir -p "${OUT}/profiles"
fail=0

echo "$MANIFEST" | while read -r path want; do
    [ -n "$path" ] || continue
    echo "fetching ${path}"
    curl -fsSL "${BASE}/${path}" -o "${OUT}/${path}"
    got=$(sha256 "${OUT}/${path}")
    if [ "$got" = "$want" ]; then
        echo "  OK    ${got}"
    else
        echo "  MISMATCH for ${path}"
        echo "    expected ${want}"
        echo "    got      ${got}"
        exit 1
    fi
done || fail=1

if [ "$fail" -ne 0 ]; then
    echo ""
    echo "Digest mismatch: do not proceed. If PALA1_REF points at a"
    echo "ref other than the v1.0 freeze, that is expected — the pinned"
    echo "digests are the frozen ones."
    exit 1
fi

echo ""
echo "Sealed package ready in ./${OUT}/ — work from these files only."
echo "Next: read ${OUT}/PALA-1.md, then the kit README task section."
