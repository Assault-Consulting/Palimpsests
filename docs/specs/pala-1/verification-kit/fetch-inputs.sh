#!/bin/sh
# PALA-1 verification kit — assemble the sealed input package.
#
# Fetches ONLY the allowed inputs of one track of the kit, into a new
# folder, and verifies their SHA-256 digests. Do not clone the
# repository: it contains the reference implementation and earlier
# runs' verifiers, which a fresh run must not read.
#
# Usage:
#   sh fetch-inputs.sh            the core track     -> ./pala1-package/
#   sh fetch-inputs.sh core       the same
#   sh fetch-inputs.sh profile    the profile track  -> ./pala1-profile-r9-package/
#
# The core track is the frozen format, at its own tag (pala1-v1.0). That
# is not a release of the palimpsests package, and the profile documents
# it carries are the freeze-day copies.
#
# The profile track is the inference profile at revision r9, with its
# vectors and the core it rests on, at the tag of the first release that
# carries r9 (v0.15.0).
#
# PALA1_REF is for maintainers checking another ref against the pinned
# digests. Leave it unset for a run: any ref whose files differ fails
# the check below.

set -eu

TRACK="${1:-core}"

case "$TRACK" in
core)
    REF="${PALA1_REF:-pala1-v1.0}"
    OUT="pala1-package"
    # file  expected-sha256
    MANIFEST="
PALA-1.md b4ea536bec5d4a52cf1f2bbbd20ee8ea25b627bab41d7fa5da4012bd114381d5
profiles/robotics.md 20093ccd12075aef2062603b5282df83e70ce3a59944173d930183ca6e36fe56
profiles/inference.md 3ef8feb3017bd24ca117710c7983641ee5a3803272b6dea82937d60735449a0f
test-vectors.json 476c05ce8ef765c57b0b67bea8ac4ddf73a85d8e0435aac38b19831ae20a8193
"
    NEXT="read ${OUT}/PALA-1.md, then the kit README, section 2."
    ;;
profile)
    REF="${PALA1_REF:-v0.15.0}"
    OUT="pala1-profile-r9-package"
    MANIFEST="
PALA-1.md b4ea536bec5d4a52cf1f2bbbd20ee8ea25b627bab41d7fa5da4012bd114381d5
test-vectors.json 476c05ce8ef765c57b0b67bea8ac4ddf73a85d8e0435aac38b19831ae20a8193
profiles/inference.md 6c93362144065af796481af4a669fd6c5a6d2987924e9314dbb37a8764258186
profiles/inference-vectors.json 4fb17b23c4be5292240c4b99b3debfae31d31311cf0692380bc5b84d56442005
profiles/payload-digest-vectors.json 9cb9c337e3cc67a0b0c15fb13afa9e5e450ef21b61eba37e6c7e40154a3dc859
profiles/retention-continuation.md 73f88321939f9d52df70fd3448fafa6b4f844b1e19d01e7922c3f37750073fb9
"
    NEXT="read ${OUT}/profiles/inference.md, then PROFILE-R9.md in the kit."
    ;;
*)
    echo "usage: sh fetch-inputs.sh [core|profile]" >&2
    exit 2
    ;;
esac

BASE="https://raw.githubusercontent.com/Assault-Consulting/Palimpsests/${REF}/docs/specs/pala-1"

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
    echo "Digest mismatch: do not proceed. If PALA1_REF points at a ref"
    echo "other than the track's own tag, that is expected — the pinned"
    echo "digests are those of the tag."
    exit 1
fi

echo ""
echo "Sealed package ready in ./${OUT}/ — work from these files only."
echo "Next: ${NEXT}"
