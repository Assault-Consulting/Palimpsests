#!/bin/sh
# PALA-1 v1.0 independent verification run — full suite.
#
# Usage:  sh verifier/run-all.sh
# Expects ./pala1-package/ (built by the kit's fetch-inputs.sh) in the cwd.
set -eu

PKG="${PALA1_PKG:-pala1-package}"
VEC="${PKG}/test-vectors.json"
CONTAINER="chain.pala"

echo "PALA-1 v1.0 independent verification run"
echo "date: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "perl: $(perl -e 'print $^V')"
echo ""

echo "### 0. input package digests (must match the kit's pinned values)"
for f in PALA-1.md profiles/robotics.md profiles/inference.md test-vectors.json; do
    printf '  %s  %s\n' "$(sha256sum "${PKG}/${f}" | cut -d' ' -f1)" "$f"
done
echo ""

echo "### 1. build the section 2.4 container"
perl verifier/build-container.pl "$VEC" "$CONTAINER"
printf '  sha256(%s) = %s\n' "$CONTAINER" "$(sha256sum "$CONTAINER" | cut -d' ' -f1)"
echo ""

echo "### 2. section 8 expected results (the pass bar)"
perl verifier/run-suite.pl "$CONTAINER" "$VEC"

echo "### 3. section 8 mutation demos + independent adversarial cases"
perl verifier/demos.pl "$CONTAINER" "$VEC"

echo "### 4. section 7.5 / 4.4 body verification and decryption"
perl verifier/body-check.pl "$CONTAINER" "$VEC"

echo "### 5. section 8 narrative table vs. the bytes"
perl verifier/narrative-check.pl "$CONTAINER"

echo "ALL SUITES PASSED"
