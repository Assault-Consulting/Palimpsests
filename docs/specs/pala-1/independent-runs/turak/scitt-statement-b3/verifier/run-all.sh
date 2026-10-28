#!/bin/sh
# Bridge run B3 -- reproduce the whole run from a checkout of this repository.
#
#   sh run-all.sh [path-to-repo-root]
#
# Writes ../output/full-run.log and ../output/results.json.
# Exit status is the verifier's: 0 iff every check passed.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
# Resolve the repo root to an absolute path before changing directory, so a
# relative argument is read against the caller's cwd and the default against
# this script's own location.
if [ -n "$1" ]; then
  ROOT="$(cd "$1" && pwd)"
else
  ROOT="$(cd "$HERE/../../../../../../.." && pwd)"
fi
OUT="$HERE/../output"
mkdir -p "$OUT"

cd "$HERE"
echo "repo root: $ROOT"

echo "--- module self-tests ---"
python ed25519.py
python merkle.py

echo "--- full run ---"
python scitt_verify_v3.py \
  "$ROOT/docs/interop/scitt-statement-vector-v3.json" \
  "$ROOT/docs/interop/scitt-statement-vector.json" \
  "$ROOT/docs/specs/pala-1/test-vectors.json" \
  "$ROOT/docs/specs/pala-1/consistency-vectors.json" \
  "$ROOT/docs/specs/pala-1/profiles/inference-vectors.json" \
  "$OUT/results.json" 2>&1 | tee "$OUT/full-run.log"
