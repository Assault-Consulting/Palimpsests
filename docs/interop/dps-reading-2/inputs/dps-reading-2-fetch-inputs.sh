#!/bin/sh
# DPS reading 2 - the anchoring checkpoint and an OpenTimestamps replay, from the text.
# Downloads exactly the allowed inputs at pinned commits and checks their SHA-256,
# then tries the two time-anchor drafts and the RFCs the anchoring text cites (digests recorded).
# Usage: sh dps-reading-2-fetch-inputs.sh [output-dir]   (default: inputs)
set -eu
OUT=${1:-inputs}
DPS=https://raw.githubusercontent.com/decision-provenance-standard/standard/007f8c99ec910564bac1c508b76c8ce8391fa11e
LL=https://raw.githubusercontent.com/Laurent-Lemonnier/dps-scitt-decision-layer/549b50afb146c172d92177063b4e3d3d3e17beab
if command -v sha256sum >/dev/null 2>&1; then CHECK="sha256sum -c --quiet -"; SUM="sha256sum"; else CHECK="shasum -a 256 -c --quiet -"; SUM="shasum -a 256"; fi
fetch() { base=$1; dir=$2; sums=$3
  printf '%s\n' "$sums" | while read -r h p; do
    mkdir -p "$OUT/$dir/$(dirname "$p")"
    curl -fsSL "$base/$p" -o "$OUT/$dir/$p"
  done
  (cd "$OUT/$dir" && printf '%s\n' "$sums" | $CHECK) || { echo "SHA-256 MISMATCH in $dir: stop, do not proceed" >&2; exit 1; }
  printf '%s\n' "$sums" > "$OUT/$dir/SHA256SUMS"
  echo "ok: $dir, $(printf '%s\n' "$sums" | wc -l | tr -d ' ') files verified"
}
fetch "$DPS" standard "$(cat <<'SUMS'
38b397e9b34044ceb6ab57eaeec6a888c190d2027dc9f7b2b7d6b863f400ef66  extensions/README.md
26bf41ffc3f233d24e87caa6bb6929f64c4e335060ab1ccbbc4f77aad2f0f197  extensions/anchoring/README.md
07b7c14aca8b2647367f70c0a3bb61888bb2bdb0795f23d035bf01b5c707b8b7  extensions/anchoring/schemas/anchoring-attachment.schema.json
f5c6beb72385af318d0e6775e7050cfe5d0631864ebae71e4726483188c1a6f8  extensions/anchoring/schemas/checkpoint.schema.json
5d6d148da4d4dc94bb33f550911ae9b89ecdf25be66cb416c0690886b5ce2b8d  extensions/anchoring/schemas/trust-policy.schema.json
2ac6afe710db3df66639d25ffc04743cd4091e7eeec75df7a56bf936a14f09a6  extensions/anchoring/schemas/verification-report.schema.json
06d9119a5b427f5f94a10cc9339f2f1051ece8ae9d09d098d1a59936c8b130e5  extensions/anchoring/tests/cases.json
ce41f52b5b8649f4a6921085218dbd7e654b057100e0f885d89fa08a770023fa  extensions/anchoring/tests/vectors.json
20b3f8f5b8dd327708ce65e9f52144750c890429aeb61e2efbbf623f49fa71a9  extensions/portable-verification/README.md
7e7d67620e95b8cd948c1dcf05361076418ea6009d92b5662cf35203d1c5dc8a  extensions/portable-verification/schemas/verification-export.schema.json
1c77f305d68923eef7d8bc7846597785a4256fad323c6be8ed979805078bd650  extensions/portable-verification/schemas/verification-report.schema.json
39139ad3c159d09c756c0f9410cd1ed4804ebaa316ab0378561e53ee854d554f  extensions/signatures/README.md
5fc61584e9296a34fd2047588d733499b231622d02fd34c0ad33a32e5e22c3ad  extensions/signatures/schemas/signatures-attachment.schema.json
c76b4ba43ddc1bd6628db5ea708be147c8a4cd7c6e8d0731a44deacdc44b0088  extensions/signatures/schemas/verification-report.schema.json
SUMS
)"
fetch "$LL" lemonnier "$(cat <<'SUMS'
4dd65643f3cf9228a0a976193fde147cd40b881219112fc10e8df6699f56240e  interop/umarise/headers-957289-957300.json
b8e5ffa1c8ef269bfced44d8e29909ceca1bde372f908b4c8c83d1f9bcd5d6d4  interop/umarise/headers-sources.json
2c1ec4cbe4779d8d598b0f9b951d8d2b351b85ab1d9ad4fe0f897f0b8dd7fd97  interop/umarise/vectors/vector1.ots
a183f624efbbda7d6208b9b5a6f9b0c2c95d90382eb209c44a1131954071f30b  interop/umarise/vectors/vector1.txt
dc630f6039890b988b2de9c51cf5b93915a24488ab69f05b3d3ed4957febb900  interop/umarise/vectors/vector2.ots
0df073a986e5e5141c96ec32303b8552ded255e4404d0aff996936a846b48cff  interop/umarise/vectors/vector2.txt
4e2a3ce0758ab8bef4b1e8311dea6e987b23a718d6eb40b6ed9f239e8cfe1f73  interop/umarise/vectors/vector3.ots
d82bf84f17057c0e3d7aa6f249dfc2e80a877b910ce4ce14dc40e653fd5be40b  interop/umarise/vectors/vector3.txt
4905b48a6d26ed43a12e92c6a75930b2d36ace7889a5937c61de45f6753b450d  interop/umarise/vectors/vector4.ots
94a86d117047f2af9a2f5635d0c530cc85fc23d20f5d4b42926b94abee7a06ec  interop/umarise/vectors/vector4.txt
SUMS
)"
# Texts pinned by name and revision; their digests are recorded, not checked.
try() { dir=$1; url=$2; f=$(basename "$url"); mkdir -p "$OUT/$dir"
  if curl -fsSL "$url" -o "$OUT/$dir/$f"; then (cd "$OUT/$dir" && $SUM "$f" >> SHA256SUMS); echo "ok: $dir/$f"
  else rm -f "$OUT/$dir/$f"; echo "not fetched: $dir/$f (download it by hand, or record that it was applied from knowledge)" >&2; fi; }
for rev in 08 03; do try ietf "https://www.ietf.org/archive/id/draft-fassbender-scitt-time-anchor-$rev.txt"; done
for n in 3161 5280 5652 5816 6979 8017 8032 8259 8392 8785 9052 9162 9500 9597 9864 9942 9943; do try rfc "https://www.rfc-editor.org/rfc/rfc$n.txt"; done
