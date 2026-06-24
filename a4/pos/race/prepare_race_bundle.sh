#!/usr/bin/env bash
# Track-A (race) clean bundler — git archive HEAD (committed code) + the HOLED binary.
#
# Why a Track-A copy instead of prepare_bundle.sh: that script's --allow-dirty OVERLAYS the
# whole dirty working tree, which sweeps in a4/builds/**/risc0-host (~600M of unneeded
# binaries) -> a 922M bundle. All race code is COMMITTED, so a pure `git archive HEAD`
# (committed tracked files only; untracked a4/builds binaries excluded) + the one holed
# binary is correct and ~130M. NO dirty overlay.
#
# Usage:  bash a4/pos/race/prepare_race_bundle.sh
#         HOLED=<path> OUT_DIR=<dir> bash a4/pos/race/prepare_race_bundle.sh
set -euo pipefail

HOLED="${HOLED:-a4/builds/ap_seamb/bench-verifyopcode/risc0-host}"
OUT_DIR="${OUT_DIR:-bundles}"
[ -x "$HOLED" ] || { echo "ERROR: holed binary missing/exec: $HOLED" >&2; exit 1; }

SHA="$(git rev-parse --short=12 HEAD)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/a4_campaign/bin" "$STAGE/a4_campaign/repo"

# committed tree only (no untracked a4/builds binaries, no frozen hosts)
git archive --format=tar HEAD | tar -x -C "$STAGE/a4_campaign/repo"
# the planted-bug binary the race targets
cp "$HOLED" "$STAGE/a4_campaign/bin/risc0-host"
chmod 0755 "$STAGE/a4_campaign/bin/risc0-host"

mkdir -p "$OUT_DIR"
OUT="$OUT_DIR/a4_campaign_race_${SHA}.tar.gz"
tar -czf "$OUT" -C "$STAGE" a4_campaign

HSHA="$(sha256sum "$STAGE/a4_campaign/bin/risc0-host" | awk '{print $1}')"
VO="$(grep -c verifyopcode "$STAGE/a4_campaign/repo/a4/pos/fingerprint_guard.py" 2>/dev/null || echo 0)"
cat <<EOF
[race-bundle] DONE
  bundle:        $OUT  ($(du -h "$OUT" | cut -f1))
  host sha256:   ${HSHA}
  verifyopcode profile in bundled guard: ${VO}  (must be >=1)
  scp:  scp -P 10022 $OUT ivgreiff@coinbase.net.in.tum.de:~/
EOF
[ "$VO" -ge 1 ] || { echo "ERROR: bundled fingerprint_guard lacks verifyopcode profile" >&2; exit 2; }
