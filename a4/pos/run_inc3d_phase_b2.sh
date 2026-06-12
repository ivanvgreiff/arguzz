#!/usr/bin/env bash
# Inc 3d Phase B2 (B4) — Memory-record fingerprint capture.
#
# Single focused dispatch: same SPREAD plan but with A4_MEM_FINGERPRINT=1.
# Drops A4_COVERAGE_TOUCH_VERBOSE and A4_FTW291_TRACE to keep logs small
# (those data are already captured in Pass 1).
#
# Pre-reservation: same as Inc 3c/3d (one multi-node entry, --allocation-duration 0).
#
# Usage (coinbase, after bundle prep with NEW host SHA):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   export INC3D_B2_BUNDLE=~/INC3D_B2_BUNDLE.tar.gz
#   bash a4/pos/run_inc3d_phase_b2.sh 2>&1 | tee ~/inc3d_b2_dispatch.log

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first" >&2
    exit 1
fi

BUNDLE="${INC3D_B2_BUNDLE:-}"
for candidate in \
    "$HOME/INC3D_B2_BUNDLE.tar.gz" \
    "$HOME/bundles/"a4_campaign_*.tar.gz; do
    if [[ -z "$BUNDLE" && -f "$candidate" ]]; then
        BUNDLE="$candidate"
    fi
done
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: set INC3D_B2_BUNDLE to instrumented-host tarball (new SHA after B4 build)" >&2
    exit 1
fi

# Verify the bundle has the B4 patch (memory fingerprint code in executor passthrough)
if ! tar -xOf "$BUNDLE" a4_campaign/repo/a4/core/executor.py 2>/dev/null \
     | grep -q "A4_MEM_FINGERPRINT"; then
    echo "ERROR: bundle missing B4 (A4_MEM_FINGERPRINT) executor passthrough." >&2
    echo "       Rebuild bundle after pulling latest executor.py changes." >&2
    exit 1
fi

OUT="${INC3D_B2_OUT:-$HOME/inc3d_out_b2}"
mkdir -p "$OUT"
CAMPAIGN="pos_inc3d_phase_b2"

ACTUAL_HOST_SHA=$(tar -xOf "$BUNDLE" a4_campaign/bundle.json | grep -o '"host_sha256": "[^"]*"' | awk '{print $2}' | tr -d '"')
echo "INC3D_B2_BUNDLE=$BUNDLE"
echo "host_sha256=$ACTUAL_HOST_SHA  (NEW — should differ from 632094ef…)"
echo "campaign_name=$CAMPAIGN"

write_manifest() {
    local seed="$1" suffix="$2" out="$3"
    A4_MANIFEST_CAMPAIGN="$CAMPAIGN" \
    A4_MANIFEST_SUFFIX="$suffix" \
    A4_MANIFEST_SEED="$seed" \
    python3 - <<'PY' > "$out"
import json, os
job = {
    "strategy": "zoned",
    "seed": int(os.environ["A4_MANIFEST_SEED"]),
    "n": 50,
    "telemetry_level": "full",
    "run_suffix": os.environ["A4_MANIFEST_SUFFIX"],
    "coverage_touch_verbose": False,
    "ftw291_trace": False,
    "mem_fingerprint": True,
}
print(json.dumps({
    "name": os.environ["A4_MANIFEST_CAMPAIGN"],
    "image": "debian-trixie",
    "guest_args": ["--in1", "5", "--in4", "10"],
    "jobs": [job],
}, indent=2))
PY
}

dispatch() {
    local manifest="$1" node="$2"
    echo "=== dispatch $node $(basename "$manifest") ==="
    PYTHONUNBUFFERED=1 python -m a4.pos.dispatch_pos \
        --manifest "$manifest" --bundle "$BUNDLE" --nodes "$node" \
        --allocation-duration 0 --await --await-timeout 5400
}

run_node_pair() {
    local node="$1" seed="$2" sa="$3" sb="$4"
    local tmp
    tmp=$(mktemp -d)
    write_manifest "$seed" "$sa" "$tmp/$sa.json"
    write_manifest "$seed" "$sb" "$tmp/$sb.json"
    dispatch "$tmp/$sa.json" "$node"
    dispatch "$tmp/$sb.json" "$node"
    rm -rf "$tmp"
}

# Same SPREAD layout as Inc 3c/3d phase B for consistency.
( for pair in "999 octoaA octoaB" "999 octobA octobB"; do
      set -- $pair; run_node_pair octorand "$1" "$2" "$3"
  done ) > "$OUT/octo.log" 2>&1 &
PID_OCTO=$!
( run_node_pair opulous 1000 opugA opugB ) > "$OUT/opulous.log" 2>&1 &
PID_OPU=$!
( run_node_pair meld 1001 melddA melddB ) > "$OUT/meld.log" 2>&1 &
PID_MELD=$!
( run_node_pair flare 999 flareCtrlA flareCtrlB ) > "$OUT/flare.log" 2>&1 &
PID_FLARE=$!

fail=0
for name in OCTO OPU MELD FLARE; do
    pid_var="PID_$name"
    log_var="$(echo "$name" | tr A-Z a-z).log"
    if ! wait "${!pid_var}"; then
        echo "$name FAILED"; tail -100 "$OUT/$log_var"; fail=1
    fi
done
[[ "$fail" = 0 ]] || exit 1

echo "Inc 3d Phase B2 complete. Logs under $OUT."
echo "Collect with: INC3D_PASS=b2 bash a4/pos/collect_inc3d_results.sh   (after adjusting collect script)"
