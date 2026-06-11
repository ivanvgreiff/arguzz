#!/usr/bin/env bash
# Inc 3c Phase δ — B7 race closure capture (patched host + verbose).
#
# PRE-RESERVATION REQUIRED (see POS_PLAYBOOK §12.37):
#   This script uses --allocation-duration 0 ("claim pre-existing reservation").
#   BEFORE running, the user MUST create ONE multi-node calendar entry covering
#   ALL nodes used below (octorand + flare, optionally opulous + meld) via the
#   web calendar UI for ≥60 min. Without this, every dispatch creates its own
#   calendar entry and the 2-future-entries cap fires after the 2nd parallel
#   dispatch (see POS_PLAYBOOK §12.28).
#
# DEFAULT PLAN (drop-in for original):
#   octorand: 4 sequential pairs (8 runs)
#   flare:    1 control pair (2 runs) in parallel
#   Wall time: ~40 min (octorand bound), all under ONE pre-reserved entry.
#
# OPTIONAL --spread MODE (set SPREAD=1):
#   octorand:  2 pairs (4 runs)  — primary race capture
#   opulous:   1 pair (2 runs)   — bonus Tier S sibling check
#   meld:      1 pair (2 runs)   — bonus Tier S sibling check
#   flare:     1 control pair    — negative control
#   Wall time: ~20 min (all 4 nodes parallel, max = octorand 4 runs).
#   Reservation must cover all 4 nodes.
#
# Usage (coinbase):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   export INC3C_BUNDLE=~/a4_campaign_inc3c.tar.gz
#   bash a4/pos/run_inc3c_phase_delta.sh           # default plan
#   SPREAD=1 bash a4/pos/run_inc3c_phase_delta.sh  # spread plan (4 nodes)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first" >&2
    exit 1
fi

BUNDLE="${INC3C_BUNDLE:-}"
for candidate in \
    "$HOME/a4_campaign_inc3c.tar.gz" \
    "$HOME/a4_campaign_61a1ba8dfe80_inc3b.tar.gz" \
    "$HOME/bundles/a4_campaign_61a1ba8dfe80.tar.gz"; do
    if [[ -z "$BUNDLE" && -f "$candidate" ]]; then
        BUNDLE="$candidate"
    fi
done
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: set INC3C_BUNDLE to patched-host tarball (c2e77443…)" >&2
    exit 1
fi

EXPECTED="c2e77443275372846a73a9d1d13d340e8068ff70961d8e8b97fff479bb63b332"
ACTUAL=$(tar -xOf "$BUNDLE" a4_campaign/bundle.json | grep -o '"host_sha256": "[^"]*"' | awk '{print $2}' | tr -d '"')
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    echo "ERROR: bundle host sha mismatch" >&2
    echo "  expected $EXPECTED" >&2
    echo "  actual   $ACTUAL" >&2
    exit 1
fi

# CRITICAL: the bundle must ALSO contain the patched fuzzer that passes
# <a4_touch_verbose> tags through to stdout (a4/core/executor.py). Without
# this patch, the host emits verbose tags but the fuzzer's capture_output=True
# swallows them before they ever reach the campaign log.
if ! tar -xOf "$BUNDLE" a4_campaign/repo/a4/core/executor.py 2>/dev/null \
     | grep -q "A4_COVERAGE_TOUCH_VERBOSE.*== .1."; then
    echo "ERROR: bundle is missing the verbose-passthrough fuzzer patch."   >&2
    echo "       Rebuild after pulling latest main (a4/core/executor.py)."  >&2
    exit 1
fi

OUT="${INC3C_OUT:-$HOME/inc3c_out}"
mkdir -p "$OUT"
echo "INC3C_BUNDLE=$BUNDLE"
echo "host_sha256=$ACTUAL"
echo "verbose-passthrough patch: present"
echo "SPREAD mode: ${SPREAD:-0}"

write_manifest() {
    local seed="$1" suffix="$2" out="$3"
    python3 -c "
import json
print(json.dumps({
    'name': 'pos_inc3c_phase_delta',
    'image': 'debian-trixie',
    'guest_args': ['--in1', '5', '--in4', '10'],
    'jobs': [{
        'strategy': 'zoned', 'seed': $seed, 'n': 50,
        'telemetry_level': 'full', 'run_suffix': '$suffix',
        'coverage_touch_verbose': True
    }]
}, indent=2))" > "$out"
}

dispatch() {
    local manifest="$1" node="$2"
    echo "=== dispatch $node $(basename "$manifest") ==="
    # --allocation-duration 0 → claim PRE-EXISTING calendar entry. Caller must
    # have pre-reserved $node via web calendar UI.
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

if [[ "${SPREAD:-0}" = "1" ]]; then
    # SPREAD plan: 4 nodes in parallel, max wall ~20 min
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
        log_var="$(echo $name | tr A-Z a-z).log"
        if ! wait "${!pid_var}"; then
            echo "$name FAILED"; tail -100 "$OUT/$log_var"; fail=1
        fi
    done
    [[ "$fail" = 0 ]] || exit 1
else
    # DEFAULT plan: 2 nodes in parallel, max wall ~40 min
    ( for pair in "999 octoaA octoaB" "999 octobA octobB" "1000 octogA octogB" "1001 octodA octodB"; do
          set -- $pair; run_node_pair octorand "$1" "$2" "$3"
      done ) > "$OUT/octo.log" 2>&1 &
    PID_OCTO=$!

    ( run_node_pair flare 999 flareCtrlA flareCtrlB ) > "$OUT/flare.log" 2>&1 &
    PID_FLARE=$!

    wait "$PID_OCTO" || { echo "OCTO FAILED"; tail -100 "$OUT/octo.log"; exit 1; }
    wait "$PID_FLARE" || { echo "FLARE FAILED"; tail -100 "$OUT/flare.log"; exit 1; }
fi

echo "Phase δ capture complete. Logs under $OUT."
