#!/usr/bin/env bash
# Inc 3b B7 Phase γ — same-node pairs + verbose touch (rolled into intra).
#
# Optimizations (Opus Inc 3b timing review):
#   - debian-trixie (~3 sec/mut on POS; bullseye breaks host → 0 cycles)
#   - pre-fix host bundle (6873e588…) — original B7 divergence host
#   - flare-pair || octorand-pair in parallel (different physical nodes)
#   - A4_COVERAGE_TOUCH_VERBOSE=1 in intra (§B.3 merged into §B.2)
#
# Usage (coinbase):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   bash a4/pos/run_inc3b_b7_gamma.sh intra flare octorand

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first" >&2
    exit 1
fi

MODE="${1:-intra}"
shift || true
FLARE="${1:-flare}"
OCTO="${2:-octorand}"

BUNDLE="${B7_BUNDLE:-}"
if [[ -z "$BUNDLE" ]]; then
    for candidate in \
        ~/a4_campaign_inc3b_b7.tar.gz \
        ~/a4_campaign_3ff810e4ab47.tar.gz; do
        if [[ -f "$candidate" ]]; then
            BUNDLE="$candidate"
            break
        fi
    done
fi
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: no B7 bundle (set B7_BUNDLE)" >&2
    exit 1
fi
echo "B7_BUNDLE=$BUNDLE"
tar -xOf "$BUNDLE" a4_campaign/bundle.json | grep host_sha256 || true

write_job_manifest() {
    local suffix="$1"
    local out="$2"
    python3 -c "
import json
print(json.dumps({
    'name': 'pos_inc3b_b7_intra',
    'image': 'debian-trixie',
    'guest_args': ['--in1', '5', '--in4', '10'],
    'jobs': [{
        'strategy': 'zoned', 'seed': 999, 'n': 50,
        'telemetry_level': 'full', 'run_suffix': '$suffix',
        'coverage_touch_verbose': True
    }]
}, indent=2))
" > "$out"
}

dispatch_job() {
    local manifest="$1"
    local node="$2"
    echo "=== $node $(basename "$manifest") ==="
    PYTHONUNBUFFERED=1 python -m a4.pos.dispatch_pos \
        --manifest "$manifest" \
        --bundle "$BUNDLE" \
        --nodes "$node" \
        --allocation-duration 60 \
        --await \
        --await-timeout 3600
}

run_node_pair() {
    local node="$1"
    local suffix_a="$2"
    local suffix_b="$3"
    local tmp
    tmp=$(mktemp -d)
    write_job_manifest "$suffix_a" "$tmp/${suffix_a}.json"
    write_job_manifest "$suffix_b" "$tmp/${suffix_b}.json"
    dispatch_job "$tmp/${suffix_a}.json" "$node"
    dispatch_job "$tmp/${suffix_b}.json" "$node"
    rm -rf "$tmp"
}

run_intra() {
    local tmpdir logdir
    tmpdir=$(mktemp -d)
    logdir=$(mktemp -d)
    echo "Parallel: ${FLARE}-pair + ${OCTO}-pair (~10 min wall each)"
    run_node_pair "$FLARE" flareA flareB > "$logdir/flare.log" 2>&1 &
    local pid_flare=$!
    run_node_pair "$OCTO" octoA octoB > "$logdir/octo.log" 2>&1 &
    local pid_octo=$!
    wait "$pid_flare" || { echo "flare pair FAILED"; cat "$logdir/flare.log"; exit 1; }
    wait "$pid_octo" || { echo "octo pair FAILED"; cat "$logdir/octo.log"; exit 1; }
    cat "$logdir/flare.log" "$logdir/octo.log"
    rm -rf "$tmpdir" "$logdir"
}

case "$MODE" in
    intra) run_intra ;;
    verbose)
        echo "NOTE: verbose is merged into intra (coverage_touch_verbose=true). Running intra." >&2
        run_intra
        ;;
    *)
        echo "Usage: bash a4/pos/run_inc3b_b7_gamma.sh intra [flare] [octorand]" >&2
        exit 2
        ;;
esac

echo "Inc 3b B7 gamma ($MODE) complete."
