#!/usr/bin/env bash
# Inc 3b §A.2 — B1 full strict verifier on POS (5 parallel shards, ~10 min wall).
#
# Run on coinbase: source /srv/testbed/pos/cli/venv3/bin/activate
#   bash a4/pos/run_inc3b_b1_verify_pos.sh
#   bash a4/pos/run_inc3b_b1_verify_pos.sh flare octorand opulous algofi idex
#
# Uses patched-host bundle (c2e77443…) + debian-trixie. ~3 sec/mut on POS test nodes.

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first" >&2
    exit 1
fi

if [[ $# -ge 5 ]]; then
    NODES=("$@")
else
    NODES=(flare octorand opulous algofi idex)
fi

BUNDLE="${B1_BUNDLE:-}"
for candidate in \
    "$HOME/a4_campaign_61a1ba8dfe80_inc3b.tar.gz" \
    "$HOME/a4_campaign_inc3b_b1.tar.gz"; do
    if [[ -z "$BUNDLE" && -f "$candidate" ]]; then
        BUNDLE="$candidate"
    fi
done
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: patched-host bundle missing (set B1_BUNDLE)" >&2
    exit 1
fi

echo "=== Inc 3b B1 verify (POS, 5-way parallel) ==="
echo "bundle=$BUNDLE"
tar -xOf "$BUNDLE" a4_campaign/bundle.json | grep host_sha256 || true
echo "nodes=${NODES[*]}"

PYTHONUNBUFFERED=1 python -m a4.pos.dispatch_b1_verify_pos \
    --manifest a4/pos/manifests/pos_inc3b_b1_verify.json \
    --bundle "$BUNDLE" \
    --nodes "${NODES[@]}" \
    --image debian-trixie \
    --allocation-duration 60 \
    --await \
    --await-timeout 3600 \
    --out dispatch_inc3b_b1_verify_manifest.json

echo "=== B1 POS verify complete — collect B1_V*.json from results ==="
