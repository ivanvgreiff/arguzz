#!/usr/bin/env bash
# Launch B1 phase-B strict verifier on POS (5 parallel shards).
#
# Run on coinbase after: source /srv/testbed/pos/cli/venv3/bin/activate
#
# Usage:
#   bash a4/pos/run_b1_verify_pos.sh flare octorand opulous algofi idex

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv: source /srv/testbed/pos/cli/venv3/bin/activate" >&2
    exit 1
fi

NODES=("$@")
if [[ ${#NODES[@]} -lt 5 ]]; then
    echo "Usage: bash a4/pos/run_b1_verify_pos.sh NODE NODE NODE NODE NODE" >&2
    echo "Need 5 nodes (one B1 variant shard each)." >&2
    exit 2
fi

BUNDLE=$(ls -t ~/a4_campaign_*.tar.gz 2>/dev/null | head -1 || true)
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: no ~/a4_campaign_*.tar.gz" >&2
    exit 1
fi

echo "=== B1 verify dispatch ==="
echo "bundle=$BUNDLE"
echo "nodes=${NODES[*]}"

ALLOC_ID="${B1_VERIFY_ALLOC_ID:-}"
EXTRA_ALLOC=()
if [[ -n "$ALLOC_ID" ]]; then
    EXTRA_ALLOC=(--allocation-id "$ALLOC_ID")
    echo "reusing allocation $ALLOC_ID"
fi

PYTHONUNBUFFERED=1 python -m a4.pos.dispatch_b1_verify_pos \
    --manifest a4/pos/manifests/pos_audit_b1_verify.json \
    --bundle "$BUNDLE" \
    --nodes "${NODES[@]}" \
    --allocation-duration 180 \
    "${EXTRA_ALLOC[@]}" \
    --await \
    --await-timeout 7200 \
    --out dispatch_b1_verify_manifest.json

echo "=== B1 verify dispatch complete ==="
echo "Collect shards from results dir, then merge on WSL."
