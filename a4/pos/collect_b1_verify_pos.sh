#!/usr/bin/env bash
# Collect B1 verify shard JSONs from coinbase results into WSL audit_output.
#
# Usage (WSL):
#   bash a4/pos/collect_b1_verify_pos.sh [coinbase_results_subdir]
#
# Default subdir is the latest pos_audit_b1_verify* under ivgreiff results.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO_ROOT/a4/audits/audit_output/b1_verify_shards"
REMOTE_USER="${POS_USER:-ivgreiff}"
REMOTE_HOST="${POS_HOST:-coinbase.net.in.tum.de}"
REMOTE_PORT="${POS_PORT:-10022}"

mkdir -p "$OUT"

if [[ -n "${1:-}" ]]; then
    REMOTE_DIR="$1"
else
    REMOTE_DIR=$(ssh -p "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST" \
        'ls -td /srv/testbed/results/ivgreiff/a4/pos_audit_b1_verify*/*/B1_V*.json 2>/dev/null | head -1 | xargs dirname 2>/dev/null || \
         ls -td /srv/testbed/results/ivgreiff/*/pos_audit_b1_verify*/**/B1_V1.json 2>/dev/null | head -1 | xargs dirname 2>/dev/null || true')
fi

if [[ -z "$REMOTE_DIR" ]]; then
    echo "Searching for B1_V*.json under ivgreiff results..." >&2
    ssh -p "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST" \
        'find /srv/testbed/results/ivgreiff -name "B1_V1.json" 2>/dev/null | head -5'
    echo "ERROR: pass explicit results path as arg" >&2
    exit 2
fi

echo "Collecting from $REMOTE_DIR"
scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/B1_V"*.json "$OUT/" 2>/dev/null || \
scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:$REMOTE_DIR/out/B1_V"*.json "$OUT/" 2>/dev/null || {
    echo "Trying per-node upload dirs..." >&2
    for v in V1 V2 V3 V4 V5; do
        scp -P "$REMOTE_PORT" "$REMOTE_USER@$REMOTE_HOST:/srv/testbed/results/ivgreiff/a4/pos_audit_b1_verify*/**/*B1_${v}.json" "$OUT/" 2>/dev/null || true
    done
}

ls -la "$OUT"
echo "Shards in $OUT"
