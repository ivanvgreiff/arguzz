#!/usr/bin/env bash
# Phase 7d Inc 3 — dispatch B1/B4/B7 POS audits from coinbase management node.
#
# Prereqs (on coinbase, after user scp's bundle):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   Bundle at ~/a4_campaign_<sha>.tar.gz
#
# Usage:
#   bash a4/pos/run_inc3_pos.sh b1 flare bitcoin bitcoincash bitcoingold litecoin
#   bash a4/pos/run_inc3_pos.sh b4  flare bitcoin bitcoincash bitcoingold litecoin
#   bash a4/pos/run_inc3_pos.sh b7  flare bitcoin bitcoincash bitcoingold litecoin dogecoin
#   bash a4/pos/run_inc3_pos.sh all flare bitcoin bitcoincash bitcoingold litecoin dogecoin
#
# B1 needs 5 nodes (5×200=1000 muts). B4 needs 5 nodes. B7 needs 10 nodes (or run in two waves).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first:" >&2
    echo "  source /srv/testbed/pos/cli/venv3/bin/activate" >&2
    exit 1
fi

AUDIT="${1:-}"
shift || true
NODES=("$@")

if [[ -z "$AUDIT" ]]; then
    echo "Usage: bash a4/pos/run_inc3_pos.sh {b1|b4|b7|all} NODE [NODE ...]" >&2
    exit 2
fi

BUNDLE=$(ls -t ~/a4_campaign_*.tar.gz 2>/dev/null | head -1 || true)
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: no bundle at ~/a4_campaign_*.tar.gz — scp from WSL first" >&2
    exit 1
fi

dispatch_one() {
    local manifest="$1"
    local need="${2:-1}"
    if [[ ${#NODES[@]} -lt $need ]]; then
        echo "ERROR: $manifest needs $need nodes; got ${#NODES[@]}" >&2
        exit 1
    fi
    local node_args=()
    local i
    for ((i=0; i<need; i++)); do
        node_args+=("${NODES[$i]}")
    done
    echo "=== dispatch: $manifest (${need} nodes) ==="
    python -m a4.pos.dispatch_pos \
        --manifest "$manifest" \
        --bundle "$BUNDLE" \
        --nodes "${node_args[@]}" \
        --allocation-duration 360 \
        --await
}

case "$AUDIT" in
    b1)
        dispatch_one a4/pos/manifests/pos_audit_b1.json 5
        ;;
    b4)
        dispatch_one a4/pos/manifests/pos_audit_b4.json 5
        ;;
    b7)
        dispatch_one a4/pos/manifests/pos_audit_b7.json "${#NODES[@]}"
        ;;
    all)
        dispatch_one a4/pos/manifests/pos_audit_b1.json 5
        dispatch_one a4/pos/manifests/pos_audit_b4.json 5
        dispatch_one a4/pos/manifests/pos_audit_b7.json "${#NODES[@]}"
        ;;
    *)
        echo "Unknown audit: $AUDIT" >&2
        exit 2
        ;;
esac

echo "Inc 3 POS dispatch ($AUDIT) complete."
