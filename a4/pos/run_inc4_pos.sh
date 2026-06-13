#!/usr/bin/env bash
# Phase 7d Inc 4 — dispatch B8/B11/B12 POS campaigns from coinbase management node.
#
# Prereqs (on coinbase, after user scp's bundle):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   Bundle at ~/a4_campaign_<sha>.tar.gz
#   User has pre-reserved nodes as ONE multi-node calendar entry (per
#   POS_PLAYBOOK §12.37). Default ALLOC_DURATION=0 claims that reservation.
#
# Node tiers (POS_PLAYBOOK §3.1):
#   - Tier S (Zen 4 EPYC 9354, fastest): flare, octorand, opulous, polynize
#   - Tier A (Zen 3 EPYC 7543):          algofi, gard, goracle, zone
#   - Tier C (Xeon Gold 6312U):          idex, meld, tinyman, yieldly
#   - Tier E (D-1518) and others:        DO NOT USE for Inc 4 (8-10× slower)
#
# Usage:
#   # B11 MUST be Tier S only (Tier C bottlenecks V5):
#   bash a4/pos/run_inc4_pos.sh b11     flare octorand opulous polynize
#
#   # B8 and B12 can include Tier C since N=50 is small:
#   bash a4/pos/run_inc4_pos.sh b8_seq  flare
#   bash a4/pos/run_inc4_pos.sh b8_par  flare octorand opulous polynize meld
#   bash a4/pos/run_inc4_pos.sh b12_1   flare octorand opulous polynize meld
#   bash a4/pos/run_inc4_pos.sh b12_100 flare octorand opulous polynize meld
#
# Override the calendar-claim mode if needed:
#   ALLOC_DURATION=120 bash a4/pos/run_inc4_pos.sh b8_seq flare
#   (creates a NEW 120-min entry; counts against the 2-entry user cap)
#
# Serialize dispatches on POS (B11 is heavy; do not overlap with other audits).

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
    echo "Usage: bash a4/pos/run_inc4_pos.sh {b8_seq|b8_par|b11|b12_1|b12_100|all} NODE [NODE ...]" >&2
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
    # --allocation-duration 0 = claim an EXISTING multi-node calendar reservation
    # (per POS_PLAYBOOK §12.37). User must pre-reserve nodes via web calendar UI
    # BEFORE running this. Pass --allocation-duration via env (default 0).
    python -m a4.pos.dispatch_pos \
        --manifest "$manifest" \
        --bundle "$BUNDLE" \
        --nodes "${node_args[@]}" \
        --allocation-duration "${ALLOC_DURATION:-0}" \
        --await
}

case "$AUDIT" in
    b8_seq)
        dispatch_one a4/pos/manifests/pos_audit_b8_seq.json 1
        ;;
    b8_par|b8)
        dispatch_one a4/pos/manifests/pos_audit_b8_par.json 5
        ;;
    b11)
        dispatch_one a4/pos/manifests/pos_audit_b11.json 5
        ;;
    b12_1|b12_in1_1)
        dispatch_one a4/pos/manifests/pos_audit_b12_in1_1_in4_1.json 5
        ;;
    b12_100|b12_in100)
        dispatch_one a4/pos/manifests/pos_audit_b12_in1_100_in4_100.json 5
        ;;
    all)
        dispatch_one a4/pos/manifests/pos_audit_b8_seq.json 1
        dispatch_one a4/pos/manifests/pos_audit_b8_par.json 5
        dispatch_one a4/pos/manifests/pos_audit_b11.json 5
        dispatch_one a4/pos/manifests/pos_audit_b12_in1_1_in4_1.json 5
        dispatch_one a4/pos/manifests/pos_audit_b12_in1_100_in4_100.json 5
        ;;
    *)
        echo "Unknown audit: $AUDIT" >&2
        exit 2
        ;;
esac

echo "Inc 4 POS dispatch ($AUDIT) complete."
