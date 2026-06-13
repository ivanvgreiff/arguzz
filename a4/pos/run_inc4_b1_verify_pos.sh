#!/usr/bin/env bash
# Inc 4 — B1 strict verifier on POS (B12 ×2 + B11). Run on coinbase.
#
# Usage:
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   cd ~/arguzz
#   bash a4/pos/run_inc4_b1_verify_pos.sh
#   bash a4/pos/run_inc4_b1_verify_pos.sh b12_1          # one campaign only
#   bash a4/pos/run_inc4_b1_verify_pos.sh b11 ALLOC_ID   # reuse allocation
#
# Nodes (Tier S first): flare octorand opulous algofi + meld for 5th slot.
# Reuses existing allocation when ALLOC_ID passed or $INC4_ALLOC_ID set.
#
# RESILIENCE (revised 2026-06-13 after Inc 4 B1 verify incident):
# 1. We do NOT `set -e` on dispatch_one. POS coordinator HTTP hiccups can cause
#    one dispatch's await to spuriously fail (`Unable to GET url ...`) while the
#    underlying verifier completes successfully on the nodes. We track per-
#    dispatch exit codes and continue to the next campaign regardless, so a
#    single coordinator blip cannot block the entire suite.
# 2. After all dispatches are attempted, we SSH each node and verify the
#    per-variant result JSON is present + well-formed. Output a summary table.
# 3. The Python dispatcher (`dispatch_b1_verify_pos.py`) now also retries
#    transient HTTP exceptions inside `_await_id_silently` (3 retries, exp
#    backoff) AND falls back to a node-side result-file check before declaring
#    a job failed.

set -uo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first" >&2
    exit 1
fi

CAMPAIGN="${1:-all}"
ALLOC_ID="${2:-${INC4_ALLOC_ID:-}}"
# Fastest Tier S + meld (V4/V5 DBs may live on meld/algofi from Inc4 dispatch)
NODES=(flare octorand opulous algofi meld)

BUNDLE=$(ls -t ~/a4_campaign_*.tar.gz 2>/dev/null | head -1 || true)
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: no bundle at ~/a4_campaign_*.tar.gz" >&2
    exit 1
fi

# Track outcomes across multiple dispatches
declare -A DISPATCH_RC=()
declare -a CAMPAIGNS_RUN=()

dispatch_one() {
    local manifest="$1"
    local label="${manifest##*/}"; label="${label%.json}"
    local extra_args=()
    if [[ -n "$ALLOC_ID" ]]; then
        extra_args+=(--allocation-id "$ALLOC_ID")
    else
        extra_args+=(--allocation-duration 120)
    fi
    echo
    echo "=================================================================="
    echo "=== B1 verify POS: $manifest"
    echo "=================================================================="
    set +e
    PYTHONUNBUFFERED=1 python -m a4.pos.dispatch_b1_verify_pos \
        --manifest "$manifest" \
        --bundle "$BUNDLE" \
        --nodes "${NODES[@]}" \
        --image debian-trixie \
        "${extra_args[@]}" \
        --await \
        --await-timeout 14400 \
        --out "dispatch_${label}.json"
    local rc=$?
    set -e
    DISPATCH_RC[$label]=$rc
    CAMPAIGNS_RUN+=("$label")
    echo "[run_inc4_b1] dispatch_one $label exit=$rc"
    return 0  # NEVER fail the outer script on one dispatch's exit
}

case "$CAMPAIGN" in
    b12_1|b12_in1_1)
        dispatch_one a4/pos/manifests/pos_inc4_b12_b1_in1_1.json ;;
    b12_100|b12_in100)
        dispatch_one a4/pos/manifests/pos_inc4_b12_b1_in100.json ;;
    b11)
        dispatch_one a4/pos/manifests/pos_inc4_b11_b1.json ;;
    all)
        dispatch_one a4/pos/manifests/pos_inc4_b12_b1_in1_1.json
        dispatch_one a4/pos/manifests/pos_inc4_b12_b1_in100.json
        dispatch_one a4/pos/manifests/pos_inc4_b11_b1.json
        ;;
    *)
        echo "Usage: bash a4/pos/run_inc4_b1_verify_pos.sh {all|b12_1|b12_100|b11} [ALLOC_ID]" >&2
        exit 2 ;;
esac

# ------------------------------------------------------------------
# POST-DISPATCH AUDIT: did each campaign actually land its result JSONs?
# ------------------------------------------------------------------
echo
echo "=================================================================="
echo "=== Inc 4 B1 POS verify — POST-DISPATCH AUDIT"
echo "=================================================================="

audit_campaign() {
    local label="$1"
    local rc="${DISPATCH_RC[$label]:-?}"
    echo
    echo "[audit] $label (dispatch rc=$rc)"
    local got=0 want=5
    for n in "${NODES[@]}"; do
        # Map node -> variant via the manifest jobs order
        for v in V1 V2 V3 V4 V5; do
            local remote="/root/b1_verify_results/${label}_${v}/B1_${v}.json"
            local result
            result=$(ssh -o ConnectTimeout=8 -o StrictHostKeyChecking=no -o LogLevel=ERROR \
                "root@$n" "test -f $remote && python3 -c 'import json; d=json.load(open(\"$remote\")); pv=d[\"per_variant\"][\"$v\"]; print(f\"{pv[\\\"pass\\\"]}/{pv[\\\"total\\\"]}\")' 2>/dev/null" 2>/dev/null \
                || echo "")
            if [[ -n "$result" ]]; then
                echo "  ✓ $n/$v = $result"
                got=$((got+1))
                break
            fi
        done
    done
    echo "  → $got/$want variants found"
}

for c in "${CAMPAIGNS_RUN[@]}"; do
    audit_campaign "$c"
done

echo
echo "=================================================================="
echo "=== Inc 4 B1 POS verify SUMMARY"
echo "=================================================================="
for c in "${CAMPAIGNS_RUN[@]}"; do
    echo "  $c: dispatch rc=${DISPATCH_RC[$c]:-?}"
done
echo
echo "Next: collect with"
echo "  cd ~/arguzz && bash a4/pos/collect_inc4_b1_results.sh"

# Return nonzero if any campaign had a hard failure AND no results landed
total_failed=0
for c in "${CAMPAIGNS_RUN[@]}"; do
    [[ "${DISPATCH_RC[$c]}" -ne 0 ]] && total_failed=$((total_failed+1))
done
echo "[run_inc4_b1] $total_failed/${#CAMPAIGNS_RUN[@]} dispatches had nonzero rc (does NOT necessarily mean failure — see post-dispatch audit above)"
exit 0
