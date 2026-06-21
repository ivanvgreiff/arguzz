#!/bin/bash
# dispatch_d2g_triage.sh — D2.G full-campaign tier-2 triage on POS (1423 deduped jobs).
#
# Run from coinbase (POS SSH access to flare…goracle). See POS_PLAYBOOK §12.53.
#
# Usage:
#   REPO=~/arguzz \
#   MANIFEST_DIR=$REPO/a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_full \
#   TRIAGE_NODES="flare polynize octorand opulous algofi zone gard goracle" \
#   bash a4/pos/dispatch_d2g_triage.sh preflight
#   bash a4/pos/dispatch_d2g_triage.sh dispatch
#   bash a4/pos/dispatch_d2g_triage.sh postcollect
#   bash a4/pos/dispatch_d2g_triage.sh all
#
# Env overrides:
#   TRIAGE_NODES   — space-separated node list (default: 8 D2.F campaign nodes)
#   MANIFEST_DIR   — dir with d2g_triage_rerun_manifest.csv + chain file
#   CHAIN          — chain file path (default: $MANIFEST_DIR/d2g_triage_rerun.chain)
#   REPO           — arguzz checkout on coinbase (PYTHONPATH root)
#   POLL_SEC       — chain poll interval (default 10)
#   D2G_BASELINE_CACHE — baseline trace disk cache (set in chain remote_cmd)
#   RESULTS_BASE   — chain_dispatcher pull dir (default /tmp/d2g_triage_chain_results)
#   COLLECT_DIR    — merged triage JSON dir (default /tmp/d2g_triage_collected)
#   OUT_DIR        — final CSV/report dir (default $MANIFEST_DIR)

set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
MANIFEST_DIR="${MANIFEST_DIR:-$REPO/a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_full}"
CHAIN="${CHAIN:-${MANIFEST_DIR}/d2g_triage_rerun.chain}"
MANIFEST_CSV="${MANIFEST_DIR}/d2g_triage_rerun_manifest.csv"
POLL_SEC="${POLL_SEC:-10}"
RESULTS_BASE="${RESULTS_BASE:-/tmp/d2g_triage_chain_results}"
COLLECT_DIR="${COLLECT_DIR:-/tmp/d2g_triage_collected/merged}"
OUT_DIR="${OUT_DIR:-$MANIFEST_DIR}"
LOG_FILE="${LOG_FILE:-/tmp/d2g_triage_chain.log}"
DEFAULT_TRIAGE_NODES="flare polynize octorand opulous algofi zone gard goracle"

export PYTHONPATH="$REPO"

cmd="${1:-all}"

_check_manifest_seeds() {
    echo "=== Mandatory pre-dispatch seed check ==="
    test -f "$MANIFEST_CSV" || { echo "missing manifest: $MANIFEST_CSV"; exit 1; }
    local seeds
    seeds=$(cut -d, -f2 "$MANIFEST_CSV" | tail -n +2 | sort -u | tr '\n' ' ')
    echo "manifest seeds: $seeds"
    for s in 1234 1235 1236; do
        echo "$seeds" | grep -qw "$s" || {
            echo "ERROR: seed $s missing — wrong collection_root or batch-1-only manifest. STOP."
            exit 1
        }
    done
    local n_jobs
    n_jobs=$(tail -n +2 "$MANIFEST_CSV" | wc -l)
    echo "manifest jobs: $n_jobs (expect 1423)"
    if [[ "$n_jobs" -lt 1400 ]]; then
        echo "ERROR: job count $n_jobs looks like batch-1 subset. STOP."
        exit 1
    fi
}

do_preflight() {
    echo "=== D2.G triage preflight ==="
    _check_manifest_seeds
    # shellcheck disable=SC2206
    local nodes=(${TRIAGE_NODES:-$DEFAULT_TRIAGE_NODES})
    python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale preflight --nodes "${nodes[@]}"
}

do_dispatch() {
    echo "=== D2.G triage chain dispatch ==="
    _check_manifest_seeds
    test -f "$CHAIN" || { echo "missing chain: $CHAIN"; exit 1; }
    MANIFEST="$CHAIN" \
    CHAIN_NAME=d2g_triage_full \
    LOG_FILE="$LOG_FILE" \
    POLL_SEC="$POLL_SEC" \
    RESULTS_BASE="$RESULTS_BASE" \
    bash "$REPO/a4/pos/chain_dispatcher.sh"
}

do_gather() {
    echo "=== Gather triage JSON from POS nodes ==="
    # shellcheck disable=SC2206
    local nodes=(${TRIAGE_NODES:-$DEFAULT_TRIAGE_NODES})
    python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale gather --out "${COLLECT_DIR%/merged}" --nodes "${nodes[@]}"
}

do_collect() {
    echo "=== collect → CSV ==="
    OUT_CSV="$OUT_DIR/d2g_accept_triage_all_variants.csv"
    REPORT="$OUT_DIR/d2g_triage_collect_report.json"
    python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale collect "$COLLECT_DIR" \
        --out "$OUT_CSV" --report "$REPORT" --manifest "$MANIFEST_CSV"
    echo "Wrote $OUT_CSV"
}

do_soundness() {
    echo "=== soundness re-read ==="
    OUT_CSV="$OUT_DIR/d2g_accept_triage_all_variants.csv"
    test -f "$OUT_CSV" || { echo "missing $OUT_CSV — run postcollect first"; exit 1; }
    python3 -m a4.runs.iv_pos_8.d2g.soundness_reread "$OUT_CSV" \
        --out-json "$OUT_DIR/d2g_soundness_reread.json" \
        --out-md "$OUT_DIR/d2g_soundness_reread.md"
}

case "$cmd" in
    preflight) _check_manifest_seeds; do_preflight ;;
    dispatch)  do_dispatch ;;
    gather)    do_gather ;;
    collect)   do_collect ;;
    soundness) do_soundness ;;
    postcollect) do_gather; do_collect; do_soundness ;;
    all) do_preflight; do_dispatch; do_gather; do_collect; do_soundness ;;
    check) _check_manifest_seeds ;;
    *) echo "usage: $0 {check|preflight|dispatch|gather|collect|soundness|postcollect|all}"; exit 1 ;;
esac
