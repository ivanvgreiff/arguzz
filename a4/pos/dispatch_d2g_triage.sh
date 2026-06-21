#!/bin/bash
# dispatch_d2g_triage.sh — B4 full-variant tier-2 triage on POS (1022 jobs).
#
# Run from coinbase (POS SSH access to flare…goracle). See POS_PLAYBOOK §12.53.
#
# Usage:
#   REPO=/path/to/arguzz \
#   MANIFEST_DIR=$REPO/a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4 \
#   bash a4/pos/dispatch_d2g_triage.sh preflight
#   bash a4/pos/dispatch_d2g_triage.sh dispatch
#   bash a4/pos/dispatch_d2g_triage.sh postcollect
#   bash a4/pos/dispatch_d2g_triage.sh all
#
# Env overrides:
#   MANIFEST_DIR   — dir with d2g_triage_rerun.chain + manifest CSV
#   REPO           — local arguzz checkout (PYTHONPATH root)
#   POLL_SEC       — chain poll interval (default 30)
#   RESULTS_BASE   — chain_dispatcher pull dir (default /tmp/d2g_triage_chain_results)
#   COLLECT_DIR    — merged triage JSON dir (default /tmp/d2g_triage_collected)
#   OUT_DIR        — final CSV/report dir (default $MANIFEST_DIR)

set -euo pipefail

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
MANIFEST_DIR="${MANIFEST_DIR:-$REPO/a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4}"
CHAIN="${MANIFEST_DIR}/d2g_triage_rerun.chain"
MANIFEST_CSV="${MANIFEST_DIR}/d2g_triage_rerun_manifest.csv"
POLL_SEC="${POLL_SEC:-30}"
RESULTS_BASE="${RESULTS_BASE:-/tmp/d2g_triage_chain_results}"
COLLECT_DIR="${COLLECT_DIR:-/tmp/d2g_triage_collected/merged}"
OUT_DIR="${OUT_DIR:-$MANIFEST_DIR}"
LOG_FILE="${LOG_FILE:-/tmp/d2g_triage_chain.log}"

export PYTHONPATH="$REPO"

cmd="${1:-all}"

do_preflight() {
    echo "=== D2.G triage preflight ==="
    python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale preflight
}

do_dispatch() {
    echo "=== D2.G triage chain dispatch ==="
    test -f "$CHAIN" || { echo "missing chain: $CHAIN"; exit 1; }
    MANIFEST="$CHAIN" \
    CHAIN_NAME=d2g_triage_b4 \
    LOG_FILE="$LOG_FILE" \
    POLL_SEC="$POLL_SEC" \
    RESULTS_BASE="$RESULTS_BASE" \
    bash "$REPO/a4/pos/chain_dispatcher.sh"
}

do_gather() {
    echo "=== Gather triage JSON from POS nodes ==="
    python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale gather --out "${COLLECT_DIR%/merged}"
}

do_collect() {
    echo "=== collect → CSV ==="
    OUT_CSV="$OUT_DIR/d2g_accept_triage_all_variants.csv"
    REPORT="$OUT_DIR/d2g_triage_collect_report.json"
    python3 -m a4.runs.iv_pos_8.d2g.triage_at_scale collect "$COLLECT_DIR" \
        --out "$OUT_CSV" --report "$REPORT"
    echo "Wrote $OUT_CSV"
}

do_soundness() {
    echo "=== soundness re-read (Item 2) ==="
    OUT_CSV="$OUT_DIR/d2g_accept_triage_all_variants.csv"
    test -f "$OUT_CSV" || { echo "missing $OUT_CSV — run postcollect first"; exit 1; }
    python3 -m a4.runs.iv_pos_8.d2g.soundness_reread "$OUT_CSV" \
        --out-json "$OUT_DIR/d2g_soundness_reread.json" \
        --out-md "$OUT_DIR/d2g_soundness_reread.md"
}

case "$cmd" in
    preflight) do_preflight ;;
    dispatch)  do_dispatch ;;
    gather)    do_gather ;;
    collect)   do_collect ;;
    soundness) do_soundness ;;
    postcollect) do_gather; do_collect; do_soundness ;;
    all) do_preflight; do_dispatch; do_gather; do_collect; do_soundness ;;
    *) echo "usage: $0 {preflight|dispatch|gather|collect|soundness|postcollect|all}"; exit 1 ;;
esac
