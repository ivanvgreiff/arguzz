#!/usr/bin/env bash
# a4/pos/run_inc4_all.sh — Run ALL Inc 4 POS audits sequentially via dispatch_audit.sh.
#
# Designed to be fire-and-forget inside tmux on coinbase. ~80 min total wall.
#
# USAGE
#   tmux new -s inc4
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   cd ~/arguzz
#   bash a4/pos/run_inc4_all.sh
#   # Ctrl-b d to detach.
#
# WHAT IT DOES (sequentially, each blocks until done):
#   Phase 1 — b8_seq:   5 sub-dispatches on flare         (~25 min)
#   Phase 2a — b8_par:  1 dispatch on 5 non-flare nodes   (~10 min)
#   Phase 2b — b12_1:   1 dispatch on 5 non-flare nodes   (~10 min)
#   Phase 2c — b12_100: 1 dispatch on 5 non-flare nodes   (~10 min)
#   Phase 3 — b11:      1 dispatch on 5 Tier S nodes      (~25 min)
#
# NODE POOLS (assumes calendar entry 1747 covers all 6 nodes; §12.37 pattern)
#   FLARE_ONLY   = flare                                  # b8_seq slot
#   POOL_5       = octorand opulous polynize algofi meld  # b8_par, b12_*
#   TIER_S_5     = flare octorand opulous polynize algofi # b11 (no meld bottleneck)
#
# OUTPUT
#   - DBs on POS at /srv/testbed/results/ivgreiff/a4/<manifest_name>/
#   - Per-dispatch logs at /tmp/inc4_logs/
#   - This orchestrator log at /tmp/inc4_logs/run_inc4_all.log
#
# NB: if any sub-dispatch fails, the script aborts (set -e) leaving partial
# results. Inspect /tmp/inc4_logs/ to diagnose.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

LOG_DIR=/tmp/inc4_logs
mkdir -p "$LOG_DIR"
MASTER_LOG="$LOG_DIR/run_inc4_all.log"

exec > >(tee -a "$MASTER_LOG") 2>&1

echo "════════════════════════════════════════════════════════════════════"
echo "[run_inc4_all] STARTED at $(date -u +%FT%TZ)"
echo "[run_inc4_all] cwd: $(pwd)"
echo "════════════════════════════════════════════════════════════════════"

DISPATCH=a4/pos/dispatch_audit.sh
M=a4/pos/manifests

# Node pools (per POS_PLAYBOOK §3.1 + current Inc 4 reservation 1747)
FLARE_ONLY=(flare)
POOL_5=(octorand opulous polynize algofi meld)
TIER_S_5=(flare octorand opulous polynize algofi)

# Helper: emit phase banner with timestamp
phase() {
    echo ""
    echo "════════════════════════════════════════════════════════════════════"
    echo "[run_inc4_all] $1  $(date -u +%FT%TZ)"
    echo "════════════════════════════════════════════════════════════════════"
}

# Phase 1: b8_seq — 5 sub-dispatches on flare (template handles slicing)
phase "PHASE 1 / b8_seq — 5 variants sequential on flare (~25 min)"
bash "$DISPATCH" "$M/pos_audit_b8_seq.json" "${FLARE_ONLY[@]}"

# Phase 2a: b8_par — 5 jobs on 5 nodes (1 dispatch, round-robin)
phase "PHASE 2a / b8_par — 5 variants parallel on 5 nodes (~10 min)"
bash "$DISPATCH" "$M/pos_audit_b8_par.json" "${POOL_5[@]}"

# Phase 2b: b12_1
phase "PHASE 2b / b12_in1_1_in4_1 — alternate input (~10 min)"
bash "$DISPATCH" "$M/pos_audit_b12_in1_1_in4_1.json" "${POOL_5[@]}"

# Phase 2c: b12_100
phase "PHASE 2c / b12_in1_100_in4_100 — alternate input (~10 min)"
bash "$DISPATCH" "$M/pos_audit_b12_in1_100_in4_100.json" "${POOL_5[@]}"

# Phase 3: b11 — scale stress on 5 Tier S nodes
phase "PHASE 3 / b11 — N=500 scale stress on 5 Tier S nodes (~25 min)"
bash "$DISPATCH" "$M/pos_audit_b11.json" "${TIER_S_5[@]}"

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "[run_inc4_all] ALL PHASES COMPLETE  $(date -u +%FT%TZ)"
echo "════════════════════════════════════════════════════════════════════"
echo "DBs on POS:"
echo "  /srv/testbed/results/ivgreiff/a4/pos_audit_b8_seq/  (5 run_dirs × 1 DB each)"
echo "  /srv/testbed/results/ivgreiff/a4/pos_audit_b8_par/  (1 run_dir × 5 DBs)"
echo "  /srv/testbed/results/ivgreiff/a4/pos_audit_b11/     (1 run_dir × 5 DBs)"
echo "  /srv/testbed/results/ivgreiff/a4/pos_audit_b12_in1_1_in4_1/    (1 run_dir × 5 DBs)"
echo "  /srv/testbed/results/ivgreiff/a4/pos_audit_b12_in1_100_in4_100/ (1 run_dir × 5 DBs)"
echo ""
echo "Per-dispatch logs:  $LOG_DIR/"
echo "Master log:         $MASTER_LOG"
