#!/usr/bin/env bash
# a4/pos/dispatch_audit.sh — Universal POS dispatch wrapper for Inc 4+ audits.
#
# PURPOSE
#   Single re-usable entry point for dispatching ANY audit manifest. Handles
#   both single-dispatch and multi-dispatch cases automatically.
#
# WHY THIS EXISTS (POS_PLAYBOOK §12.36)
#   `dispatch_pos.py` assumes ONE job per node per allocation. The dispatcher's
#   per-assignment `set_variables` overwrites itself when multiple jobs land
#   on the same node, so only the LAST job's variables survive. Multi-job
#   manifests (e.g. pos_audit_b8_seq.json has 5 jobs) that are dispatched on
#   1 node will silently corrupt — all 5 commands run with the last job's
#   strategy and write to the same DB filename. Verified Jun 13 07:48 CEST:
#   only `cTS_semantic_v2.db` was written for a 5-variant b8_seq run.
#
# HOW IT WORKS
#   - If jobs ≤ nodes  → SINGLE dispatch (round-robin: jobs[i] → nodes[i % len]).
#   - If jobs >  nodes → MULTI dispatch (slice manifest per-job, one dispatch
#                        per variant on the FIRST node; nodes 2..N ignored).
#
# USAGE
#   bash a4/pos/dispatch_audit.sh <manifest> <node1> [node2] ...
#
# ENV
#   ALLOC_DURATION   — minutes; default 0 (claim pre-existing calendar entry)
#                      Set to >0 only if you want a NEW calendar entry (uses
#                      one of your 2 calendar-entry slots, per §12.28).
#   BUNDLE           — explicit bundle path; default = newest ~/a4_campaign_*.tar.gz
#   DISPATCH_LOG_DIR — where to write per-dispatch logs; default /tmp/inc4_logs
#
# EXAMPLES
#   # 5 jobs × 1 node → 5 sequential dispatches on flare (b8_seq)
#   bash a4/pos/dispatch_audit.sh a4/pos/manifests/pos_audit_b8_seq.json flare
#
#   # 5 jobs × 5 nodes → 1 dispatch, round-robin (b8_par, b11, b12_*)
#   bash a4/pos/dispatch_audit.sh a4/pos/manifests/pos_audit_b8_par.json \
#       flare octorand opulous polynize algofi
#
# SAFETY
#   - Bails on any sub-dispatch failure (exit non-zero), preserving partial DBs.
#   - Each sub-dispatch is logged to $DISPATCH_LOG_DIR/<manifest>_<stem>.log
#     for post-mortem (audit script wall-time check, error inspection).
#   - Reads --allocation-duration via env so the same template works for both
#     pre-reserved (ALLOC_DURATION=0, default) and ad-hoc (ALLOC_DURATION=120)
#     calendar regimes — see POS_PLAYBOOK §12.29 + §12.37.

set -euo pipefail

# ----- args & validation -------------------------------------------------
MANIFEST="${1:-}"
shift || true
NODES=("$@")

if [[ -z "$MANIFEST" || ! -f "$MANIFEST" ]]; then
    echo "ERROR: manifest not found: '${MANIFEST}'" >&2
    echo "Usage: bash a4/pos/dispatch_audit.sh <manifest.json> <node1> [node2] ..." >&2
    exit 2
fi
if [[ ${#NODES[@]} -lt 1 ]]; then
    echo "ERROR: provide at least one node" >&2
    exit 2
fi

# ----- POS venv check ----------------------------------------------------
if ! python -c "import poslib" 2>/dev/null; then
    echo "ERROR: poslib not importable. Activate the POS venv first:" >&2
    echo "  source /srv/testbed/pos/cli/venv3/bin/activate" >&2
    exit 1
fi

# ----- bundle discovery --------------------------------------------------
BUNDLE="${BUNDLE:-}"
if [[ -z "$BUNDLE" ]]; then
    BUNDLE=$(ls -t ~/a4_campaign_*.tar.gz 2>/dev/null | head -1 || true)
fi
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: no bundle. Expected ~/a4_campaign_*.tar.gz (or set BUNDLE=)" >&2
    exit 1
fi

# ----- logs --------------------------------------------------------------
LOG_DIR="${DISPATCH_LOG_DIR:-/tmp/inc4_logs}"
mkdir -p "$LOG_DIR"

# ----- job-count discovery -----------------------------------------------
NJOBS=$(python3 -c "import json; print(len(json.load(open('$MANIFEST'))['jobs']))")
NNODES=${#NODES[@]}
MANIFEST_STEM=$(basename "$MANIFEST" .json)

ALLOC="${ALLOC_DURATION:-0}"

echo "════════════════════════════════════════════════════════════════════"
echo "[dispatch_audit] manifest:  $MANIFEST  ($NJOBS jobs)"
echo "[dispatch_audit] nodes:     ${NODES[*]}  ($NNODES nodes)"
echo "[dispatch_audit] bundle:    $BUNDLE"
echo "[dispatch_audit] alloc_dur: $ALLOC  (0 = claim pre-existing calendar entry)"
echo "[dispatch_audit] log_dir:   $LOG_DIR"
echo "[dispatch_audit] started:   $(date -u +%FT%TZ)"
echo "════════════════════════════════════════════════════════════════════"

# ----- dispatch logic ----------------------------------------------------
if (( NJOBS <= NNODES )); then
    # CASE 1: SINGLE DISPATCH — jobs ≤ nodes, dispatch_pos round-robins safely.
    echo "[dispatch_audit] MODE: SINGLE — 1 dispatch, jobs round-robin to nodes"
    LOG="$LOG_DIR/${MANIFEST_STEM}.log"
    echo "[dispatch_audit] log: $LOG"
    python -m a4.pos.dispatch_pos \
        --manifest "$MANIFEST" \
        --bundle "$BUNDLE" \
        --nodes "${NODES[@]}" \
        --allocation-duration "$ALLOC" \
        --await 2>&1 | tee "$LOG"
else
    # CASE 2: MULTI-DISPATCH — jobs > nodes. Slice manifest, dispatch each
    # variant on a single node sequentially. Workaround for §12.36.
    NODE0="${NODES[0]}"
    echo "[dispatch_audit] MODE: MULTI — $NJOBS sub-dispatches on $NODE0 (sequential)"
    if (( NNODES > 1 )); then
        echo "[dispatch_audit] NOTE: $((NNODES-1)) extra nodes provided; ignored — multi-dispatch is 1-node sequential"
    fi
    STRATEGIES=$(python3 -c "
import json
m = json.load(open('$MANIFEST'))
print(chr(10).join(j['strategy'] for j in m['jobs']))
")
    while IFS= read -r STRATEGY; do
        [[ -z "$STRATEGY" ]] && continue
        echo ""
        echo "──────────────────────────────────────────────────────────────────"
        echo "[dispatch_audit] sub-dispatch: variant=$STRATEGY  node=$NODE0  $(date -u +%FT%TZ)"
        echo "──────────────────────────────────────────────────────────────────"
        TMP_MANIFEST=$(mktemp --suffix=.json)
        python3 -c "
import json
m = json.load(open('$MANIFEST'))
m['jobs'] = [j for j in m['jobs'] if j['strategy'] == '$STRATEGY']
assert len(m['jobs']) == 1, 'variant $STRATEGY not found exactly once in manifest'
print(json.dumps(m, indent=2))
" > "$TMP_MANIFEST"
        LOG="$LOG_DIR/${MANIFEST_STEM}__${STRATEGY}.log"
        echo "[dispatch_audit] log: $LOG"
        python -m a4.pos.dispatch_pos \
            --manifest "$TMP_MANIFEST" \
            --bundle "$BUNDLE" \
            --nodes "$NODE0" \
            --allocation-duration "$ALLOC" \
            --await 2>&1 | tee "$LOG"
        rm -f "$TMP_MANIFEST"
    done <<< "$STRATEGIES"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "[dispatch_audit] DONE: $MANIFEST"
echo "[dispatch_audit] finished: $(date -u +%FT%TZ)"
echo "════════════════════════════════════════════════════════════════════"
