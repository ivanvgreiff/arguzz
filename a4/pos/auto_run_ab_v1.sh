#!/bin/bash
# ==============================================================================
# IV.POS.5 fire-and-forget auto-runner (v2: 3-parallel, N=6000, 5 dispatches)
#
# Runs all 5 by-seed dispatches (a4/pos/manifests/ab_v1/) back-to-back in a
# single tmux session on coinbase. Each dispatch claims flare+octorand+opulous
# (Tier S EPYC 9354 x3) via PRE-EXISTING calendar reservations (you create
# them through the web calendar UI; the dispatcher uses --allocation-duration 0
# so it does NOT create new entries that would hit the 2-future-entries cap).
#
# Each dispatch: ~5.1 hr wall (5 hr compute + ~10 min setup). Fits inside one
# 6-hr reservation with ~54 min buffer. 5 dispatches = 5 reservations = ~30 hr
# clock time (one dispatch per reservation; runner waits for the next
# reservation window to begin if the previous dispatch finishes early).
#
# USAGE:
#   On coinbase, inside tmux:
#     tmux new -s ivpos5
#     cd ~/arguzz
#     bash a4/pos/auto_run_ab_v1.sh [START_AT] 2>&1 | tee /tmp/pos_ab_v1/AUTORUN.log
#     # Detach: Ctrl+B d. Reconnect any time: tmux attach -t ivpos5
#
#   START_AT (optional): dispatch id to start from, e.g. "d3" to skip d1+d2.
#                        Defaults to "d1".
#
# PRE-REQUISITES (you must do these via the WEB CALENDAR UI before launching):
#   1. Reserve flare+octorand+opulous as a SINGLE entry, 6 hr block.
#   2. Reserve flare+octorand+opulous as a SECOND entry, 6 hr block, contiguous.
#   3. As the campaign runs, every ~6 hr the oldest entry expires; immediately
#      reserve a NEW 6-hr entry for the same 3 nodes (the cap is 2 FUTURE
#      entries, so you always have one running + one queued).
#   4. Total reservations needed: 5 (one per dispatch). You make 3 extras
#      during the run (~30 sec each through the UI).
#
# OUTPUTS (all under /tmp/pos_ab_v1/):
#   AUTORUN.log                 Combined log of the whole campaign
#   STATUS.txt                  Single-line current state
#   pos_ab_v1_dN.log            Per-dispatch dispatcher output
#   pos_ab_v1_dN.json           Per-dispatch dispatch_manifest output
#   pos_ab_v1_dN.OK             Touched on successful completion of dN
#   pos_ab_v1_dN.FAIL           Touched on failure of dN
#   SUMMARY.txt                 Final summary written at end (or on abort)
#
# INSPECTION (from any SSH session, no need to attach tmux):
#   cat /tmp/pos_ab_v1/STATUS.txt
#   ls /tmp/pos_ab_v1/
#   tail -F /tmp/pos_ab_v1/AUTORUN.log
#   tail -F /tmp/pos_ab_v1/pos_ab_v1_d3.log
#   tmux attach -t ivpos5   (Ctrl+B d to detach)
#
# RESUME after a failure:
#   1. cat /tmp/pos_ab_v1/pos_ab_v1_d3.log   (inspect)
#   2. Fix root cause (refresh reservations, free stuck allocs, etc.)
#   3. bash a4/pos/auto_run_ab_v1.sh d3      (resume from the failed dispatch)
# ==============================================================================

set -uo pipefail

# ---------- configuration (override via env) ----------
LOG_DIR="/tmp/pos_ab_v1"
BUNDLE="${BUNDLE:-$HOME/a4_campaign_b169e76c7b1c.tar.gz}"
# Default nodes (all Tier S EPYC 9354). Override via:
#   NODES="flare octorand opulous" bash a4/pos/auto_run_ab_v1.sh
NODES="${NODES:-flare octorand opulous}"
# Reservation-based dispatch: do NOT create new calendar entries.
ALLOC_DURATION="${ALLOC_DURATION:-0}"
START_AT="${1:-d1}"
ALL_DISPATCHES=(d1 d2 d3 d4 d5)
USER_NAME="${USER:-$(whoami)}"

# ---------- setup ----------
mkdir -p "$LOG_DIR"
REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT" || { echo "FATAL: cannot cd to repo root"; exit 2; }

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { echo "[$(ts)] $*"; }
status() { echo "$*" > "$LOG_DIR/STATUS.txt"; }

# ---------- pre-flight ----------
log "================================================================"
log "IV.POS.5 AUTO-RUNNER v2 starting"
log "================================================================"
log "  LOG_DIR          = $LOG_DIR"
log "  BUNDLE           = $BUNDLE"
log "  NODES            = $NODES"
log "  ALLOC_DURATION   = $ALLOC_DURATION  (0 = use existing calendar entries)"
log "  START_AT         = $START_AT"
log "  USER             = $USER_NAME"
log "  PID              = $$"
log ""

if [[ ! -f "$BUNDLE" ]]; then
    log "FATAL: bundle not found at $BUNDLE"
    exit 2
fi
log "  bundle size = $(du -h "$BUNDLE" | cut -f1)"

if ! command -v pos &>/dev/null; then
    log "FATAL: 'pos' CLI not on PATH. Run 'source /srv/testbed/pos/cli/venv3/bin/activate' first."
    exit 2
fi

for d in "${ALL_DISPATCHES[@]}"; do
    m="a4/pos/manifests/ab_v1/pos_ab_v1_${d}.json"
    if [[ ! -f "$m" ]]; then
        log "FATAL: missing manifest $m"
        exit 2
    fi
done
log "  all 5 manifests present"

# Show current calendar so user can verify enough reservations are queued
log ""
log "  Current calendar entries for $USER_NAME:"
pos calendar list -j 2>/dev/null | python3 -c "
import json, sys, datetime
try:
    entries = json.load(sys.stdin)
except Exception as e:
    print(f'    (could not parse calendar JSON: {e})')
    sys.exit(0)
mine = [e for e in entries if e.get('owner') == '$USER_NAME']
if not mine:
    print('    NONE')
else:
    for e in mine:
        print(f\"    id={e['id']} nodes={e.get('nodes')} {e['start_date']} -> {e['end_date']}\")
" 2>&1
log ""

# Find the index of START_AT
START_IDX=0
for i in "${!ALL_DISPATCHES[@]}"; do
    if [[ "${ALL_DISPATCHES[$i]}" == "$START_AT" ]]; then
        START_IDX=$i
        break
    fi
done
log "  starting from dispatch index $START_IDX (${ALL_DISPATCHES[$START_IDX]})"
log ""

# ---------- helpers ----------
free_all_my_allocations() {
    local lines
    lines=$(pos allocations list -f owner=$USER_NAME 2>/dev/null | tail -n +3) || true
    if [[ -z "$lines" ]]; then
        return 0
    fi
    while IFS= read -r line; do
        local alloc_id
        alloc_id=$(echo "$line" | awk '{print $1}')
        if [[ -n "$alloc_id" ]]; then
            log "    freeing allocation: $alloc_id"
            pos allocations free "$alloc_id" 2>&1 | sed 's/^/      /' || true
        fi
    done <<< "$lines"
}

check_nodes_status() {
    # Print "node alloc_status" for each node we'd use.
    local node_table
    node_table=$(pos nodes list 2>/dev/null)
    for n in $NODES; do
        local row alloc
        row=$(echo "$node_table" | awk -v n="$n" '$1==n {print; exit}')
        alloc=$(echo "$row" | awk '{print $4}')
        log "    $n: alloc=$alloc"
    done
}

run_one_dispatch() {
    local d_id="$1"
    local manifest="a4/pos/manifests/ab_v1/pos_ab_v1_${d_id}.json"
    local log_file="$LOG_DIR/pos_ab_v1_${d_id}.log"
    local out_file="$LOG_DIR/pos_ab_v1_${d_id}.json"
    local ok_marker="$LOG_DIR/pos_ab_v1_${d_id}.OK"
    local fail_marker="$LOG_DIR/pos_ab_v1_${d_id}.FAIL"

    rm -f "$ok_marker" "$fail_marker"

    log ""
    log "================================================================"
    log "DISPATCH $d_id starting"
    log "  manifest = $manifest"
    log "  nodes    = $NODES"
    log "================================================================"
    status "dispatch=$d_id status=preparing started_at=$(ts)"

    log "  pre-flight: freeing any owned allocations"
    free_all_my_allocations
    sleep 3

    log "  pre-flight: node status"
    check_nodes_status

    status "dispatch=$d_id status=running started_at=$(ts) nodes=\"$NODES\""
    log "  launching at $(ts)"
    log "  tail -F $log_file in another session to see live progress"
    local start_epoch
    start_epoch=$(date +%s)

    # PYTHONUNBUFFERED=1 + python -u so stdout/stderr flush per-line.
    # Without these, Python block-buffers ~4KB of output when redirected to a
    # file, which makes the dispatcher appear hung for 10+ min during 3-node
    # boot/setup (every print just sits in the buffer). Verified Jun 6 21:00.
    PYTHONUNBUFFERED=1 python -u -m a4.pos.dispatch_pos \
        --manifest "$manifest" \
        --bundle "$BUNDLE" \
        --nodes $NODES \
        --allocation-duration "$ALLOC_DURATION" \
        --await \
        --out "$out_file" \
        >"$log_file" 2>&1
    local rc=$?

    local end_epoch elapsed elapsed_str
    end_epoch=$(date +%s)
    elapsed=$((end_epoch - start_epoch))
    elapsed_str=$(printf '%dh%02dm%02ds' $((elapsed/3600)) $(((elapsed%3600)/60)) $((elapsed%60)))

    log "  post-dispatch: freeing allocations"
    free_all_my_allocations

    if [[ $rc -eq 0 ]]; then
        touch "$ok_marker"
        log "DISPATCH $d_id OK (rc=$rc, wall=$elapsed_str)"
        status "dispatch=$d_id status=OK ended_at=$(ts) wall=$elapsed_str"
        return 0
    else
        touch "$fail_marker"
        log "DISPATCH $d_id FAIL (rc=$rc, wall=$elapsed_str)"
        log "  inspect: cat $log_file"
        status "dispatch=$d_id status=FAIL ended_at=$(ts) wall=$elapsed_str rc=$rc"
        return $rc
    fi
}

write_final_summary() {
    local summary="$LOG_DIR/SUMMARY.txt"
    {
        echo "IV.POS.5 auto-run summary written at $(ts)"
        echo "================================================================"
        echo ""
        printf '%-6s %-8s %-12s\n' "DID" "STATUS" "MARKER"
        printf '%-6s %-8s %-12s\n' "---" "------" "------"
        for d in "${ALL_DISPATCHES[@]}"; do
            if [[ -f "$LOG_DIR/pos_ab_v1_${d}.OK" ]]; then
                printf '%-6s %-8s %s\n' "$d" "OK" "${LOG_DIR}/pos_ab_v1_${d}.OK"
            elif [[ -f "$LOG_DIR/pos_ab_v1_${d}.FAIL" ]]; then
                printf '%-6s %-8s %s\n' "$d" "FAIL" "${LOG_DIR}/pos_ab_v1_${d}.FAIL"
            else
                printf '%-6s %-8s %s\n' "$d" "SKIPPED" "(not attempted)"
            fi
        done
        echo ""
        echo "Result DBs (on coinbase):"
        echo "  /srv/testbed/results/$USER_NAME/a4/pos_ab_v1_d*/"
        echo ""
        echo "Per-dispatch logs:"
        ls "$LOG_DIR"/pos_ab_v1_d*.log 2>/dev/null || true
    } > "$summary"
    log ""
    log "SUMMARY written to $summary:"
    cat "$summary" | sed 's/^/  /'
}

on_exit() {
    write_final_summary
    log "AUTO-RUNNER exiting at $(ts)"
}
trap on_exit EXIT

# ---------- main loop ----------
status "auto-runner started PID=$$ at $(ts)"
TOTAL_RC=0
for ((i=START_IDX; i<${#ALL_DISPATCHES[@]}; i++)); do
    d="${ALL_DISPATCHES[$i]}"
    if ! run_one_dispatch "$d"; then
        TOTAL_RC=1
        log ""
        log "STOPPING: dispatch $d failed. Investigate, then resume with:"
        log "  bash a4/pos/auto_run_ab_v1.sh $d"
        if (( i + 1 < ${#ALL_DISPATCHES[@]} )); then
            log "(or skip past it: bash a4/pos/auto_run_ab_v1.sh ${ALL_DISPATCHES[$((i+1))]})"
        fi
        break
    fi
done

log ""
log "================================================================"
if [[ $TOTAL_RC -eq 0 ]]; then
    log "ALL DISPATCHES (from $START_AT onward) COMPLETE"
    status "auto-runner COMPLETE at $(ts)"
else
    log "AUTO-RUNNER STOPPED on failure"
    status "auto-runner STOPPED at $(ts) on dispatch failure"
fi
log "================================================================"

exit $TOTAL_RC
