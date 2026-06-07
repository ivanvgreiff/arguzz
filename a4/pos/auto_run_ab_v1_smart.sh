#!/bin/bash
# ==============================================================================
# IV.POS.5 SMART auto-runner (v3: reservation-aware)
#
# Strict superset of auto_run_ab_v1.sh. The ONLY behavioral difference: BEFORE
# launching each dispatch, we WAIT for a calendar reservation owned by the
# current user, covering all NODES, with at least MIN_RES_HR hours of effective
# remaining time, to be ACTIVE. This eliminates the d2->d3 / d3->d4 / d4->d5
# transition problem where the OLD runner would launch the next dispatch
# against a soon-to-expire reservation and lose 5+ hours of compute.
#
# WHY THIS EXISTS:
#   Discovered Jun 7 03:00 CEST that POS allocations PERSIST past calendar
#   event end_date when a follow-up reservation for the same nodes/owner
#   immediately succeeds (Scenario A confirmed for d1->d2). However, this is
#   sample size of 1. To be safe, we never start a dispatch unless we have
#   the FULL ~5.5hr of fresh reservation time available.
#
# USAGE:
#   On coinbase, inside tmux:
#     tmux new -s ivpos5_smart
#     cd ~/arguzz
#     bash a4/pos/auto_run_ab_v1_smart.sh [START_AT] 2>&1 | tee /tmp/pos_ab_v1/AUTORUN_SMART.log
#     # Detach: Ctrl+B d. Reconnect any time: tmux attach -t ivpos5_smart
#
#   START_AT (optional): dispatch id to start from, e.g. "d3" to skip d1+d2.
#                        Defaults to "d1".
#
# CONFIGURATION (env overrides):
#   MIN_RES_HR=5.5   minimum remaining hours required before launching a dispatch
#   POLL_SEC=300     seconds between reservation rechecks while waiting
#   NODES="flare octorand opulous"
#   BUNDLE=...
#
# PRE-REQUISITES:
#   You manually create one calendar reservation per dispatch via the WEB
#   CALENDAR UI. As old reservations expire, slots free up for new ones (2
#   future-entries cap means you always have at most 2 reservations queued).
#   The smart runner SLEEPS gracefully if no valid reservation is found yet
#   (logs "no valid reservation, recheck in ${POLL_SEC}s" every 5 min).
#
# OUTPUTS: same as auto_run_ab_v1.sh (under /tmp/pos_ab_v1/).
# ==============================================================================

set -uo pipefail

# ---------- configuration ----------
LOG_DIR="/tmp/pos_ab_v1"
BUNDLE="${BUNDLE:-$HOME/a4_campaign_b169e76c7b1c.tar.gz}"
NODES="${NODES:-flare octorand opulous}"
ALLOC_DURATION="${ALLOC_DURATION:-0}"
MIN_RES_HR="${MIN_RES_HR:-5.5}"
POLL_SEC="${POLL_SEC:-300}"
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

# ---------- pre-flight banner ----------
log "================================================================"
log "IV.POS.5 SMART AUTO-RUNNER v3 starting"
log "================================================================"
log "  LOG_DIR          = $LOG_DIR"
log "  BUNDLE           = $BUNDLE"
log "  NODES            = $NODES"
log "  ALLOC_DURATION   = $ALLOC_DURATION"
log "  MIN_RES_HR       = $MIN_RES_HR  (need this much reservation time before launching)"
log "  POLL_SEC         = $POLL_SEC  (seconds between reservation rechecks)"
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

log ""
log "  Current calendar entries for $USER_NAME:"
pos calendar list -j 2>/dev/null | python3 -c "
import json, sys
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
    local node_table
    node_table=$(pos nodes list 2>/dev/null)
    for n in $NODES; do
        local row alloc
        row=$(echo "$node_table" | awk -v n="$n" '$1==n {print; exit}')
        alloc=$(echo "$row" | awk '{print $4}')
        log "    $n: alloc=$alloc"
    done
}

# Print one of:
#   ACTIVE                - a reservation is active right now AND has >= MIN_RES_HR remaining
#   WAIT <ts> <iso>       - the earliest qualifying reservation starts at <ts> (epoch) / <iso>
#   NONE                  - no qualifying reservation exists at all
# A "qualifying" reservation:
#   - owned by USER_NAME
#   - nodes superset of NODES (all our nodes are covered by this single entry)
#   - effective time remaining (end_date - max(start_date, now)) >= MIN_RES_HR
find_qualifying_reservation() {
    local now_epoch
    now_epoch=$(date +%s)
    local min_seconds
    min_seconds=$(awk -v h="$MIN_RES_HR" 'BEGIN { printf "%d", h * 3600 }')

    pos calendar list -j 2>/dev/null | NODES="$NODES" USER_NAME="$USER_NAME" python3 -c "
import json, sys, os, datetime
nodes = set(os.environ['NODES'].split())
user = os.environ['USER_NAME']
now_ts = $now_epoch
min_sec = $min_seconds

def parse_iso(s):
    # POS returns 'YYYY-MM-DD HH:MM:SS' or ISO; handle both
    s2 = s.replace('T', ' ').split('+')[0].split('Z')[0]
    return datetime.datetime.strptime(s2[:19], '%Y-%m-%d %H:%M:%S').timestamp()

try:
    entries = json.load(sys.stdin)
except Exception:
    print('NONE')
    sys.exit(0)

best_start = None
best_iso = None
for e in entries:
    if e.get('owner') != user:
        continue
    e_nodes = set(e.get('nodes') or [])
    if not nodes <= e_nodes:
        continue
    try:
        s = parse_iso(e['start_date'])
        en = parse_iso(e['end_date'])
    except Exception:
        continue
    eff_start = max(s, now_ts)
    if en - eff_start < min_sec:
        continue
    if best_start is None or s < best_start:
        best_start = s
        best_iso = e['start_date']

if best_start is None:
    print('NONE')
elif best_start <= now_ts:
    print('ACTIVE')
else:
    print(f'WAIT {int(best_start)} {best_iso}')
"
}

# Returns 0 if ANY previous dispatch's fuzzer is still running on our nodes
# (i.e., a pos_ab_v1_dN command owned by us in status=running on a target node).
# Returns 1 otherwise. Used to avoid killing in-flight work if the user starts
# the smart runner while a previous dispatch is still active.
#
# CRITICAL BASH QUOTING NOTE: the original version of this function had
# `noderx="^("node_re")$"` (no $ in front of node_re) which Bash parses as
# string concatenation with the LITERAL word "node_re" in the middle, NOT
# the variable. The awk regex then never matched any real node, so the
# function ALWAYS returned false. This bug killed the d2 run at Jun 7 03:17
# CEST when the smart runner was launched with d3 while d2 was still running.
# Fix: build the awk regex in a Bash variable first, then pass it directly.
has_previous_dispatch_running() {
    local node_re node_regex
    node_re=$(echo "$NODES" | tr ' ' '|')
    node_regex="^(${node_re})\$"
    local count
    count=$(pos commands list -a 2>/dev/null | awk -v user="$USER_NAME" -v noderx="$node_regex" '
        $1==user && $5=="running" && $3 ~ noderx && $2 ~ /pos_ab_v1_d/
    ' | wc -l)
    [[ $count -gt 0 ]]
}

# Block until no previous dispatch's fuzzer is running on our nodes.
wait_for_previous_dispatch_to_finish() {
    local d_id="$1"
    local announced=0
    while has_previous_dispatch_running; do
        if [[ $announced -eq 0 ]]; then
            log "    [prev-dispatch-check] a previous dispatch's fuzzer is still running on our nodes"
            log "    [prev-dispatch-check] WAITING for it to finish before touching state (poll=${POLL_SEC}s)"
            status "dispatch=$d_id status=waiting_for_previous since=$(ts) nodes=\"$NODES\""
            announced=1
        fi
        sleep "$POLL_SEC"
    done
    if [[ $announced -eq 1 ]]; then
        log "    [prev-dispatch-check] previous dispatch finished; proceeding"
    else
        log "    [prev-dispatch-check] no previous dispatch active; proceeding"
    fi
}

# Block until a qualifying reservation is ACTIVE. Logs every poll iteration.
# Returns when a reservation is active (and we expect to launch immediately).
wait_for_qualifying_reservation() {
    local d_id="$1"
    while true; do
        local now_epoch
        now_epoch=$(date +%s)
        local result
        result=$(find_qualifying_reservation)
        case "$result" in
            ACTIVE)
                log "    [reservation-check] ACTIVE: a qualifying reservation is active and has >= ${MIN_RES_HR}h remaining"
                return 0
                ;;
            WAIT\ *)
                local target_ts target_iso
                target_ts=$(echo "$result" | awk '{print $2}')
                target_iso=$(echo "$result" | awk '{for(i=3;i<=NF;i++) printf "%s%s", $i, (i<NF?" ":"")}')
                local wait_sec=$((target_ts - now_epoch + 10))   # +10s buffer for POS to activate
                local wait_min=$((wait_sec / 60))
                log "    [reservation-check] WAIT: earliest qualifying reservation starts at $target_iso CEST (in ${wait_min}m)"
                if (( wait_sec <= POLL_SEC )); then
                    log "    [reservation-check] sleeping ${wait_sec}s until reservation start"
                    sleep "$wait_sec"
                else
                    log "    [reservation-check] sleeping ${POLL_SEC}s (poll interval); will recheck"
                    sleep "$POLL_SEC"
                fi
                ;;
            NONE)
                log "    [reservation-check] NONE: no qualifying reservation found"
                log "    [reservation-check] CREATE one via the web calendar UI (need >= ${MIN_RES_HR}h, nodes: $NODES)"
                log "    [reservation-check] rechecking in ${POLL_SEC}s"
                status "dispatch=$d_id status=waiting_for_reservation since=$(ts) need_hours=$MIN_RES_HR nodes=\"$NODES\""
                sleep "$POLL_SEC"
                ;;
            *)
                log "    [reservation-check] WARN: unexpected output '$result'; rechecking in ${POLL_SEC}s"
                sleep "$POLL_SEC"
                ;;
        esac
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

    # NEW: wait for any previous dispatch's fuzzer to finish BEFORE we touch
    # any allocation state. Otherwise the pre-flight free would kill it.
    log "  [prev-dispatch-wait] checking for in-flight fuzzers on $NODES"
    wait_for_previous_dispatch_to_finish "$d_id"

    # NEW: wait for a qualifying reservation BEFORE doing anything that touches
    # state. This is the entire reason the smart runner exists.
    log "  [smart-wait] ensuring a reservation with >= ${MIN_RES_HR}h remaining is active..."
    wait_for_qualifying_reservation "$d_id"

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
        echo "IV.POS.5 smart auto-run summary written at $(ts)"
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
    log "SMART AUTO-RUNNER exiting at $(ts)"
}
trap on_exit EXIT

# ---------- main loop ----------
status "smart auto-runner started PID=$$ at $(ts)"
TOTAL_RC=0
for ((i=START_IDX; i<${#ALL_DISPATCHES[@]}; i++)); do
    d="${ALL_DISPATCHES[$i]}"
    if ! run_one_dispatch "$d"; then
        TOTAL_RC=1
        log ""
        log "STOPPING: dispatch $d failed. Investigate, then resume with:"
        log "  bash a4/pos/auto_run_ab_v1_smart.sh $d"
        if (( i + 1 < ${#ALL_DISPATCHES[@]} )); then
            log "(or skip past it: bash a4/pos/auto_run_ab_v1_smart.sh ${ALL_DISPATCHES[$((i+1))]})"
        fi
        break
    fi
done

log ""
log "================================================================"
if [[ $TOTAL_RC -eq 0 ]]; then
    log "ALL DISPATCHES (from $START_AT onward) COMPLETE"
    status "smart auto-runner COMPLETE at $(ts)"
else
    log "SMART AUTO-RUNNER STOPPED on failure"
    status "smart auto-runner STOPPED at $(ts) on dispatch failure"
fi
log "================================================================"

exit $TOTAL_RC
