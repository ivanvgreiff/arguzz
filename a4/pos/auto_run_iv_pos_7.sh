#!/bin/bash
# ==============================================================================
# IV.POS.7 (Phase 8) BATCHED-PARALLEL AUTO-RUNNER
#
# What this is
# ------------
#   Fire-and-forget orchestrator for ONE tier's worth of batches. Two copies of
#   this runner (one with --tier=s and one with --tier=a) execute INDEPENDENTLY
#   in two tmux sessions, dispatching their batches sequentially to disjoint
#   node sets. Together they cover all 50 IV.POS.7 jobs in ~35h wall.
#
#   See PHASE_8_PLAN.md §3 (batched-parallel design) and the dispatch plan at
#   a4/pos/manifests/iv_pos_7/_dispatch_plan.json for the variant-node mapping.
#
# Why two tiers / two runners
# ---------------------------
#   The POS testbed gives us 4 Tier-S EPYC 9354 nodes (flare, octorand, opulous,
#   polynize) and 4 Tier-A EPYC 7543 nodes (algofi, gard, goracle, zone). They
#   become available at different times (Tier-A held by another user until
#   03:00 UTC) so we can't treat all 8 as a single pool. By running 2 fully
#   independent runners we (a) start each tier the moment it becomes available
#   and (b) keep the orchestration simple (no cross-runner coordination).
#
#   Within a runner, batches are sequential. Within a batch, the 2-4 jobs fan
#   out to 2-4 nodes in parallel (round-robin from --nodes order, which mirrors
#   the node_label field in each manifest -> per-tier pinning is preserved).
#
# Pinning model (Pro-disclosure: PHASE_8_PLAN.md §3.2)
# ----------------------------------------------------
#   Each variant is pinned to exactly one node per tier. V2-V5 split their
#   10 seeds 7+3 across Tier-S/Tier-A; V1 runs 10 seeds entirely on Tier-A
#   spread across all 4 Tier-A nodes (race-immune, no MAB).
#
# USAGE (on coinbase, inside tmux)
# --------------------------------
#   # Tier-S runner (start as soon as Tier-S reservation is active):
#   tmux new -s ivpos7_ts
#   cd ~/arguzz
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   bash a4/pos/auto_run_iv_pos_7.sh --tier=s [--start-at=ts_b3]
#
#   # Tier-A runner (start after christer's reservation 1750 ends 03:00 UTC):
#   tmux new -s ivpos7_ta
#   cd ~/arguzz
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   bash a4/pos/auto_run_iv_pos_7.sh --tier=a [--start-at=ta_b3]
#
#   # Smoke run (validate end-to-end on any 5-node tier, ~3 min):
#   bash a4/pos/auto_run_iv_pos_7.sh --smoke
#
# OUTPUTS (per tier)
# ------------------
#   /tmp/iv_pos_7_<tier>/AUTORUN.log                full orchestrator log
#   /tmp/iv_pos_7_<tier>/STATUS.txt                 one-line current status
#   /tmp/iv_pos_7_<tier>/SUMMARY.txt                per-batch OK/FAIL on exit
#   /tmp/iv_pos_7_<tier>/<manifest_name>.log        per-batch dispatcher log
#   /tmp/iv_pos_7_<tier>/<manifest_name>.json       per-batch result file
#   /tmp/iv_pos_7_<tier>/<manifest_name>.OK         OK marker (rc=0 + DBs present)
#   /tmp/iv_pos_7_<tier>/<manifest_name>.FAIL       FAIL marker (otherwise)
#
# CONFIG (env overrides)
# ----------------------
#   BUNDLE=~/a4_campaign_iv_pos_7.tar.gz        the bundle to dispatch
#   MIN_RES_HR=5.5                              min effective remaining reservation
#   POLL_SEC=300                                reservation/dispatch recheck interval
#   ALLOC_DURATION=0                            0 = use existing calendar entry
#   NODES_TIER_S="flare octorand opulous polynize"     Tier-S node order
#   NODES_TIER_A="algofi gard goracle zone"            Tier-A node order
#   BACKUP_TIER_S="goracle algofi"              auto-substitute if a Tier-S node bricks
#   BACKUP_TIER_A="flare octorand"              auto-substitute if a Tier-A node bricks
# ==============================================================================

set -uo pipefail

# ---------- argument parsing ----------
TIER=""
START_AT=""
SMOKE=0

usage() {
    cat <<EOF
Usage: $0 --tier=<s|a> [--start-at=<batch_name>]
       $0 --smoke
       $0 --help

  --tier=s         run Tier-S batches (ts_b1..ts_b7 on flare/octorand/opulous/polynize)
  --tier=a         run Tier-A batches (ta_b1..ta_b6 on algofi/gard/goracle/zone)
  --start-at=NAME  resume from batch NAME, e.g. --start-at=ts_b3 (default: first batch)
  --smoke          run the N=20 smoke manifest only (~3 min on 5 nodes)
  --help           print this message and exit
EOF
}

for arg in "$@"; do
    case "$arg" in
        --tier=s|--tier=S) TIER=s ;;
        --tier=a|--tier=A) TIER=a ;;
        --start-at=*) START_AT="${arg#--start-at=}" ;;
        --smoke) SMOKE=1 ;;
        --help|-h) usage; exit 0 ;;
        *) echo "ERROR: unknown arg '$arg'"; usage; exit 2 ;;
    esac
done

if [[ $SMOKE -eq 0 && -z "$TIER" ]]; then
    echo "ERROR: must specify --tier=s OR --tier=a OR --smoke"
    usage
    exit 2
fi

# ---------- config ----------
BUNDLE="${BUNDLE:-$HOME/a4_campaign_iv_pos_7.tar.gz}"
ALLOC_DURATION="${ALLOC_DURATION:-0}"
MIN_RES_HR="${MIN_RES_HR:-5.5}"
POLL_SEC="${POLL_SEC:-300}"
NODES_TIER_S="${NODES_TIER_S:-flare octorand opulous polynize}"
NODES_TIER_A="${NODES_TIER_A:-algofi gard goracle zone}"
BACKUP_TIER_S="${BACKUP_TIER_S:-}"
BACKUP_TIER_A="${BACKUP_TIER_A:-}"
USER_NAME="${USER:-$(whoami)}"
RESULTS_MIRROR="/srv/testbed/results/$USER_NAME"
MANIFEST_DIR="a4/pos/manifests/iv_pos_7"

# Per-tier wiring
if [[ $SMOKE -eq 1 ]]; then
    TIER_TAG="smoke"
    NODES_RAW="${NODES_TIER_S} meld"
    BACKUP_RAW=""
    ALL_BATCHES=(pos_iv_pos_7_smoke)
elif [[ "$TIER" == "s" ]]; then
    TIER_TAG="tier_s"
    NODES_RAW="$NODES_TIER_S"
    BACKUP_RAW="$BACKUP_TIER_S"
    ALL_BATCHES=(ts_b1 ts_b2 ts_b3 ts_b4 ts_b5 ts_b6 ts_b7)
elif [[ "$TIER" == "a" ]]; then
    TIER_TAG="tier_a"
    NODES_RAW="$NODES_TIER_A"
    BACKUP_RAW="$BACKUP_TIER_A"
    ALL_BATCHES=(ta_b1 ta_b2 ta_b3 ta_b4 ta_b5 ta_b6)
fi

LOG_DIR="/tmp/iv_pos_7_${TIER_TAG}"
mkdir -p "$LOG_DIR"

# Convert NODES_RAW / BACKUP_RAW to arrays (avoids the IV.POS.5 word-split bug §12.42)
read -r -a NODES_ARR <<< "$NODES_RAW"
read -r -a BACKUP_ARR <<< "$BACKUP_RAW"

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT" || { echo "FATAL: cannot cd to repo root"; exit 2; }

ts() { date -u '+%Y-%m-%dT%H:%M:%SZ'; }
log() { echo "[$(ts)] $*"; }
status() { echo "$*" > "$LOG_DIR/STATUS.txt"; }

# ---------- pre-flight banner ----------
log "================================================================"
log "IV.POS.7 (Phase 8) BATCHED-PARALLEL AUTO-RUNNER starting"
log "================================================================"
log "  TIER_TAG       = $TIER_TAG ($([[ $SMOKE -eq 1 ]] && echo 'SMOKE' || echo "tier=$TIER"))"
log "  LOG_DIR        = $LOG_DIR"
log "  BUNDLE         = $BUNDLE"
log "  NODES          = ${NODES_ARR[*]}    (count=${#NODES_ARR[@]})"
log "  BACKUP_NODES   = ${BACKUP_ARR[*]:-<none>}  (count=${#BACKUP_ARR[@]})"
log "  ALLOC_DURATION = $ALLOC_DURATION (0 = use existing reservation)"
log "  MIN_RES_HR     = $MIN_RES_HR"
log "  POLL_SEC       = $POLL_SEC"
log "  START_AT       = ${START_AT:-<first batch>}"
log "  ALL_BATCHES    = ${ALL_BATCHES[*]}"
log "  USER           = $USER_NAME"
log "  ALLOWED_OWNERS = ${ALLOWED_OWNERS:-$USER_NAME} (calendar-entry owners that count as qualifying)"
log "  PID            = $$"
log ""

if [[ ! -f "$BUNDLE" ]]; then
    log "FATAL: bundle not found at $BUNDLE"
    log "  Pass via BUNDLE=/path/to/a4_campaign_iv_pos_7_<sha>.tar.gz"
    exit 2
fi
log "  bundle size = $(du -h "$BUNDLE" | cut -f1)"

if ! command -v pos &>/dev/null; then
    log "FATAL: 'pos' CLI not on PATH. Run 'source /srv/testbed/pos/cli/venv3/bin/activate' first."
    exit 2
fi

for b in "${ALL_BATCHES[@]}"; do
    m="$MANIFEST_DIR/pos_iv_pos_7_${b}.json"
    # smoke is named pos_iv_pos_7_smoke (no extra prefix)
    if [[ "$b" == "pos_iv_pos_7_smoke" ]]; then
        m="$MANIFEST_DIR/pos_iv_pos_7_smoke.json"
    fi
    if [[ ! -f "$m" ]]; then
        log "FATAL: missing manifest $m"
        log "  Generate via: python3 a4/pos/generate_iv_pos_7_manifests.py"
        exit 2
    fi
done
log "  all ${#ALL_BATCHES[@]} manifests present"

log ""
log "  Current calendar entries for owners=${ALLOWED_OWNERS:-$USER_NAME}:"
pos calendar list -j 2>/dev/null | ALLOWED_OWNERS="${ALLOWED_OWNERS:-$USER_NAME}" python3 -c "
import json, sys, os
allowed = {o.strip() for o in os.environ['ALLOWED_OWNERS'].split(',') if o.strip()}
try:
    entries = json.load(sys.stdin)
except Exception as e:
    print(f'    (could not parse calendar JSON: {e})')
    sys.exit(0)
mine = [e for e in entries if e.get('owner') in allowed]
if not mine:
    print('    NONE')
else:
    for e in sorted(mine, key=lambda x: x['start_date']):
        print(f\"    id={e['id']} owner={e['owner']} nodes={e.get('nodes')} {e['start_date']} -> {e['end_date']}\")
" 2>&1
log ""

# Determine the start index from --start-at
START_IDX=0
if [[ -n "$START_AT" ]]; then
    found=0
    for i in "${!ALL_BATCHES[@]}"; do
        if [[ "${ALL_BATCHES[$i]}" == "$START_AT" ]]; then
            START_IDX=$i
            found=1
            break
        fi
    done
    if [[ $found -eq 0 ]]; then
        log "FATAL: --start-at='$START_AT' not in batch list (${ALL_BATCHES[*]})"
        exit 2
    fi
fi
log "  starting from batch index $START_IDX (${ALL_BATCHES[$START_IDX]})"
log ""

# ---------- helpers ----------

free_all_my_allocations() {
    # CRITICAL: filter to allocations whose nodes are a SUBSET of THIS tier's
    # NODES_ARR. Without this filter, a parallel-tier runner can wipe out a
    # sibling tier's allocation (lost IV.POS.7 ta_b1 at 06:10 UTC). Uses JSON
    # output (-j) to avoid the multi-line text parse bug that also tried to
    # free node-name fragments and partial words as allocation IDs.
    local nodes_csv
    nodes_csv="$(IFS=,; echo "${NODES_ARR[*]}")"

    local alloc_ids
    alloc_ids=$(pos allocations list -j 2>/dev/null | \
        NODES_CSV="$nodes_csv" USER_NAME="$USER_NAME" python3 -c "
import json, sys, os
try:
    allocs = json.load(sys.stdin)
except Exception:
    sys.exit(0)
our_nodes = set(os.environ['NODES_CSV'].split(','))
user = os.environ['USER_NAME']
for a in allocs:
    if a.get('owner') != user:
        continue
    a_nodes = set(a.get('nodes') or [])
    # ONLY free allocations entirely contained within OUR tier's node set.
    if a_nodes and a_nodes <= our_nodes:
        print(a['id'])
")

    if [[ -z "$alloc_ids" ]]; then
        return 0
    fi

    while IFS= read -r alloc_id; do
        if [[ -n "$alloc_id" ]]; then
            log "    freeing allocation: $alloc_id (filtered to this tier's nodes; -k preserves calendar entry)"
            pos allocations free -k "$alloc_id" 2>&1 | sed 's/^/      /' || true
        fi
    done <<< "$alloc_ids"
}

# Returns 0 if all NODES_ARR nodes look healthy. Returns 1 if any look broken.
check_nodes_status() {
    local node_table
    node_table=$(pos nodes list 2>/dev/null)
    local any_broken=0
    for n in "${NODES_ARR[@]}"; do
        local row alloc statusf
        row=$(echo "$node_table" | awk -v n="$n" '$1==n {print; exit}')
        if [[ -z "$row" ]]; then
            log "    $n: NOT FOUND in nodes list"
            any_broken=1
            continue
        fi
        statusf=$(echo "$row" | awk '{print $3}')
        alloc=$(echo "$row" | awk '{print $4}')
        log "    $n: status=$statusf alloc=$alloc"
        if echo "$row" | grep -qi "ERR\|FAIL"; then
            log "    WARN: $n appears broken — will try substitute from BACKUP_NODES"
            any_broken=1
        fi
    done
    return $any_broken
}

# Substitute broken nodes with healthy ones from BACKUP_ARR (in order). Returns 0
# if all slots are healthy after substitution; 1 otherwise.
try_substitute_broken_nodes() {
    if [[ ${#BACKUP_ARR[@]} -eq 0 ]]; then
        log "    [substitute] no backup nodes configured; cannot substitute"
        return 1
    fi
    local node_table
    node_table=$(pos nodes list 2>/dev/null)
    local new_arr=()
    local backup_idx=0
    local substituted=0
    for n in "${NODES_ARR[@]}"; do
        local row
        row=$(echo "$node_table" | awk -v n="$n" '$1==n {print; exit}')
        if [[ -z "$row" ]] || echo "$row" | grep -qi "ERR\|FAIL"; then
            local sub=""
            while (( backup_idx < ${#BACKUP_ARR[@]} )); do
                local cand="${BACKUP_ARR[$backup_idx]}"
                backup_idx=$((backup_idx + 1))
                local cand_row
                cand_row=$(echo "$node_table" | awk -v n="$cand" '$1==n {print; exit}')
                if [[ -n "$cand_row" ]] && ! echo "$cand_row" | grep -qi "ERR\|FAIL"; then
                    sub="$cand"
                    break
                fi
            done
            if [[ -z "$sub" ]]; then
                log "    [substitute] cannot replace broken node $n (no backup available)"
                new_arr+=("$n")
            else
                log "    [substitute] $n -> $sub"
                new_arr+=("$sub")
                substituted=$((substituted + 1))
            fi
        else
            new_arr+=("$n")
        fi
    done
    if (( substituted > 0 )); then
        NODES_ARR=("${new_arr[@]}")
        log "    [substitute] new NODES_ARR: ${NODES_ARR[*]}"
    fi
    for n in "${NODES_ARR[@]}"; do
        local row
        row=$(echo "$node_table" | awk -v n="$n" '$1==n {print; exit}')
        if [[ -z "$row" ]] || echo "$row" | grep -qi "ERR\|FAIL"; then
            return 1
        fi
    done
    return 0
}

# Reservation-aware wait. Identical pattern to auto_run_ab_v1_smart.sh §find_qualifying_reservation
# but parameterised on NODES_ARR and MIN_RES_HR.
#
# ALLOWED_OWNERS env var (comma-separated, default = USER_NAME) controls which
# calendar-entry owners count as "qualifying". Use this to borrow reservations
# made by collaborators who reserve-but-do-not-allocate (e.g. frezabek for IV.POS.7).
# Allocate calls still run as the invoking shell user; this only widens the
# calendar filter so the runner doesn't fall asleep during a collaborator's window.
find_qualifying_reservation() {
    local now_epoch
    now_epoch=$(date +%s)
    local min_seconds
    min_seconds=$(awk -v h="$MIN_RES_HR" 'BEGIN { printf "%d", h * 3600 }')

    local nodes_str="${NODES_ARR[*]}"
    local allowed_owners="${ALLOWED_OWNERS:-$USER_NAME}"

    pos calendar list -j 2>/dev/null | NODES="$nodes_str" ALLOWED_OWNERS="$allowed_owners" python3 -c "
import json, sys, os, datetime
nodes = set(os.environ['NODES'].split())
allowed = {o.strip() for o in os.environ['ALLOWED_OWNERS'].split(',') if o.strip()}
now_ts = $now_epoch
min_sec = $min_seconds

def parse_iso(s):
    s2 = s.replace('T', ' ').split('+')[0].split('Z')[0]
    return datetime.datetime.strptime(s2[:19], '%Y-%m-%d %H:%M:%S').timestamp()

try:
    entries = json.load(sys.stdin)
except Exception:
    print('NONE'); sys.exit(0)

# Step 1: collect entries that cover all our nodes + are owned by an allowed user.
raw = []
for e in entries:
    if e.get('owner') not in allowed:
        continue
    e_nodes = set(e.get('nodes') or [])
    if not nodes <= e_nodes:
        continue
    try:
        s = parse_iso(e['start_date'])
        en = parse_iso(e['end_date'])
    except Exception:
        continue
    raw.append((s, en, e['start_date']))
raw.sort()

# Step 2: merge back-to-back entries (end of one == start of next, within GAP_TOL).
# This lets the runner treat e.g. 1752 (01:00-07:00) + 1753 (07:00-13:00) as a
# single 12h block, so a batch can launch the moment the previous finishes even
# if a reservation boundary is < MIN_RES_HR away.
GAP_TOL = 60  # seconds - tolerate small clock-skew gaps
merged = []
for s, en, iso in raw:
    if merged and (s - merged[-1][1]) <= GAP_TOL:
        prev_s, _, prev_iso = merged[-1]
        merged[-1] = (prev_s, en, prev_iso)
    else:
        merged.append((s, en, iso))

# Step 3: pick the earliest merged block with >= MIN_RES_HR remaining from now.
best_start = None
best_iso = None
for s, en, iso in merged:
    eff_start = max(s, now_ts)
    if en - eff_start < min_sec:
        continue
    if best_start is None or s < best_start:
        best_start = s
        best_iso = iso

if best_start is None:
    print('NONE')
elif best_start <= now_ts:
    print('ACTIVE')
else:
    print(f'WAIT {int(best_start)} {best_iso}')
"
}

wait_for_qualifying_reservation() {
    local b_id="$1"
    while true; do
        local now_epoch result
        now_epoch=$(date +%s)
        result=$(find_qualifying_reservation)
        case "$result" in
            ACTIVE)
                log "    [reservation-check] ACTIVE: qualifying reservation covers ${NODES_ARR[*]} with >= ${MIN_RES_HR}h remaining"
                return 0
                ;;
            WAIT\ *)
                local target_ts target_iso
                target_ts=$(echo "$result" | awk '{print $2}')
                target_iso=$(echo "$result" | awk '{for(i=3;i<=NF;i++) printf "%s%s", $i, (i<NF?" ":"")}')
                local wait_sec=$((target_ts - now_epoch + 10))
                local wait_min=$((wait_sec / 60))
                log "    [reservation-check] WAIT: next qualifying reservation starts at $target_iso (in ${wait_min}m)"
                if (( wait_sec <= POLL_SEC )); then
                    log "    [reservation-check] sleeping ${wait_sec}s until reservation start"
                    sleep "$wait_sec"
                else
                    log "    [reservation-check] sleeping ${POLL_SEC}s; will recheck"
                    sleep "$POLL_SEC"
                fi
                ;;
            NONE)
                log "    [reservation-check] NONE: no qualifying reservation found"
                log "    [reservation-check] CREATE one via web calendar (need >= ${MIN_RES_HR}h covering ${NODES_ARR[*]})"
                log "    [reservation-check] rechecking in ${POLL_SEC}s"
                status "batch=$b_id status=waiting_for_reservation since=$(ts) need_hours=$MIN_RES_HR nodes=\"${NODES_ARR[*]}\""
                sleep "$POLL_SEC"
                ;;
            *)
                log "    [reservation-check] WARN: unexpected output '$result'; rechecking in ${POLL_SEC}s"
                sleep "$POLL_SEC"
                ;;
        esac
    done
}

# Post-dispatch sanity: check that all expected DBs uploaded to the coinbase
# results mirror. Returns 0 if N/N present (N = number of jobs in this batch).
verify_batch_results() {
    local manifest_name="$1"
    local n_expected found
    n_expected=$(python3 -c "
import json, sys
with open('$MANIFEST_DIR/${manifest_name}.json') as f:
    m = json.load(f)
print(len(m['jobs']))
" 2>/dev/null)
    if [[ -z "$n_expected" ]] || [[ "$n_expected" == "0" ]]; then
        log "    [post-dispatch-verify] could not determine expected job count; skipping verify"
        return 0
    fi
    log "    [post-dispatch-verify] looking for $n_expected DBs under $RESULTS_MIRROR/a4/${manifest_name}/"
    found=$(python3 -c "
import json, sys, os, glob
with open('$MANIFEST_DIR/${manifest_name}.json') as f:
    m = json.load(f)
found = 0
for j in m['jobs']:
    pat = f'$RESULTS_MIRROR/a4/${manifest_name}/**/${manifest_name}_{j[\"strategy\"]}_seed{j[\"seed\"]}_n{j[\"n\"]}.db'
    matches = glob.glob(pat, recursive=True)
    if matches:
        print(f'  FOUND {j[\"strategy\"]} seed={j[\"seed\"]} -> {os.path.basename(matches[0])}')
        found += 1
    else:
        print(f'  MISSING {j[\"strategy\"]} seed={j[\"seed\"]} (pat={pat})')
print(f'RESULT {found}/$n_expected')
" 2>&1 | tee -a "$LOG_DIR/${manifest_name}.verify.log" | tail -1)
    local n_found
    n_found=$(echo "$found" | grep -oP '\d+(?=/)' | head -1)
    log "    [post-dispatch-verify] $found"
    [[ "$n_found" == "$n_expected" ]]
}

run_one_batch() {
    local b_id="$1"
    local manifest_name
    if [[ "$b_id" == "pos_iv_pos_7_smoke" ]]; then
        manifest_name="pos_iv_pos_7_smoke"
    else
        manifest_name="pos_iv_pos_7_${b_id}"
    fi
    local manifest="$MANIFEST_DIR/${manifest_name}.json"
    local log_file="$LOG_DIR/${manifest_name}.log"
    local out_file="$LOG_DIR/${manifest_name}.json"
    local ok_marker="$LOG_DIR/${manifest_name}.OK"
    local fail_marker="$LOG_DIR/${manifest_name}.FAIL"

    rm -f "$ok_marker" "$fail_marker"

    log ""
    log "================================================================"
    log "BATCH $b_id starting (manifest: $manifest_name)"
    log "  manifest = $manifest"
    log "  nodes    = ${NODES_ARR[*]}"
    log "================================================================"
    status "batch=$b_id status=preparing started_at=$(ts)"

    if [[ $SMOKE -eq 0 ]]; then
        log "  [smart-wait] ensuring a reservation with >= ${MIN_RES_HR}h remaining is active..."
        wait_for_qualifying_reservation "$b_id"
    else
        log "  [smoke-mode] skipping smart-wait (assume current reservation covers ${NODES_ARR[*]})"
    fi

    log "  pre-flight: node health check"
    if ! check_nodes_status; then
        log "  WARN: at least one node appears broken; attempting substitution from BACKUP_NODES"
        if ! try_substitute_broken_nodes; then
            log "  FAIL: could not assemble a healthy node set; marking batch FAIL"
            touch "$fail_marker"
            status "batch=$b_id status=FAIL ended_at=$(ts) reason=node_brick"
            return 1
        fi
        log "  pre-flight: re-checking after substitution"
        check_nodes_status || true
    fi

    log "  pre-flight: freeing any owned allocations (with -k to preserve calendar)"
    free_all_my_allocations
    sleep 3

    # dispatch_pos.py round-robins jobs to nodes. We must pass nodes in the
    # SAME number as jobs in the manifest (avoids dropped or duplicated jobs).
    local n_jobs
    n_jobs=$(python3 -c "import json; print(len(json.load(open('$manifest'))['jobs']))")
    local nodes_to_use=()
    if [[ $n_jobs -le ${#NODES_ARR[@]} ]]; then
        # CRITICAL: use 'j' not 'i' here. The outer batch loop uses i; declaring
        # this inner loop with 'i' (or any global var without `local`) clobbers
        # the outer i and causes batch ordering to jump (lost IV.POS.7 ts_b2-b5 at 06:10 UTC).
        local j
        for ((j=0; j<n_jobs; j++)); do nodes_to_use+=("${NODES_ARR[$j]}"); done
    else
        log "  WARN: batch has $n_jobs jobs but only ${#NODES_ARR[@]} nodes; some nodes will run >1 job sequentially"
        nodes_to_use=("${NODES_ARR[@]}")
    fi
    log "  effective node assignment: ${nodes_to_use[*]} ($n_jobs jobs)"

    status "batch=$b_id status=running started_at=$(ts) nodes=\"${nodes_to_use[*]}\""
    log "  launching at $(ts)"
    log "  tail -F $log_file in another session to see live progress"
    local start_epoch
    start_epoch=$(date +%s)

    PYTHONUNBUFFERED=1 python -u -m a4.pos.dispatch_pos \
        --manifest "$manifest" \
        --bundle "$BUNDLE" \
        --nodes "${nodes_to_use[@]}" \
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

    log "  post-dispatch: verifying expected DBs uploaded to results mirror"
    local dbs_ok=0
    if verify_batch_results "$manifest_name"; then
        dbs_ok=1
    fi

    # Accept rc=255 as "transient coordinator timeout" iff all DBs present
    # (the Inc 4 rc=255 patch already retries in dispatch_pos.py; this is a
    # final safety net).
    local final_status="UNKNOWN"
    if [[ $rc -eq 0 && $dbs_ok -eq 1 ]]; then
        final_status="OK"
    elif [[ $rc -eq 255 && $dbs_ok -eq 1 ]]; then
        log "  NOTE: dispatch returned rc=255 (coordinator timeout) but all DBs present — treating as OK"
        final_status="OK"
    elif [[ $rc -eq 0 && $dbs_ok -eq 0 ]]; then
        log "  WARN: dispatch returned rc=0 but only some DBs present — treating as FAIL"
        final_status="FAIL"
    else
        final_status="FAIL"
    fi

    if [[ "$final_status" == "OK" ]]; then
        touch "$ok_marker"
        log "BATCH $b_id OK (rc=$rc, wall=$elapsed_str, dbs=$n_jobs/$n_jobs)"
        status "batch=$b_id status=OK ended_at=$(ts) wall=$elapsed_str"
        return 0
    else
        touch "$fail_marker"
        log "BATCH $b_id FAIL (rc=$rc, wall=$elapsed_str, dbs_ok=$dbs_ok)"
        log "  inspect: cat $log_file"
        status "batch=$b_id status=FAIL ended_at=$(ts) wall=$elapsed_str rc=$rc"
        return 1
    fi
}

write_final_summary() {
    local summary="$LOG_DIR/SUMMARY.txt"
    {
        echo "IV.POS.7 ($TIER_TAG) auto-runner summary @ $(ts)"
        echo "================================================================"
        echo ""
        printf '%-12s %-8s %-12s\n' "BATCH" "STATUS" "MARKER"
        printf '%-12s %-8s %-12s\n' "-----" "------" "------"
        local ok_count=0
        local fail_count=0
        local skip_count=0
        for b in "${ALL_BATCHES[@]}"; do
            local mname
            if [[ "$b" == "pos_iv_pos_7_smoke" ]]; then
                mname="pos_iv_pos_7_smoke"
            else
                mname="pos_iv_pos_7_${b}"
            fi
            if [[ -f "$LOG_DIR/${mname}.OK" ]]; then
                printf '%-12s %-8s %s\n' "$b" "OK" "$LOG_DIR/${mname}.OK"
                ok_count=$((ok_count + 1))
            elif [[ -f "$LOG_DIR/${mname}.FAIL" ]]; then
                printf '%-12s %-8s %s\n' "$b" "FAIL" "$LOG_DIR/${mname}.FAIL"
                fail_count=$((fail_count + 1))
            else
                printf '%-12s %-8s %s\n' "$b" "SKIPPED" "(not attempted)"
                skip_count=$((skip_count + 1))
            fi
        done
        echo ""
        echo "Totals: OK=$ok_count FAIL=$fail_count SKIP=$skip_count (target=${#ALL_BATCHES[@]})"
        echo ""
        echo "Result DBs (on coinbase): $RESULTS_MIRROR/a4/pos_iv_pos_7_*/"
        echo "Per-batch logs:"
        ls "$LOG_DIR"/pos_iv_pos_7_*.log 2>/dev/null || true
    } > "$summary"
    log ""
    log "SUMMARY written to $summary:"
    cat "$summary" | sed 's/^/  /'
}

on_exit() {
    write_final_summary
    log "AUTO-RUNNER ($TIER_TAG) exiting at $(ts)"
}
trap on_exit EXIT

# ---------- main loop ----------
status "auto-runner ($TIER_TAG) started PID=$$ at $(ts)"
TOTAL_RC=0
for ((i=START_IDX; i<${#ALL_BATCHES[@]}; i++)); do
    b="${ALL_BATCHES[$i]}"
    if ! run_one_batch "$b"; then
        TOTAL_RC=1
        log ""
        log "STOPPING: batch $b failed. Investigate, then resume with:"
        log "  bash a4/pos/auto_run_iv_pos_7.sh --tier=$TIER --start-at=$b"
        if (( i + 1 < ${#ALL_BATCHES[@]} )); then
            log "(or skip past it: bash a4/pos/auto_run_iv_pos_7.sh --tier=$TIER --start-at=${ALL_BATCHES[$((i+1))]})"
        fi
        break
    fi
done

log ""
log "================================================================"
if [[ $TOTAL_RC -eq 0 ]]; then
    log "ALL BATCHES (from index $START_IDX onward) COMPLETE"
    status "auto-runner ($TIER_TAG) COMPLETE at $(ts)"
else
    log "AUTO-RUNNER ($TIER_TAG) STOPPED on failure"
    status "auto-runner ($TIER_TAG) STOPPED at $(ts) on batch failure"
fi
log "================================================================"

exit $TOTAL_RC
