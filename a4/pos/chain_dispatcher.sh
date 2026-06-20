#!/bin/bash
# chain_dispatcher.sh — self-driving SSH-bypass batch chain.
#
# Drives an ordered sequence of batches across remote nodes via SSH bypass.
# Each batch is a set of (node, run_id, remote_cmd) jobs that run in parallel.
# Within a batch, jobs run concurrently on their respective nodes.
# Across batches, the next batch fires the moment the previous batch's last
# job completes (rolling poll, no human intervention).
#
# Manifest format (one line per job, # for comments):
#   <batch_name>|<node>|<run_id>|<remote_cmd>
#
# Inputs (env vars):
#   MANIFEST       path to manifest file (REQUIRED)
#   CHAIN_NAME     name used in log lines (default: derived from manifest)
#   LOG_FILE       output log (default: /tmp/chain_${CHAIN_NAME}.log)
#   POLL_SEC       seconds between marker polls (default: 15)
#   RESULTS_BASE   local dir to scp results into (default: /tmp/chain_${CHAIN_NAME}_results)
#   REMOTE_BASE    remote dir prefix on each node (default: /tmp/chainjob)
#   PULL_GLOB      what to scp back (default: '*')
#
# Behavior:
#   - For each batch in order:
#     1) For each job: skip if .OK already present on remote (resume safe).
#        Otherwise create launcher script locally, scp to node, ssh -n -f nohup.
#     2) Poll each not-done job every POLL_SEC for .OK or .FAIL_rc*.
#        On .OK: scp remote run dir to local results dir, mark done.
#        On .FAIL: mark done (no pull).
#     3) Emit BATCH_COMPLETE when all jobs of the batch are done.
#   - After all batches: emit CHAIN_COMPLETE and exit 0.
#   - If interrupted (SIGTERM): emit CHAIN_INTERRUPTED. Resumable by relaunching.
#
# Logs are tee'd to LOG_FILE and stdout. tmux-friendly.

set -u
set -o pipefail

MANIFEST="${MANIFEST:?MANIFEST env var required}"
CHAIN_NAME="${CHAIN_NAME:-$(basename "$MANIFEST" .manifest)}"
LOG_FILE="${LOG_FILE:-/tmp/chain_${CHAIN_NAME}.log}"
POLL_SEC="${POLL_SEC:-15}"
RESULTS_BASE="${RESULTS_BASE:-/tmp/chain_${CHAIN_NAME}_results}"
REMOTE_BASE="${REMOTE_BASE:-/tmp/chainjob}"
PULL_GLOB="${PULL_GLOB:-*}"

mkdir -p "$RESULTS_BASE"
: > "$LOG_FILE"  # truncate per-launch; tee appends. Use append mode if you prefer resume logs.

emit() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"; }

trap 'emit "CHAIN_INTERRUPTED signal=$?"; exit 130' INT TERM

emit "CHAIN_START name=$CHAIN_NAME manifest=$MANIFEST poll=${POLL_SEC}s results=$RESULTS_BASE"

# --- parse manifest into batch arrays ---
# We build:
#   BATCH_ORDER = (b1 b2 ...)   distinct batch names in first-seen order
#   JOBS_<batch> = array of "node|run_id|cmd" strings
declare -a BATCH_ORDER
declare -A SEEN_BATCH
while IFS='|' read -r BATCH NODE RUN_ID CMD; do
    [[ -z "${BATCH:-}" || "$BATCH" =~ ^# ]] && continue
    if [[ -z "${SEEN_BATCH[$BATCH]:-}" ]]; then
        BATCH_ORDER+=("$BATCH")
        SEEN_BATCH[$BATCH]=1
        declare -ga "JOBS_${BATCH}=()"
    fi
    VAR="JOBS_${BATCH}"
    eval "${VAR}+=(\"\${NODE}|\${RUN_ID}|\${CMD}\")"
done < "$MANIFEST"

emit "CHAIN_PARSED batches=${#BATCH_ORDER[@]}: ${BATCH_ORDER[*]}"

# Tracks which nodes have the resume-check helper deployed (one-time per node).
declare -A CHECK_DEPLOYED

# --- per-batch loop ---
for BATCH in "${BATCH_ORDER[@]}"; do
    VAR="JOBS_${BATCH}[@]"
    JOBS=("${!VAR}")
    NJ=${#JOBS[@]}
    emit "BATCH_START name=$BATCH jobs=$NJ"

    # --- Launch phase ---
    for spec in "${JOBS[@]}"; do
        IFS='|' read -r NODE RUN_ID CMD <<<"$spec"
        REMOTE_DIR="${REMOTE_BASE}_${RUN_ID}"
        REMOTE_LAUNCHER="${REMOTE_BASE}_${RUN_ID}.sh"
        LOCAL_LAUNCHER="/tmp/_chain_launcher_${RUN_ID}.sh"

        # Resume / in-flight check (SAFETY CRITICAL — see §12.53 of POS_PLAYBOOK).
        #
        # Three possible states reported by the remote check_state helper:
        #   OK       — job already completed (skip launch, will be pulled on next poll).
        #   RUNNING  — a process exists on the node whose argv contains RUN_ID and is
        #              NOT the check_state shell itself (skip launch — pre-deployed/in-flight
        #              job exists; will be pulled when its .OK appears). This prevents the
        #              catastrophic failure where the dispatcher would spawn a second writer
        #              competing with an already-running job (e.g. fuzzer SQLite DB corruption).
        #   NONE     — no .OK, no matching process → safe to fire launcher.
        #
        # The helper script is deployed once per node (idempotent). It uses
        # `pgrep -f "$RID" | awk -v me=$$ '$0 != me'` to exclude itself from matches —
        # naive `pgrep -f "$RUN_ID"` over plain ssh ALWAYS matches the ssh shell because
        # the shell's argv contains the RUN_ID. Verified safe on idex/meld Jun 15 2026.
        if [[ -z "${CHECK_DEPLOYED[$NODE]:-}" ]]; then
            cat > "/tmp/_check_state_${NODE}.sh" <<'CHECK_EOF'
#!/bin/bash
# Args: $1 = REMOTE_DIR, $2 = RUN_ID
# Reports one of: OK | FAIL | RUNNING | NONE
#
# CRITICAL — uses ONLY bash builtins (no fork) after RID is read.
# Why: bash's $(...) command substitution forks a subshell that briefly
# inherits the parent's cmdline (which contains RID). Tools like pgrep
# scan /proc and CAN catch that transient subshell before it exec's,
# yielding a false-positive RUNNING. Verified racy on idex Jun 15 2026.
# This implementation:
#   - Reads /proc/PID/status with `read` builtin (no fork)
#   - Reads /proc/PID/cmdline with `mapfile -d ''` builtin (no fork)
#   - Matches with `case` (shell syntax, no fork)
#   - Excludes own PID + all ancestor PIDs
set -u
RD="$1"
RID="$2"

if [ -f "$RD/.OK" ]; then echo OK; exit 0; fi

shopt -s nullglob
FAIL_FILES=( "$RD"/.FAIL_rc* )
shopt -u nullglob
if [ "${#FAIL_FILES[@]}" -gt 0 ]; then echo FAIL; exit 0; fi

# Build ancestor set using only `read` (builtin).
declare -A ANC
ANC[$$]=1
P=$$
while :; do
    PN=""
    while IFS=':' read -r k v; do
        if [ "$k" = "PPid" ]; then
            PN="${v// /}"
            PN="${PN//	/}"
            break
        fi
    done < /proc/$P/status 2>/dev/null
    if [ -z "$PN" ] || [ "$PN" -le 1 ]; then break; fi
    ANC[$PN]=1
    P=$PN
done

# Scan /proc, no fork. mapfile -d '' reads NUL-separated argv entries.
N=0
for cmdfile in /proc/[0-9]*/cmdline; do
    pid="${cmdfile#/proc/}"
    pid="${pid%/cmdline}"
    [ -n "${ANC[$pid]:-}" ] && continue
    args=()
    mapfile -d '' args < "$cmdfile" 2>/dev/null
    fullcmd="${args[*]}"
    case "$fullcmd" in
        *"$RID"*) N=$((N + 1)) ;;
    esac
done

[ "$N" -gt 0 ] && echo RUNNING || echo NONE
CHECK_EOF
            scp -q -o ConnectTimeout=8 -o StrictHostKeyChecking=no "/tmp/_check_state_${NODE}.sh" "${NODE}:/tmp/_chain_check_state.sh" 2>/dev/null \
                && ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no "$NODE" "chmod +x /tmp/_chain_check_state.sh" 2>/dev/null \
                && CHECK_DEPLOYED[$NODE]=1 \
                || { emit "CHECK_DEPLOY_FAIL node=$NODE — aborting batch"; exit 2; }
        fi
        # Resume check with bounded retries. FAIL-SAFE: if we cannot get a clean
        # state token after MAX_RETRIES, ABORT the chain rather than risk firing
        # a launcher that would compete with an in-flight job and corrupt its DB.
        # See §12.53 — silent destruction is the worst possible outcome.
        STATE=""
        for RETRY in 0 1 2 3 4; do
            STATE=$(timeout 10 ssh -o ConnectTimeout=4 -o StrictHostKeyChecking=no "$NODE" \
                "/tmp/_chain_check_state.sh '${REMOTE_DIR}' '${RUN_ID}'" 2>/dev/null | grep -E '^(OK|FAIL|RUNNING|NONE)$' | head -1)
            case "$STATE" in OK|FAIL|RUNNING|NONE) break ;; esac
            emit "STATE_UNKNOWN_RETRY $BATCH node=$NODE run_id=$RUN_ID state='$STATE' attempt=$((RETRY+1))/5"
            sleep 3
        done
        case "$STATE" in
            OK)
                emit "LAUNCH_SKIP_RESUME $BATCH node=$NODE run_id=$RUN_ID (.OK already present)"
                continue
                ;;
            RUNNING)
                emit "LAUNCH_SKIP_INFLIGHT $BATCH node=$NODE run_id=$RUN_ID (process matched; waiting for .OK)"
                continue
                ;;
            FAIL)
                emit "LAUNCH_SKIP_FAIL $BATCH node=$NODE run_id=$RUN_ID (.FAIL marker present; will pull)"
                continue
                ;;
            NONE)
                : # verified safe to fire launcher
                ;;
            *)
                # State remained unparseable after 5 attempts. Aborting the whole chain
                # is the ONLY safe action — we cannot prove no in-flight job exists,
                # and firing the launcher with an in-flight competitor is catastrophic.
                emit "CHAIN_ABORT_STATE_UNKNOWN $BATCH node=$NODE run_id=$RUN_ID state='$STATE' — refusing to fire launcher (in-flight unknown)"
                emit "CHAIN_ABORTED — manual intervention required"
                exit 4
                ;;
        esac

        # Build launcher (escaped HEREDOC: \$ for remote, $ for local interpolation)
        cat > "$LOCAL_LAUNCHER" <<LAUNCHER_EOF
#!/bin/bash
set -u
RD="${REMOTE_DIR}"
mkdir -p "\$RD"
cd "\$RD"
rm -f .OK .FAIL_rc* 2>/dev/null
START_TS=\$(date -u +%s)
{
  echo "[\$(date -u +%H:%M:%S)] START run_id=${RUN_ID} on \$(hostname)"
  echo "[\$(date -u +%H:%M:%S)] CMD: ${CMD}"
} >> "\$RD/stdout.log"
${CMD} >> "\$RD/stdout.log" 2>> "\$RD/stderr.log"
RC=\$?
END_TS=\$(date -u +%s)
WALL=\$((END_TS - START_TS))
echo "[\$(date -u +%H:%M:%S)] END rc=\$RC wall=\${WALL}s" >> "\$RD/stdout.log"
echo "{\"run_id\":\"${RUN_ID}\",\"started_at_epoch\":\$START_TS,\"ended_at_epoch\":\$END_TS,\"wall_sec\":\$WALL,\"exit_code\":\$RC}" > "\$RD/meta.json"
if [[ \$RC -eq 0 || \$RC -eq 2 ]]; then
    touch "\$RD/.OK"
else
    touch "\$RD/.FAIL_rc\$RC"
fi
LAUNCHER_EOF

        # Background the launch (parallel across all jobs in a batch)
        (
            scp -o ConnectTimeout=10 -o StrictHostKeyChecking=no -q "$LOCAL_LAUNCHER" "${NODE}:${REMOTE_LAUNCHER}" \
              && ssh -n -f -o ConnectTimeout=10 -o StrictHostKeyChecking=no "$NODE" \
                   "chmod +x ${REMOTE_LAUNCHER} && nohup ${REMOTE_LAUNCHER} </dev/null >/dev/null 2>&1 &" \
              && emit "LAUNCHED $BATCH node=$NODE run_id=$RUN_ID" \
              || emit "LAUNCH_ERROR $BATCH node=$NODE run_id=$RUN_ID"
        ) &
    done
    wait
    emit "BATCH_LAUNCH_PHASE_DONE name=$BATCH"

    # --- Poll phase ---
    declare -A DONE=()
    declare -A SEEN_MARKER=()
    ITER=0
    while [[ ${#DONE[@]} -lt $NJ ]]; do
        for spec in "${JOBS[@]}"; do
            IFS='|' read -r NODE RUN_ID CMD <<<"$spec"
            KEY="${NODE}|${RUN_ID}"
            [[ -n "${DONE[$KEY]:-}" ]] && continue
            REMOTE_DIR="${REMOTE_BASE}_${RUN_ID}"
            STATUS=$(timeout 8 ssh -o ConnectTimeout=4 -o StrictHostKeyChecking=no "$NODE" \
                "test -f ${REMOTE_DIR}/.OK && echo OK; ls ${REMOTE_DIR}/.FAIL_rc* 2>/dev/null | head -1" 2>/dev/null | head -1)
            if [[ "$STATUS" == "OK" ]]; then
                [[ -z "${SEEN_MARKER[$KEY]:-}" ]] && { emit "OK $BATCH node=$NODE run_id=$RUN_ID"; SEEN_MARKER[$KEY]=1; }
                # Pull
                DEST="${RESULTS_BASE}/${BATCH}/${RUN_ID}"
                mkdir -p "$DEST"
                if scp -r -o ConnectTimeout=15 -o StrictHostKeyChecking=no "${NODE}:${REMOTE_DIR}/${PULL_GLOB}" "$DEST/" 2>>"${LOG_FILE}.scp_err"; then
                    emit "PULLED $BATCH node=$NODE run_id=$RUN_ID dest=$DEST"
                    DONE[$KEY]=1
                else
                    emit "PULL_RETRY $BATCH node=$NODE run_id=$RUN_ID"
                fi
            elif [[ "$STATUS" == *FAIL* ]]; then
                [[ -z "${SEEN_MARKER[$KEY]:-}" ]] && {
                    emit "FAIL $BATCH node=$NODE run_id=$RUN_ID marker=$STATUS"
                    SEEN_MARKER[$KEY]=1
                    DEST="${RESULTS_BASE}/${BATCH}/${RUN_ID}"
                    mkdir -p "$DEST"
                    scp -r -o ConnectTimeout=15 -o StrictHostKeyChecking=no "${NODE}:${REMOTE_DIR}/${PULL_GLOB}" "$DEST/" 2>>"${LOG_FILE}.scp_err" || true
                    DONE[$KEY]=1
                }
            fi
        done
        ITER=$((ITER+1))
        if (( ITER % 5 == 0 )); then
            emit "HEARTBEAT $BATCH done=${#DONE[@]}/$NJ"
        fi
        (( ${#DONE[@]} >= NJ )) && break
        sleep "$POLL_SEC"
    done
    emit "BATCH_COMPLETE name=$BATCH done=${#DONE[@]}/$NJ"
    unset DONE SEEN_MARKER
done

emit "CHAIN_COMPLETE name=$CHAIN_NAME batches=${#BATCH_ORDER[@]}"
