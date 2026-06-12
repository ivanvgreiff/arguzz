#!/usr/bin/env bash
# a4/pos/run_campaign_pos.sh
#
# Test-node entrypoint for ONE seeded campaign on a POS test node.
# Launched on the test node via: `pos.commands.launch(node, infile=this, queued=True, name=run_id)`.
#
# REVISED Jun 6, 2026:
#   - DROPPED `pip install -e repo/` (arguzz has no setup.py / [project] metadata, only [tool.*]).
#   - DROPPED `apt-get install python3-venv python3-pip build-essential git` (no install needed).
#   - DROPPED `python3 -m venv .venv` + activation (a4 imports are PURE STDLIB; verified).
#   - FIXED cwd bug: `python -m a4.standalone.cli` was run from $WORK (no a4/ there); now
#     runs from $WORK/repo where a4/ lives.
#   - Uses absolute paths for --host and --db so cwd change is harmless.
#
# Variables expected (set by dispatcher via pos.allocations.set_variables; read here via pos_get_variable):
#   A4_STRATEGY        uniform | zoned | bandit
#   A4_SEED            integer
#   A4_NUM             number of mutations
#   A4_CAMPAIGN_NAME   human label (e.g. "pos_smoke_v1")
#   A4_B_COUNT         (default 16; ignored if not bandit)
#   A4_HOST_ARGS       extra args after `--` (default "--in1 5 --in4 10")
#   A4_RUN_ID          unique run id
#   A4_NO_INTERNET     "1" => offline mode (we don't need it; left for future)
#
# Bundle is shipped to the test node BEFORE this script runs, via
# `pos.nodes.copy(<node>, '<local-bundle>.tar.gz', '/root/', recursive=False)` and
# then extracted by an inline `tar -xzf` launched by the dispatcher. After extraction:
#   /root/a4_campaign/
#     bin/risc0-host       (sha256-verified)
#     bundle.json          (manifest: git_commit, host_sha256, ...)
#     repo/                (git-archived source; contains a4/ as top-level package)
#     scripts/             (this file + benchmark_pos.sh)
#
# Behaviour:
#   1. read params via pos_get_variable
#   2. cd to /root/a4_campaign (validate); use absolute paths thereafter
#   3. verify host_sha256
#   4. run `python3 -m a4.standalone.cli fuzz ...` from $WORK/repo (a4 is in cwd)
#   5. pos_upload results (via EXIT trap so partial results survive)

set -euo pipefail

# ----- 0. emergency diagnostics: dump all pos vars to /tmp -------------
# Captures evidence regardless of whether the rest of the script crashes.
# Useful when set_variables silently no-ops and pos_get_variable fails.
{
    echo "=== run_campaign_pos.sh boot diagnostic ==="
    date -u +"%Y-%m-%dT%H:%M:%SZ"
    echo "node=$(hostname)"
    echo "uid=$(id -u) euid=$(id -u)"
    echo "PATH=$PATH"
    command -v pos_get_variable && pos_get_variable --help 2>&1 | head -5 || \
        echo "ERROR: pos_get_variable not on PATH"
    echo "--- attempted pos vars ---"
    for key in A4_STRATEGY A4_SEED A4_NUM A4_CAMPAIGN_NAME A4_B_COUNT A4_HOST_ARGS A4_RUN_ID A4_NO_INTERNET hostname; do
        val=$(pos_get_variable "$key" 2>&1 || echo "<failed>")
        echo "  $key = $val"
    done
} > /tmp/a4_boot_diag.log 2>&1

# ----- 1. read pos variables --------------------------------------------
# Wrap each required read with an informative failure message so we don't
# crash with the bare cryptic `variable X unknown` line.
_required() {
    local key="$1"
    local val
    if ! val=$(pos_get_variable "$key" 2>&1); then
        echo "[run_campaign_pos] FATAL: required variable '$key' not set on this node." >&2
        echo "[run_campaign_pos] pos_get_variable said: $val" >&2
        echo "[run_campaign_pos] Boot diagnostic dumped to /tmp/a4_boot_diag.log:" >&2
        cat /tmp/a4_boot_diag.log >&2 || true
        echo "[run_campaign_pos] This typically means the dispatcher's set_variables call" >&2
        echo "[run_campaign_pos] silently failed. Verify on mgmt node:" >&2
        echo "[run_campaign_pos]   pos allocations get_variable <node-or-alloc> $key" >&2
        exit 87
    fi
    printf '%s' "$val"
}

A4_STRATEGY=$(_required A4_STRATEGY)
A4_SEED=$(_required A4_SEED)
A4_NUM=$(_required A4_NUM)
A4_CAMPAIGN_NAME=$(_required A4_CAMPAIGN_NAME)

# Optional vars: pos_get_variable returns non-zero if missing; tolerate.
A4_B_COUNT=$(pos_get_variable A4_B_COUNT 2>/dev/null || echo "16")
A4_HOST_ARGS=$(pos_get_variable A4_HOST_ARGS 2>/dev/null || echo "--in1 5 --in4 10")
A4_RUN_ID=$(pos_get_variable A4_RUN_ID 2>/dev/null || echo "${A4_STRATEGY}_seed${A4_SEED}_n${A4_NUM}_$(date +%s)")
A4_NO_INTERNET=$(pos_get_variable A4_NO_INTERNET 2>/dev/null || echo "0")
A4_TELEMETRY_LEVEL=$(pos_get_variable A4_TELEMETRY_LEVEL 2>/dev/null || echo "")
A4_RUN_SUFFIX=$(pos_get_variable A4_RUN_SUFFIX 2>/dev/null || echo "")
A4_DEBUG_BANDIT_TRACE=$(pos_get_variable A4_DEBUG_BANDIT_TRACE 2>/dev/null || echo "0")
A4_COVERAGE_TOUCH_VERBOSE=$(pos_get_variable A4_COVERAGE_TOUCH_VERBOSE 2>/dev/null || echo "0")
A4_FTW291_TRACE=$(pos_get_variable A4_FTW291_TRACE 2>/dev/null || echo "0")
A4_MEM_FINGERPRINT=$(pos_get_variable A4_MEM_FINGERPRINT 2>/dev/null || echo "0")
A4_NODE=$(pos_get_variable hostname 2>/dev/null || hostname)

# ----- 2. workdir + result paths (all ABSOLUTE) -------------------------
WORK="/root/a4_campaign"
REPO_DIR="$WORK/repo"
HOST_BIN="$WORK/bin/risc0-host"

if [[ ! -d "$WORK" ]]; then
    echo "[run_campaign_pos] FATAL: bundle not present at $WORK — dispatcher did not pos.nodes.copy + extract" >&2
    exit 89
fi
if [[ ! -d "$REPO_DIR" ]]; then
    echo "[run_campaign_pos] FATAL: $REPO_DIR missing — bundle layout incorrect (expected /root/a4_campaign/repo/)" >&2
    exit 91
fi
if [[ ! -x "$HOST_BIN" ]]; then
    echo "[run_campaign_pos] FATAL: $HOST_BIN missing or not executable" >&2
    exit 88
fi

RESULTS="/root/results_${A4_RUN_ID}"
mkdir -p "$RESULTS"

# Inc 3b §B.1 — per-node fingerprint (before campaign work)
FP="$RESULTS/fingerprint"
mkdir -p "$FP"
env | sort > "$FP/env.txt"
uname -a > "$FP/uname.txt"
head -50 /proc/cpuinfo > "$FP/cpuinfo.txt" 2>/dev/null || true
cat /proc/meminfo > "$FP/meminfo.txt" 2>/dev/null || true
{
    sha256sum /lib/x86_64-linux-gnu/libstdc++.so.6 2>/dev/null || true
    sha256sum /lib/x86_64-linux-gnu/libc.so.6 2>/dev/null || true
    sha256sum /lib/x86_64-linux-gnu/libm.so.6 2>/dev/null || true
    sha256sum "$HOST_BIN" 2>/dev/null || true
} > "$FP/lib_shas.txt" 2>/dev/null || true
numactl --show > "$FP/numa.txt" 2>&1 || true

_NAME_SUFFIX=""
if [[ -n "$A4_RUN_SUFFIX" ]]; then
    _NAME_SUFFIX="_${A4_RUN_SUFFIX}"
fi
_LOG_STEM="${A4_CAMPAIGN_NAME}_${A4_STRATEGY}_seed${A4_SEED}_n${A4_NUM}${_NAME_SUFFIX}"
LOG="$RESULTS/${_LOG_STEM}.log"
DB="$RESULTS/${_LOG_STEM}.db"
TRACE="$RESULTS/${_LOG_STEM}.bandit_trace.jsonl"
META="$RESULTS/${_LOG_STEM}.meta.json"

# ----- 3. upload-on-EXIT trap -------------------------------------------
EXIT_CODE_SAVED=255
upload_results() {
    local rc=$?
    EXIT_CODE_SAVED=$rc
    echo "[run_campaign_pos] EXIT trap firing, rc=$rc" | tee -a "$LOG" 2>/dev/null || true
    if [[ -f "$META" ]]; then
        ENDED_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        sed -i "s/\"ended_at\":\\s*\"PENDING\"/\"ended_at\": \"$ENDED_ISO\"/" "$META" || true
        sed -i "s/\"exit_code\":\\s*-1/\"exit_code\": $rc/" "$META" || true
    fi
    # `pos_upload <path> -r -f` ships the dir into the allocation's result folder
    # on the management node (see pos-examples/tutorials/* for the canonical form).
    pos_upload "$RESULTS" -r -f 2>/dev/null || \
        echo "[run_campaign_pos] WARN: pos_upload failed (continuing)" >&2
}
trap upload_results EXIT

# ----- 4. log preamble + bundle integrity -------------------------------
echo "[run_campaign_pos] node=$A4_NODE  run_id=$A4_RUN_ID" | tee "$LOG"
echo "[run_campaign_pos] params: strat=$A4_STRATEGY seed=$A4_SEED num=$A4_NUM b_count=$A4_B_COUNT" | tee -a "$LOG"
echo "[run_campaign_pos] host_args: $A4_HOST_ARGS" | tee -a "$LOG"
echo "[run_campaign_pos] WORK=$WORK REPO=$REPO_DIR HOST=$HOST_BIN" | tee -a "$LOG"

EXPECTED_HOST_SHA=$(python3 -c "import json; print(json.load(open('$WORK/bundle.json'))['host_sha256'])" 2>/dev/null || echo "unknown")
ACTUAL_HOST_SHA=$(sha256sum "$HOST_BIN" | awk '{print $1}')
echo "[run_campaign_pos] expected host sha: $EXPECTED_HOST_SHA" | tee -a "$LOG"
echo "[run_campaign_pos] actual   host sha: $ACTUAL_HOST_SHA"   | tee -a "$LOG"
if [[ "$EXPECTED_HOST_SHA" != "unknown" && "$EXPECTED_HOST_SHA" != "$ACTUAL_HOST_SHA" ]]; then
    echo "[run_campaign_pos] FATAL: host sha mismatch" | tee -a "$LOG" >&2
    exit 90
fi

# ----- 5. system check (NO install — verified a4 is pure stdlib) --------
# `a4/standalone/` and `a4/core/` have ZERO third-party imports beyond stdlib +
# the local `a4.*` package. Debian Bookworm ships Python 3.11; that satisfies
# the >=3.10 minimum. No venv, no pip, no apt-get required.
PY=$(command -v python3)
if [[ -z "$PY" ]]; then
    echo "[run_campaign_pos] FATAL: python3 not on PATH" >&2
    exit 92
fi
PYVER=$("$PY" --version 2>&1)
echo "[run_campaign_pos] python: $PY ($PYVER)" | tee -a "$LOG"

# ----- 6. meta JSON ------------------------------------------------------
START_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(python3 -c "import json; print(json.load(open('$WORK/bundle.json'))['git_commit'])" 2>/dev/null || echo "unknown")
cat > "$META" <<EOF
{
  "campaign_name":  "${A4_CAMPAIGN_NAME}",
  "run_id":         "${A4_RUN_ID}",
  "node":           "${A4_NODE}",
  "strategy":       "${A4_STRATEGY}",
  "seed":           ${A4_SEED},
  "num_requested":  ${A4_NUM},
  "num_recorded":   -1,
  "b_count":        ${A4_B_COUNT},
  "host_args":      "${A4_HOST_ARGS}",
  "host_sha256":    "${ACTUAL_HOST_SHA}",
  "git_commit":     "${GIT_COMMIT}",
  "started_at":     "${START_ISO}",
  "ended_at":       "PENDING",
  "exit_code":      -1
}
EOF

# ----- 7. build + run cli fuzz ------------------------------------------
# Run from $REPO_DIR so `python3 -m a4.standalone.cli` finds the a4 package
# (no install needed; package is in cwd). All other paths are absolute.
cd "$REPO_DIR"

# Map A4_STRATEGY (manifest label, may be e.g. "bandit-16" or "bandit-32")
# onto the CLI's --selector choices, which are strictly: uniform | zoned | bandit | guided.
# Trailing "-NN" is treated as a b_count hint (already pushed separately as A4_B_COUNT)
# and is stripped here so argparse doesn't reject the value.
SELECTOR=$(echo "$A4_STRATEGY" | sed -E 's/-[0-9]+$//')
echo "[run_campaign_pos] mapping strategy '$A4_STRATEGY' -> selector '$SELECTOR'" | tee -a "$LOG"

declare -a CMD=(
    "$PY" -m a4.standalone.cli fuzz
    --host "$HOST_BIN"
    --selector "$SELECTOR"
    --num "$A4_NUM"
    --seed "$A4_SEED"
    --db "$DB"
)
if [[ "$SELECTOR" = "bandit" ]]; then
    CMD+=(--b-count "$A4_B_COUNT")
fi
if [[ -n "$A4_TELEMETRY_LEVEL" ]]; then
    CMD+=(--telemetry-level "$A4_TELEMETRY_LEVEL")
fi
if [[ "$A4_DEBUG_BANDIT_TRACE" = "1" ]]; then
    CMD+=(--debug-bandit-trace "$TRACE")
fi
CMD+=(--)
# Word-split A4_HOST_ARGS into individual args after --
# shellcheck disable=SC2206
HOST_ARR=($A4_HOST_ARGS); CMD+=("${HOST_ARR[@]}")

echo "[run_campaign_pos] command: ${CMD[*]}" | tee -a "$LOG"
if [[ "$A4_COVERAGE_TOUCH_VERBOSE" = "1" ]]; then
    export A4_COVERAGE_TOUCH_VERBOSE=1
    echo "[run_campaign_pos] A4_COVERAGE_TOUCH_VERBOSE=1" | tee -a "$LOG"
fi
if [[ "$A4_FTW291_TRACE" = "1" ]]; then
    export A4_FTW291_TRACE=1
    echo "[run_campaign_pos] A4_FTW291_TRACE=1" | tee -a "$LOG"
fi
if [[ "$A4_MEM_FINGERPRINT" = "1" ]]; then
    export A4_MEM_FINGERPRINT=1
    echo "[run_campaign_pos] A4_MEM_FINGERPRINT=1" | tee -a "$LOG"
fi
export A4_COVERAGE_TOUCH=1
export A4_FAMILY_RESIDUE=1
export A4_GLOBAL_RESIDUE=1
export CONSTRAINT_CONTINUE=1

"${CMD[@]}" 2>&1 | tee -a "$LOG"
CAMP_RC=${PIPESTATUS[0]}

# ----- 8. record final mutation count -----------------------------------
if [[ -f "$DB" ]]; then
    N_REC=$(python3 - <<PYEOF
import sqlite3
try:
    print(sqlite3.connect('$DB').execute('SELECT COUNT(*) FROM mutations').fetchone()[0])
except Exception:
    print(-1)
PYEOF
    )
    sed -i "s/\"num_recorded\":\\s*-1/\"num_recorded\": $N_REC/" "$META" || true
fi

echo "[run_campaign_pos] campaign rc=$CAMP_RC" | tee -a "$LOG"
exit "$CAMP_RC"  # propagates through trap
