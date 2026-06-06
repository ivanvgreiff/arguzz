#!/usr/bin/env bash
# a4/pos/run_campaign_pos.sh
#
# Test-node entrypoint for ONE seeded campaign on a POS test node.
# This is the `--infile` for `pos commands launch`.
#
# Revised Jun 5, 2026: uses `pos_get_variable` (NOT env vars). Per-job parameters are
# pushed onto the allocation via `pos.allocations.set_variables(<node>, <yaml>)` by
# the dispatcher (see dispatch_pos.py).
#
# Variables expected (set by dispatcher; read via pos_get_variable):
#   A4_STRATEGY        uniform | zoned | bandit
#   A4_SEED            integer
#   A4_NUM             number of mutations
#   A4_CAMPAIGN_NAME   human label (e.g. "pos_ab_v1")
#
# Optional:
#   A4_B_COUNT         (default 16; ignored if not bandit)
#   A4_HOST_ARGS       extra args after `--` (default "--in1 5 --in4 10")
#   A4_RUN_ID          unique run id (default ${STRATEGY}_seed${SEED}_n${NUM}_<epoch>)
#   A4_NO_INTERNET     if "1", DO NOT use online `pip install` (assume wheels staged)
#
# Bundle is shipped to the test node BEFORE this script runs, via
# `pos.nodes.copy(<role>, '<local-bundle-tarball>', '/root/', recursive=True)`
# from the dispatcher. The tarball must extract to `/root/a4_campaign/` containing:
#   bin/risc0-host    (sha256-verified)
#   bundle.json       (manifest: git_commit, host_sha256, ...)
#   repo/             (git-archived source)
#   scripts/          (this file)
#   wheels/           (optional — only if --include-wheels was used)
#
# Behaviour:
#   1. read params via pos_get_variable
#   2. cd to /root/a4_campaign (already extracted by dispatcher)
#   3. verify bundle sha
#   4. build venv, install
#   5. run cli fuzz
#   6. pos_upload results (via EXIT trap so partial results survive)

set -euo pipefail

# ----- 1. read pos variables --------------------------------------------
A4_STRATEGY=$(pos_get_variable A4_STRATEGY)
A4_SEED=$(pos_get_variable A4_SEED)
A4_NUM=$(pos_get_variable A4_NUM)
A4_CAMPAIGN_NAME=$(pos_get_variable A4_CAMPAIGN_NAME)

# Optional vars: pos_get_variable returns non-zero if missing; tolerate.
A4_B_COUNT=$(pos_get_variable A4_B_COUNT 2>/dev/null || echo "16")
A4_HOST_ARGS=$(pos_get_variable A4_HOST_ARGS 2>/dev/null || echo "--in1 5 --in4 10")
A4_RUN_ID=$(pos_get_variable A4_RUN_ID 2>/dev/null || echo "${A4_STRATEGY}_seed${A4_SEED}_n${A4_NUM}_$(date +%s)")
A4_NO_INTERNET=$(pos_get_variable A4_NO_INTERNET 2>/dev/null || echo "0")
A4_NODE=$(pos_get_variable hostname)

# ----- 2. workdir + result paths ----------------------------------------
WORK="/root/a4_campaign"
if [[ ! -d "$WORK" ]]; then
    echo "[run_campaign_pos] FATAL: bundle not present at $WORK — dispatcher did not pos.nodes.copy" >&2
    exit 89
fi
cd "$WORK"

RESULTS="/root/results_${A4_RUN_ID}"
mkdir -p "$RESULTS"

LOG="$RESULTS/${A4_CAMPAIGN_NAME}_${A4_STRATEGY}_seed${A4_SEED}_n${A4_NUM}.log"
DB="$RESULTS/${A4_CAMPAIGN_NAME}_${A4_STRATEGY}_seed${A4_SEED}_n${A4_NUM}.db"
META="$RESULTS/${A4_CAMPAIGN_NAME}_${A4_STRATEGY}_seed${A4_SEED}_n${A4_NUM}.meta.json"

# ----- 3. upload-on-EXIT trap (POS docs §4.6 + pivot §12.1) -------------
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
    pos_upload "$RESULTS" -r -f 2>/dev/null || \
        echo "[run_campaign_pos] WARN: pos_upload failed" >&2
}
trap upload_results EXIT

# ----- 4. log preamble + bundle integrity --------------------------------
echo "[run_campaign_pos] node=$A4_NODE  run_id=$A4_RUN_ID" | tee "$LOG"
echo "[run_campaign_pos] params: strat=$A4_STRATEGY seed=$A4_SEED num=$A4_NUM b_count=$A4_B_COUNT" | tee -a "$LOG"

if [[ ! -x bin/risc0-host ]]; then
    echo "[run_campaign_pos] FATAL: bin/risc0-host missing or not executable" | tee -a "$LOG" >&2
    exit 88
fi

EXPECTED_HOST_SHA=$(python3 -c "import json; print(json.load(open('bundle.json'))['host_sha256'])" 2>/dev/null || echo "unknown")
ACTUAL_HOST_SHA=$(sha256sum bin/risc0-host | awk '{print $1}')
echo "[run_campaign_pos] expected host sha: $EXPECTED_HOST_SHA" | tee -a "$LOG"
echo "[run_campaign_pos] actual   host sha: $ACTUAL_HOST_SHA"   | tee -a "$LOG"
if [[ "$EXPECTED_HOST_SHA" != "unknown" && "$EXPECTED_HOST_SHA" != "$ACTUAL_HOST_SHA" ]]; then
    echo "[run_campaign_pos] FATAL: host sha mismatch" | tee -a "$LOG" >&2
    exit 90
fi

# ----- 5. system prerequisites (idempotent; debian-bullseye default) -----
apt-get update -qq 2>&1 | tee -a "$LOG" || true
apt-get install -y -qq python3-venv python3-pip build-essential git 2>&1 | tee -a "$LOG" || true

# ----- 6. Python env -----------------------------------------------------
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip 2>&1 | tee -a "$LOG"

if [[ -d wheels && "$A4_NO_INTERNET" = "1" ]]; then
    echo "[run_campaign_pos] installing offline from wheels/" | tee -a "$LOG"
    pip install --no-index --find-links=wheels -e repo/ 2>&1 | tee -a "$LOG"
elif [[ -d wheels ]]; then
    echo "[run_campaign_pos] installing with wheelhouse fallback (internet OK)" | tee -a "$LOG"
    pip install --find-links=wheels -e repo/ 2>&1 | tee -a "$LOG"
else
    echo "[run_campaign_pos] installing from PyPI (internet required)" | tee -a "$LOG"
    pip install -e repo/ 2>&1 | tee -a "$LOG"
fi

# ----- 7. meta JSON ------------------------------------------------------
START_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(python3 -c "import json; print(json.load(open('bundle.json'))['git_commit'])" 2>/dev/null || echo "unknown")
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

# ----- 8. build + run cli fuzz ------------------------------------------
declare -a CMD=(
    python -m a4.standalone.cli fuzz
    --host "$(pwd)/bin/risc0-host"
    --selector "$A4_STRATEGY"
    --num "$A4_NUM"
    --seed "$A4_SEED"
    --db "$DB"
)
if [[ "$A4_STRATEGY" = "bandit" ]]; then
    CMD+=(--b-count "$A4_B_COUNT")
fi
CMD+=(--)
# shellcheck disable=SC2206
HOST_ARR=($A4_HOST_ARGS); CMD+=("${HOST_ARR[@]}")

echo "[run_campaign_pos] command: ${CMD[*]}" | tee -a "$LOG"

"${CMD[@]}" 2>&1 | tee -a "$LOG"
CAMP_RC=${PIPESTATUS[0]}

# ----- 9. record final mutation count -----------------------------------
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
