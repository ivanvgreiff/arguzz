#!/usr/bin/env bash
# a4/pos/benchmark_pos.sh
#
# IV.POS.2 — Testbed runtime benchmark protocol (per PIVOT_TO_POS.md §9.1).
#
# Runs three small campaigns (one per strategy) on ONE test node, measures
# seconds/mutation per strategy, writes pos_benchmark_v1.json. The number
# this produces is what we use to pick N for the IV.POS.5 full campaign.
#
# Expected to run on the same kind of test node that IV.POS.5 will use.
#
# Pre-conditions:
#   - bundle already extracted at $PWD/a4_campaign (i.e. invoked from inside
#     run_campaign_pos.sh-style env), OR
#   - this script is launched standalone with --bundle to fetch/extract first.
#
# Env vars (same conventions as run_campaign_pos.sh):
#   A4_BUNDLE        bundle path under /srv/testbed/files (if --bundle not in args)
#   A4_NODE          node name (default $(hostname))
#   A4_N             mutations per benchmark (default 50)
#   A4_B_COUNT       (default 16)
#   A4_HOST_ARGS     default "--in1 5 --in4 10"
#   A4_SEED          default 42 (same across strategies for fairness)
#   A4_CAMPAIGN_NAME default "pos_benchmark_v1"
#
# Output:
#   pos_benchmark_v1.json   (uploaded via pos_upload at end)

set -euo pipefail

A4_N="${A4_N:-50}"
A4_SEED="${A4_SEED:-42}"
A4_B_COUNT="${A4_B_COUNT:-16}"
A4_HOST_ARGS="${A4_HOST_ARGS:---in1 5 --in4 10}"
A4_NODE="${A4_NODE:-$(hostname)}"
A4_CAMPAIGN_NAME="${A4_CAMPAIGN_NAME:-pos_benchmark_v1}"

WORK="/tmp/a4_benchmark_$(date +%s)"
RESULTS="$WORK/results"
mkdir -p "$RESULTS"
cd "$WORK"

LOG="$RESULTS/benchmark.log"
BENCH_JSON="$RESULTS/${A4_CAMPAIGN_NAME}.json"

upload_on_exit() {
    pos_upload "$RESULTS" -r -o "${A4_CAMPAIGN_NAME}" -f 2>&1 | tee -a "$LOG" || true
}
trap upload_on_exit EXIT

echo "[benchmark_pos] node=$A4_NODE N=$A4_N seed=$A4_SEED b_count=$A4_B_COUNT" | tee "$LOG"

# Bundle (assume passed via A4_BUNDLE if not already extracted)
if [[ ! -d a4_campaign ]]; then
    : "${A4_BUNDLE:?required if a4_campaign/ not already present}"
    pos_download "$A4_BUNDLE" 2>&1 | tee -a "$LOG"
    tar -xzf "$(basename "$A4_BUNDLE")" 2>&1 | tee -a "$LOG"
fi
cd a4_campaign
GIT_COMMIT=$(python3 -c "import json; print(json.load(open('bundle.json'))['git_commit'])")
HOST_SHA=$(sha256sum bin/risc0-host | awk '{print $1}')

python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip 2>&1 | tee -a "$LOG"
pip install -e repo/ 2>&1 | tee -a "$LOG"  # tweak per offline policy

# CPU info
CPU_MODEL=$(grep -m1 '^model name' /proc/cpuinfo | sed 's/.*: //' || echo "unknown")
N_THREADS=$(nproc || echo 0)

# Run the 3 benchmark campaigns sequentially (one-per-node per pivot §15.6)
declare -a STRATEGIES=("uniform" "zoned" "bandit")
RUNS_JSON="[]"
for STR in "${STRATEGIES[@]}"; do
    DB="$RESULTS/${STR}_seed${A4_SEED}_n${A4_N}.db"
    SUBLOG="$RESULTS/${STR}_seed${A4_SEED}_n${A4_N}.log"
    echo "[benchmark_pos] === running $STR ===" | tee -a "$LOG"

    declare -a CMD=(
        python -m a4.standalone.cli fuzz
        --host "$(pwd)/bin/risc0-host"
        --selector "$STR"
        --num "$A4_N"
        --seed "$A4_SEED"
        --db "$DB"
    )
    [[ "$STR" == "bandit" ]] && CMD+=(--b-count "$A4_B_COUNT")
    CMD+=(--)
    # shellcheck disable=SC2206
    HOST_ARR=($A4_HOST_ARGS); CMD+=("${HOST_ARR[@]}")

    T_START=$(date +%s)
    "${CMD[@]}" 2>&1 | tee "$SUBLOG"
    T_END=$(date +%s)
    RUNTIME=$((T_END - T_START))
    SECS_PER_MUT=$(python3 -c "print(f'{$RUNTIME / max($A4_N,1):.3f}')")
    N_REC=$(python3 -c "import sqlite3; print(sqlite3.connect('$DB').execute('SELECT COUNT(*) FROM mutations').fetchone()[0])" 2>/dev/null || echo -1)

    # Append to RUNS_JSON
    RUNS_JSON=$(python3 - <<PYEOF
import json
runs = json.loads('''$RUNS_JSON''')
runs.append({
    "strategy": "$STR",
    "seed":     $A4_SEED,
    "num":      $A4_N,
    "num_recorded":     $N_REC,
    "runtime_seconds":  $RUNTIME,
    "seconds_per_mutation": $SECS_PER_MUT
})
print(json.dumps(runs))
PYEOF
)
done

# Final benchmark JSON
python3 - <<PYEOF | tee "$BENCH_JSON"
import json, os
out = {
    "campaign_name":  "$A4_CAMPAIGN_NAME",
    "node":           "$A4_NODE",
    "cpu_model":      "$CPU_MODEL",
    "n_threads":      $N_THREADS,
    "image":          os.environ.get("A4_IMAGE", "unknown"),
    "git_commit":     "$GIT_COMMIT",
    "host_sha256":    "$HOST_SHA",
    "b_count":        $A4_B_COUNT,
    "host_args":      "$A4_HOST_ARGS",
    "runs":           json.loads('''$RUNS_JSON'''),
    "created_at_utc": "$(date -u +%FT%TZ)",
}
print(json.dumps(out, indent=2))
PYEOF

echo "[benchmark_pos] DONE; results -> ${A4_CAMPAIGN_NAME} via pos_upload"
