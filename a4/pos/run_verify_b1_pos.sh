#!/usr/bin/env bash
# POS test-node entrypoint: B1 strict verifier (phase B) for ONE variant shard.
#
# Variables (set by dispatch_b1_verify_pos.py via pos.allocations.set_variables):
#   A4_VARIANT         V1..V5
#   A4_CAMPAIGN_NAME   label for pos_upload
#   A4_HOST_ARGS       default "--in1 5 --in4 10"
#   A4_RUN_ID          unique run id
#
# Before launch, dispatcher copies:
#   /root/b1_verify/<db_basename>   — one POS smoke DB for this shard
# Bundle at /root/a4_campaign/ provides risc0-host + repo (audit scripts).

set -euo pipefail

_required() {
    local key="$1" val
    if ! val=$(pos_get_variable "$key" 2>&1); then
        echo "[run_verify_b1] FATAL: required variable '$key' not set" >&2
        exit 87
    fi
    printf '%s' "$val"
}

A4_VARIANT=$(_required A4_VARIANT)
A4_CAMPAIGN_NAME=$(_required A4_CAMPAIGN_NAME)
A4_HOST_ARGS=$(pos_get_variable A4_HOST_ARGS 2>/dev/null || echo "--in1 5 --in4 10")
A4_EXPECTED_N=$(pos_get_variable A4_EXPECTED_N 2>/dev/null || echo "")
A4_RUN_ID=$(pos_get_variable A4_RUN_ID 2>/dev/null || echo "b1_verify_${A4_VARIANT}_$(date +%s)")
A4_NODE=$(pos_get_variable hostname 2>/dev/null || hostname)

WORK="/root/a4_campaign"
REPO_DIR="$WORK/repo"
HOST_BIN="$WORK/bin/risc0-host"
VERIFY_DIR="/root/b1_verify"
RESULTS="/root/b1_verify_results/${A4_CAMPAIGN_NAME}_${A4_VARIANT}"

upload_results() {
    local rc=$?
    mkdir -p "$RESULTS"
    cp -a "$VERIFY_DIR/out/"* "$RESULTS/" 2>/dev/null || true
    cp -a "$VERIFY_DIR/"*.db "$RESULTS/" 2>/dev/null || true
    echo "[run_verify_b1] exit=$rc uploading $RESULTS" >&2
    pos_upload "$RESULTS" -r -f 2>/dev/null || \
        echo "[run_verify_b1] WARN: pos_upload failed" >&2
    exit "$rc"
}
trap upload_results EXIT

if [[ ! -x "$HOST_BIN" ]]; then
    echo "[run_verify_b1] FATAL: host missing at $HOST_BIN" >&2
    exit 2
fi

mkdir -p "$VERIFY_DIR/out" "$RESULTS"
# Dispatcher copies DB to /root/*.db — stage into VERIFY_DIR for glob resolver
shopt -s nullglob
for db in /root/pos_audit_*.db; do
    cp -a "$db" "$VERIFY_DIR/"
done
shopt -u nullglob
if ! compgen -G "$VERIFY_DIR/*.db" >/dev/null; then
    echo "[run_verify_b1] FATAL: no pos_audit_*.db staged in $VERIFY_DIR" >&2
    ls -la /root "$VERIFY_DIR" >&2 || true
    exit 2
fi

LOG="$RESULTS/${A4_RUN_ID}.log"
mkdir -p "$(dirname "$LOG")"

{
    echo "=== B1 verify shard ==="
    date -u +"%Y-%m-%dT%H:%M:%SZ"
    echo "node=$A4_NODE variant=$A4_VARIANT"
    echo "host=$HOST_BIN"
    ls -la "$VERIFY_DIR"/*.db
} | tee "$LOG"

cd "$REPO_DIR"
export PYTHONUNBUFFERED=1

# shellcheck disable=SC2206
HOST_ARR=($A4_HOST_ARGS)
python3 a4/audits/B1_hook_fidelity.py \
    --db-dir "$VERIFY_DIR" \
    --variants "$A4_VARIANT" \
    --host "$HOST_BIN" \
    ${A4_EXPECTED_N:+--expected-n "$A4_EXPECTED_N"} \
    --output "$VERIFY_DIR/out/B1_${A4_VARIANT}.json" \
    -- "${HOST_ARR[@]}" \
    2>&1 | tee -a "$LOG"

echo "[run_verify_b1] DONE variant=$A4_VARIANT" | tee -a "$LOG"
