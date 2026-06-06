#!/usr/bin/env bash
# ============================================================
# DEFERRED OPTIONAL BACKEND — NOT THE DEFAULT PATH (Jun 4, 2026)
# ============================================================
# The primary backend is now the university POS testbed; see
# a4/pos/run_campaign_pos.sh for the POS-native test-node entrypoint.
# This script is kept because most of its structure (env-driven CLI
# build, DB+log+meta JSON, sha256 record, exit-code propagation)
# is reused there; only the upload mechanism (gsutil cp vs pos_upload)
# differs. Do not invoke this script for current campaigns.
# ============================================================

# Cloud entrypoint for one (strategy, seed) campaign.
#
# Required env vars:
#   A4_STRATEGY      uniform | zoned | bandit
#   A4_SEED          integer
#   A4_NUM           number of mutations
#   A4_BUCKET        GCS bucket name for results
#   A4_CAMPAIGN_NAME human-readable campaign label (e.g. "cloud_ab_v1")
#
# Optional:
#   A4_B_COUNT       bandit b-count override (default 16; ignored for non-bandit)
#   A4_HOST_ARGS     extra args to risc0-host after "--" (default "--in1 5 --in4 10")
#   A4_EXTRA_FUZZ    extra args to cli.py fuzz (default empty)
#   A4_RUN_ID        unique run identifier (default ${A4_STRATEGY}_seed${A4_SEED}_$(date +%s))
#
# Outputs (uploaded to gs://${A4_BUCKET}/results/${A4_CAMPAIGN_NAME}/${A4_RUN_ID}/):
#   campaign.db        - sqlite DB with all III.1/III.3 tables populated
#   campaign.log       - full stdout+stderr (for analyze_campaign.parse_terminal)
#   campaign.meta.json - one-row summary (start, end, exit code, num_recorded, binary_sha)

set -euo pipefail

: "${A4_STRATEGY:?required}"
: "${A4_SEED:?required}"
: "${A4_NUM:?required}"
: "${A4_BUCKET:?required}"
: "${A4_CAMPAIGN_NAME:?required}"

A4_B_COUNT="${A4_B_COUNT:-16}"
A4_HOST_ARGS="${A4_HOST_ARGS:---in1 5 --in4 10}"
A4_EXTRA_FUZZ="${A4_EXTRA_FUZZ:-}"
A4_RUN_ID="${A4_RUN_ID:-${A4_STRATEGY}_seed${A4_SEED}_$(date +%s)}"

WORK=/tmp/${A4_RUN_ID}
mkdir -p "$WORK"
DB="${WORK}/campaign.db"
LOG="${WORK}/campaign.log"
META="${WORK}/campaign.meta.json"

# 1. Binary verification (fail-loud if image was built wrong)
BINARY_SHA=$(sha256sum /app/bin/risc0-host | awk '{print $1}')
echo "[run_campaign] binary sha256: ${BINARY_SHA}" | tee "$LOG"

# 2. Build the CLI command
declare -a CMD=(
  python -m a4.standalone.cli fuzz
  --host /app/bin/risc0-host
  --selector "$A4_STRATEGY"
  --num "$A4_NUM"
  --seed "$A4_SEED"
  --db "$DB"
)
# bandit-only options
if [[ "$A4_STRATEGY" == "bandit" ]]; then
  CMD+=(--b-count "$A4_B_COUNT")
fi
# Extra fuzz args (e.g. --kind, --values), space-separated
if [[ -n "$A4_EXTRA_FUZZ" ]]; then
  # shellcheck disable=SC2206
  EXTRA_ARRAY=($A4_EXTRA_FUZZ)
  CMD+=("${EXTRA_ARRAY[@]}")
fi
CMD+=(--)
# Host args after "--", space-separated
# shellcheck disable=SC2206
HOST_ARRAY=($A4_HOST_ARGS)
CMD+=("${HOST_ARRAY[@]}")

echo "[run_campaign] command: ${CMD[*]}" | tee -a "$LOG"

# 3. Run, capturing exit code without aborting the bash script (we want to upload partial
#    output on failure too).
START_EPOCH=$(date +%s)
START_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
set +e
"${CMD[@]}" 2>&1 | tee -a "$LOG"
EXIT_CODE=${PIPESTATUS[0]}
set -e
END_EPOCH=$(date +%s)
END_ISO=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# 4. Recorded-mutation sanity check
if [[ -f "$DB" ]]; then
  N_RECORDED=$(sqlite3 "$DB" "SELECT COUNT(*) FROM mutations" 2>/dev/null || echo -1)
else
  N_RECORDED=-1
fi

# 5. Meta JSON
cat > "$META" <<EOF
{
  "campaign_name": "${A4_CAMPAIGN_NAME}",
  "run_id":         "${A4_RUN_ID}",
  "strategy":       "${A4_STRATEGY}",
  "seed":           ${A4_SEED},
  "num_requested":  ${A4_NUM},
  "num_recorded":   ${N_RECORDED},
  "b_count":        ${A4_B_COUNT},
  "host_args":      "${A4_HOST_ARGS}",
  "binary_sha256":  "${BINARY_SHA}",
  "started_at":     "${START_ISO}",
  "ended_at":       "${END_ISO}",
  "elapsed_seconds": $(( END_EPOCH - START_EPOCH )),
  "exit_code":      ${EXIT_CODE}
}
EOF

# 6. Upload to GCS
GCS_PREFIX="gs://${A4_BUCKET}/results/${A4_CAMPAIGN_NAME}/${A4_RUN_ID}"
echo "[run_campaign] uploading to ${GCS_PREFIX}/" | tee -a "$LOG"
gsutil -q cp "$META"           "${GCS_PREFIX}/campaign.meta.json"  || true
gsutil -q cp "$LOG"            "${GCS_PREFIX}/campaign.log"        || true
[[ -f "$DB" ]] && gsutil -q cp "$DB" "${GCS_PREFIX}/campaign.db"   || true

# 7. Propagate inner exit code so Cloud Run knows we failed
exit "$EXIT_CODE"
