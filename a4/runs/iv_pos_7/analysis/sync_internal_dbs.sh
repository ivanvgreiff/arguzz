#!/usr/bin/env bash
# Sync V0 (uniform) + V6 (arguzz) DBs from coinbase → local dbs/.
# coinbase SSH: port 10022 (see POS_PLAYBOOK / PHASE_8_LIVE_STATE).
# Incomplete V6 runs filtered at analysis time via meta.json exit_code in discover.py.

set -euo pipefail

COINBASE="${COINBASE:-ivgreiff@coinbase.net.in.tum.de}"
SSH_PORT="${SSH_PORT:-10022}"
REMOTE_BASE="/srv/testbed/results/ivgreiff/a4"
LOCAL_DBS="$(cd "$(dirname "$0")/.." && pwd)/dbs"

RSYNC_SSH="ssh -p ${SSH_PORT}"
RSYNC=(rsync -avzm -e "${RSYNC_SSH}")

echo "=== Sync IV.POS.7 internal DBs ==="
echo "Remote: ${COINBASE}:${REMOTE_BASE} (port ${SSH_PORT})"
echo "Local:  ${LOCAL_DBS}"
mkdir -p "${LOCAL_DBS}"

sync_batch() {
  local batch="$1"
  local remote="${REMOTE_BASE}/pos_iv_pos_7_${batch}"
  if ! ssh -p "${SSH_PORT}" "${COINBASE}" "test -d '${remote}'"; then
    echo "  ${batch}: not on remote yet"
    return 0
  fi
  echo "  rsync ${remote}/"
  "${RSYNC[@]}" --include='*/' --include='*.db' --include='meta.json' \
    --exclude='*' \
    "${COINBASE}:${remote}/" \
    "${LOCAL_DBS}/"
}

echo ""
echo "--- V0 (uniform) ---"
for batch in u_b1a u_b1b u_b1c u_b2; do
  sync_batch "${batch}"
done

echo ""
echo "--- V6 (arguzz) ---"
# Final V6 production batch names (5 batches × 2 seeds = 10 DBs):
# v6_b1a/b/c (initial 6) + v6_b2 (chain b2) + v6_b3 (chain v6_idle b1)
for batch in v6_b1a v6_b1b v6_b1c v6_b2 v6_b3; do
  sync_batch "${batch}"
done

echo ""
echo "=== Sync complete. Verify with: ==="
echo "  cd $(dirname "$0")/.. && python3 analysis/build_internal_artifacts.py"
