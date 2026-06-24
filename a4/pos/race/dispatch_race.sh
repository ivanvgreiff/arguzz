#!/usr/bin/env bash
# Track-A (A3 Seam-B race) POS launch wrapper — runs ON COINBASE.
#
# Track-A-ISOLATED copy of the deploy+chain pattern (POS_PLAYBOOK §12.52/§12.53 + ★ templates).
# A concurrent Track-B (sweep) OCP uses the SAME shared scripts (chain_dispatcher.sh,
# fingerprint_guard.py) on DIFFERENT nodes; this wrapper namespaces everything (tmux session,
# CHAIN_NAME, RESULTS_BASE, manifest path) under "race_*" so the two never collide. It does
# NOT modify any shared script — it invokes chain_dispatcher.sh read-only with isolated env.
#
# Pre-reqs (operator/Ivan): the assigned nodes are RESERVED + booted on **debian-trixie**
# (GLIBC 2.39 — §12.30; risc0-host won't load on bookworm), and SSH-reachable from coinbase.
# The HOLED bundle (built by prepare_bundle.sh --host .../bench-verifyopcode/risc0-host) is at
# $BUNDLE on coinbase.
#
# Usage (on coinbase; venv active; ~/arguzz present):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   BUNDLE=~/a4_campaign_<sha>.tar.gz STAGE=smoke N=2000 \
#     bash a4/pos/race/dispatch_race.sh flare zone goracle algofi
#   # monitor: tail -F /tmp/chain_race_smoke.log
set -euo pipefail

NODES=("$@")
[ ${#NODES[@]} -ge 1 ] || { echo "usage: BUNDLE=.. STAGE=smoke N=2000 dispatch_race.sh <node> [node...]" >&2; exit 2; }
STAGE="${STAGE:-smoke}"
N="${N:-2000}"
BUNDLE="${BUNDLE:?set BUNDLE=~/a4_campaign_<sha>.tar.gz (the HOLED bundle)}"
REPO="${REPO:-$HOME/arguzz}"
SEEDS="${SEEDS:-}"
CHAIN_NAME="race_${STAGE}"
RESULTS_BASE="${RESULTS_BASE:-$HOME/race_results/${CHAIN_NAME}}"
POLL_SEC="${POLL_SEC:-30}"
BASENAME="$(basename "$BUNDLE")"
SSH_OPTS=(-o ConnectTimeout=20 -o StrictHostKeyChecking=no)

[ -f "$BUNDLE" ] || { echo "ERROR: bundle missing: $BUNDLE" >&2; exit 1; }

echo "[race] stage=$STAGE N=$N nodes=${NODES[*]} bundle=$BASENAME"

# 1. deploy the holed bundle to each assigned node (SSH-bypass)
for n in "${NODES[@]}"; do
  echo "[race-deploy] $n: scp + extract"
  scp -q "${SSH_OPTS[@]}" "$BUNDLE" "${n}:/root/${BASENAME}"
  ssh "${SSH_OPTS[@]}" "$n" \
    "set -e; cd /root; rm -rf a4_campaign; tar -xzf ${BASENAME}; \
     test -x a4_campaign/bin/risc0-host && test -f a4_campaign/repo/a4/pos/fingerprint_guard.py && echo OK_${n}"
done

# 2. CONTAMINATION GUARD (G-FP): every node's binary MUST be the verifyopcode-holed build.
#    (The manifest also guard-prefixes each job; this is the earlier, fail-fast check.)
for n in "${NODES[@]}"; do
  ssh "${SSH_OPTS[@]}" "$n" \
    "cd /root/a4_campaign/repo && python3 -m a4.pos.fingerprint_guard /root/a4_campaign/bin/risc0-host --profile verifyopcode" \
    || { echo "[race] ABORT: $n binary is NOT the verifyopcode-holed build" >&2; exit 87; }
done

# 3. generate the race manifest with the REAL assigned nodes
cd "$REPO"
MAN="/tmp/${CHAIN_NAME}.manifest"
SEED_ARG=(); [ -n "$SEEDS" ] && SEED_ARG=(--seeds $SEEDS)
python3 -m a4.pos.generate_race_manifests --stage "$STAGE" --n "$N" --nodes "${NODES[@]}" "${SEED_ARG[@]}" --out "$MAN"
echo "[race] manifest: $MAN ($(grep -cvE '^#|^$' "$MAN") jobs)"

# 4. launch the shared chain_dispatcher in a race-NAMESPACED tmux session (isolated env)
mkdir -p "$RESULTS_BASE"
SESS="chain_${CHAIN_NAME}"
tmux kill-session -t "$SESS" 2>/dev/null || true
tmux new -d -s "$SESS" \
  "MANIFEST='$MAN' CHAIN_NAME='$CHAIN_NAME' POLL_SEC=$POLL_SEC RESULTS_BASE='$RESULTS_BASE' REMOTE_BASE=/tmp/chainjob PULL_GLOB='*' bash '$REPO/a4/pos/chain_dispatcher.sh'"
echo "[race] chain launched in tmux '$SESS'."
echo "[race] monitor:  ssh -p 10022 ivgreiff@coinbase.net.in.tum.de 'tail -F /tmp/chain_${CHAIN_NAME}.log'"
echo "[race] results -> $RESULTS_BASE/"
