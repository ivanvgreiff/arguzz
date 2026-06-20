#!/usr/bin/env bash
# Deploy campaign bundle to booted nodes via SSH bypass (POS_PLAYBOOK §12.52).
set -euo pipefail

NODES=(flare polynize octorand opulous algofi zone gard goracle)
BUNDLE="${BUNDLE:-$HOME/a4_campaign_da2e1393078c.tar.gz}"
BASENAME=$(basename "$BUNDLE")

if [[ ! -f "$BUNDLE" ]]; then
  echo "ERROR: bundle missing: $BUNDLE" >&2
  exit 1
fi

echo "[deploy] bundle=$BUNDLE nodes=${NODES[*]}"
for n in "${NODES[@]}"; do
  echo "[deploy] $n: scp bundle..."
  scp -q -o ConnectTimeout=15 -o StrictHostKeyChecking=no "$BUNDLE" "${n}:/root/${BASENAME}"
  echo "[deploy] $n: extract..."
  ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no "$n" \
    "set -e; cd /root; rm -rf a4_campaign; tar -xzf ${BASENAME}; test -f a4_campaign/repo/a4/standalone/l1_signals.py && test -x a4_campaign/bin/risc0-host && echo OK_${n}"
done
echo "[deploy] DONE"
