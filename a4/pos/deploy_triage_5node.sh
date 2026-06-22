#!/usr/bin/env bash
# Deploy campaign bundle + D2.G triage code patch to the 5 dedicated triage nodes.
# Run ON coinbase (SSH access to pact stoi idex meld tinyman).
set -euo pipefail

NODES=(pact stoi idex meld tinyman)
BUNDLE="${BUNDLE:-$HOME/a4_campaign_da2e1393078c.tar.gz}"
PATCH_TGZ="${PATCH_TGZ:-$HOME/d2g_triage_patch.tgz}"
BASENAME="$(basename "$BUNDLE")"

if [[ ! -f "$BUNDLE" ]]; then
  echo "ERROR: bundle missing: $BUNDLE" >&2
  exit 1
fi
if [[ ! -f "$PATCH_TGZ" ]]; then
  echo "ERROR: patch missing: $PATCH_TGZ (scp from dev)" >&2
  exit 1
fi

echo "[deploy-triage] nodes=${NODES[*]} bundle=$BUNDLE"
for n in "${NODES[@]}"; do
  echo "[deploy-triage] $n: bundle..."
  scp -q -o ConnectTimeout=20 -o StrictHostKeyChecking=no "$BUNDLE" "${n}:/root/${BASENAME}"
  ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no "$n" \
    "set -e; cd /root; rm -rf a4_campaign; tar -xzf ${BASENAME}; test -x a4_campaign/bin/risc0-host"
  echo "[deploy-triage] $n: patch..."
  scp -q -o ConnectTimeout=20 -o StrictHostKeyChecking=no "$PATCH_TGZ" "${n}:/root/d2g_triage_patch.tgz"
  ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no "$n" \
    "set -e; cd /root/a4_campaign/repo; tar -xzf /root/d2g_triage_patch.tgz; rm -f /root/d2g_triage_patch.tgz; \
     PYTHONPATH=/root/a4_campaign/repo python3 -c 'import a4.runs.iv_pos_8.d2g.run_one_pos' && \
     echo OK_${n}"
done
echo "[deploy-triage] DONE"
