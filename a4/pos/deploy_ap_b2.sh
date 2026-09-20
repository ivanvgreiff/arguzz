#!/usr/bin/env bash
# Deploy AP.B2 dual-host bundle to POS triage nodes. Run ON coinbase.
set -euo pipefail

NODES=(flare zone goracle algofi opulous polynize octorand gard)
BUNDLE="${BUNDLE:-$HOME/a4_ap_campaign.tar.gz}"
BASENAME="$(basename "$BUNDLE")"

if [[ ! -f "$BUNDLE" ]]; then
  echo "ERROR: bundle missing: $BUNDLE" >&2
  exit 1
fi

echo "[deploy_ap_b2] nodes=${NODES[*]} bundle=$BUNDLE"
for n in "${NODES[@]}"; do
  echo "[deploy_ap_b2] $n: scp + extract..."
  scp -q -o ConnectTimeout=20 -o StrictHostKeyChecking=no "$BUNDLE" "${n}:/root/${BASENAME}"
  ssh -o ConnectTimeout=20 -o StrictHostKeyChecking=no "$n" \
    "set -e; cd /root; rm -rf a4_ap_campaign; tar -xzf ${BASENAME}; \
     test -x a4_ap_campaign/bin/risc0-host-patched; \
     test -x a4_ap_campaign/bin/risc0-host-bench-isread; \
     PYTHONPATH=/root/a4_ap_campaign/repo python3 -c 'import a4.scripts.ap_b2_run_one' && \
     echo OK_${n}"
done
echo "[deploy_ap_b2] DONE"
