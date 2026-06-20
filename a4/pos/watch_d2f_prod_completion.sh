#!/usr/bin/env bash
# Poll F.2 chain until CHAIN_COMPLETE, then run exit gate + collection manifest.
set -euo pipefail
LOG=/tmp/chain_d2f_prod.log
RESULTS=/srv/testbed/results/ivgreiff/a4/d2f_prod
ARGUZZ=~/arguzz

echo "[d2f_watch] watching $LOG ..."
while ! grep -q 'CHAIN_COMPLETE' "$LOG" 2>/dev/null; do
  if grep -q 'CHAIN_ABORT' "$LOG" 2>/dev/null; then
    echo "[d2f_watch] CHAIN_ABORT detected"; tail -20 "$LOG"; exit 1
  fi
  tail -3 "$LOG" 2>/dev/null || true
  sleep 300
done

echo "[d2f_watch] CHAIN_COMPLETE — running exit gate"
cd "$ARGUZZ"
PYTHONPATH=repo python3 -m a4.pos.validate_d2f_f1_gate "$RESULTS" --expected-n 10000 \
  | tee /tmp/d2f_f2_exit_gate.log

PYTHONPATH=repo python3 -m a4.pos.generate_d2f_collection_manifest \
  "$RESULTS" --out "$RESULTS/d2f_collection_manifest.json"

echo "[d2f_watch] done — see $RESULTS/d2f_collection_manifest.json"
