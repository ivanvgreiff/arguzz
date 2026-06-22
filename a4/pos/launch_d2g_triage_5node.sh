#!/usr/bin/env bash
# Launch 1022-job D2.G triage chain on pact stoi idex meld tinyman (from coinbase).
set -euo pipefail

REPO="${REPO:-$HOME/d2g_triage_repo}"
CHAIN="${CHAIN:-$REPO/a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4/d2g_triage_b4_5node.chain}"
MANIFEST_DIR="${MANIFEST_DIR:-$REPO/a4/runs/iv_pos_8/d2f/prod/artifacts/d2g/triage_at_scale_b4}"
OUT_DIR="${OUT_DIR:-$MANIFEST_DIR}"
COLLECT_DIR="${COLLECT_DIR:-/tmp/d2g_triage_collected/merged}"
POLL_SEC="${POLL_SEC:-10}"
LOG="${LOG:-/tmp/d2g_triage_5node.log}"
RESULTS_BASE="${RESULTS_BASE:-/tmp/d2g_triage_chain_results}"

export PYTHONPATH="$REPO"
export TRIAGE_NODES="pact stoi idex meld tinyman"

cd "$REPO"
echo "=== preflight (ssh) ==="
for n in pact stoi idex meld tinyman; do
  ssh -o ConnectTimeout=10 "$n" \
    "test -x /root/a4_campaign/bin/risc0-host && cd /root/a4_campaign/repo && PYTHONPATH=/root/a4_campaign/repo python3 -c 'import a4.runs.iv_pos_8.d2g.run_one_pos' && echo OK_$n" \
    || { echo "FAIL $n"; exit 1; }
done

echo "=== dispatch (POLL_SEC=${POLL_SEC}) ==="
MANIFEST="$CHAIN" \
  CHAIN_NAME=d2g_triage_5node \
  LOG_FILE="$LOG" \
  POLL_SEC="$POLL_SEC" \
  RESULTS_BASE="$RESULTS_BASE" \
  bash a4/pos/chain_dispatcher.sh

echo "=== gather (ssh) ==="
GATHER_ROOT="${COLLECT_DIR%/merged}"
mkdir -p "$GATHER_ROOT/merged"
for n in pact stoi idex meld tinyman; do
  mkdir -p "$GATHER_ROOT/$n"
  scp -q -o ConnectTimeout=15 "${n}:/tmp/d2g_triage_results/*.json" "$GATHER_ROOT/$n/" 2>/dev/null || true
  for f in "$GATHER_ROOT/$n"/*.json; do
    [[ -f "$f" ]] || continue
    base=$(basename "$f")
    [[ -f "$GATHER_ROOT/merged/$base" ]] || cp "$f" "$GATHER_ROOT/merged/$base"
  done
done
echo "merged $(ls "$GATHER_ROOT/merged"/*.json 2>/dev/null | wc -l) json files"

echo "=== collect + soundness (needs pandas on coinbase) ==="
if python3 -c 'import pandas' 2>/dev/null; then
  TRIAGE_NODES="pact stoi idex meld tinyman" bash a4/pos/dispatch_d2g_triage.sh collect
  TRIAGE_NODES="pact stoi idex meld tinyman" bash a4/pos/dispatch_d2g_triage.sh soundness
else
  echo "SKIP collect/soundness — install pandas on coinbase or run locally after scp merged/"
fi
