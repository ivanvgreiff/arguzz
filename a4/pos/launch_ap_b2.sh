#!/usr/bin/env bash
# AP.B2 POS launcher — screen then bracket via chain_dispatcher. Run ON coinbase.
set -euo pipefail

REPO="${REPO:-$HOME/arguzz}"
AP_DIR="${AP_DIR:-$REPO/a4/runs/iv_pos_9/ap}"
POLL_SEC="${POLL_SEC:-10}"
NODES=(flare zone goracle algofi opulous polynize octorand gard)

cmd="${1:-all}"

do_preflight() {
  echo "=== AP.B2 preflight ==="
  for n in "${NODES[@]}"; do
    echo -n "$n: "
    ssh -o BatchMode=yes -o ConnectTimeout=10 "$n" \
      "test -x /root/a4_ap_campaign/bin/risc0-host-patched && \
       test -x /root/a4_ap_campaign/bin/risc0-host-bench-isread && echo OK" \
      || { echo "FAIL"; exit 1; }
  done
  test -f "$AP_DIR/ap_b2_screen.chain" || { echo "missing screen chain"; exit 1; }
}

do_screen() {
  echo "=== AP.B2 screen dispatch ==="
  MANIFEST="$AP_DIR/ap_b2_screen.chain" \
  CHAIN_NAME=ap_b2_screen \
  LOG_FILE=/tmp/ap_b2_screen.log \
  POLL_SEC="$POLL_SEC" \
  RESULTS_BASE=/tmp/ap_b2_screen_results \
  bash "$REPO/a4/pos/chain_dispatcher.sh"
}

do_bracket() {
  echo "=== AP.B2 bracket dispatch ==="
  test -f "$AP_DIR/ap_b2_bracket.chain" || { echo "missing bracket chain — run gather screen first"; exit 1; }
  MANIFEST="$AP_DIR/ap_b2_bracket.chain" \
  CHAIN_NAME=ap_b2_bracket \
  LOG_FILE=/tmp/ap_b2_bracket.log \
  POLL_SEC="$POLL_SEC" \
  RESULTS_BASE=/tmp/ap_b2_bracket_results \
  bash "$REPO/a4/pos/chain_dispatcher.sh"
}

do_gather_screen() {
  export PYTHONPATH="$REPO"
  python3 "$REPO/a4/scripts/ap_b2_gather.py" \
    --phase screen \
    --screen-results /tmp/ap_b2_screen_results \
    --out-dir "$AP_DIR"
  python3 "$REPO/a4/scripts/ap_b2_gen_manifest.py" bracket \
    --corpus "$AP_DIR/ap_corpus_010.json" \
    --out "$AP_DIR/ap_b2_bracket.chain"
}

do_gather_all() {
  export PYTHONPATH="$REPO"
  python3 "$REPO/a4/scripts/ap_b2_gather.py" \
    --phase all \
    --screen-results /tmp/ap_b2_screen_results \
    --bracket-results /tmp/ap_b2_bracket_results \
    --out-dir "$AP_DIR"
}

case "$cmd" in
  preflight) do_preflight ;;
  screen) do_screen ;;
  gather-screen) do_gather_screen ;;
  bracket) do_bracket ;;
  gather) do_gather_all ;;
  all)
    do_preflight
    do_screen
    do_gather_screen
    do_bracket
    do_gather_all
    ;;
  *) echo "usage: $0 {preflight|screen|gather-screen|bracket|gather|all}" >&2; exit 2 ;;
esac
