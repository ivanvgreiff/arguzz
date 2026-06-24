#!/usr/bin/env bash
# IV.POS.9 Track-B — one-command sweep orchestrator (run ON coinbase).
#
# Pipeline:
#   1. CLAIM the pre-existing reservation (calendar 1916/1917) for the 6 nodes
#      (`pos allocations allocate <nodes>` with NO --duration => uses the calendar event,
#      no new quota hit; evicts any squatter on a node we own per POS auto-evict).
#   2. Probe ssh-reachability; reset+wait any booted-but-unrouted node (optional, --reset).
#   3. Deploy the sweep bundle to every reachable node (deploy_sweep_nodes.sh).
#   4. Generate the screening manifest over the LIVE reachable node set.
#   5. Launch chain_dispatcher in a detached tmux session (self-driving, resume-safe).
#
# Resume across reservation blocks: re-run this script. Completed jobs (.OK markers on the
# remote) are skipped; nodes that rebooted at a block boundary are re-deployed first.
#
# Usage (on coinbase):
#   RUN=/tmp/ivg_sweep bash $RUN/a4_campaign/repo/a4/runs/iv_pos_9/sweep/run_sweep_pos.sh \
#       [--reset] [--guests "g1_ecall_control g2_mem_stress g3_accelerator"] [--seeds "1234 1235 1236"]
set -uo pipefail

RUN="${RUN:-/tmp/ivg_sweep}"
REPO="$RUN/a4_campaign/repo"
BUNDLE="${BUNDLE:-$(ls -t $RUN/sweep_*.tar.gz 2>/dev/null | head -1)}"
# Track-B-ONLY node pool. zone is RESERVED FOR TRACK A — never used here (2026-06-24).
NODES_ALL=(pact stoi idex meld tinyman)
GUESTS="${GUESTS:-g1_ecall_control g2_mem_stress g3_accelerator}"
SEEDS="${SEEDS:-1234 1235 1236}"
DO_RESET=0
RESULTS="$RUN/results"
TMUX_SESS="sweepb3"

while [[ $# -gt 0 ]]; do case "$1" in
    --reset) DO_RESET=1; shift;;
    --guests) GUESTS="$2"; shift 2;;
    --seeds)  SEEDS="$2"; shift 2;;
    *) echo "unknown arg: $1" >&2; exit 2;;
esac; done

[[ -f "$BUNDLE" ]] || { echo "FATAL: no bundle ($BUNDLE)"; exit 1; }
echo "[run] bundle=$BUNDLE  guests=($GUESTS)  seeds=($SEEDS)"

echo "[run] 1. claim reservation for: ${NODES_ALL[*]}"
pos allocations allocate "${NODES_ALL[@]}" -r a4/iv_pos_9_sweep 2>&1 | tail -4 || \
    echo "[run] (allocate returned nonzero — may already be held by us; continuing)"

echo "[run] 2. probe reachability"
LIVE=()
for n in "${NODES_ALL[@]}"; do
    if timeout 10 ssh -o ConnectTimeout=7 -o StrictHostKeyChecking=no "$n" 'true' 2>/dev/null; then
        LIVE+=("$n"); echo "   $n: reachable"
    else
        echo "   $n: UNREACHABLE"
        if [[ $DO_RESET -eq 1 ]]; then
            echo "   $n: resetting (boot fresh image)…"
            pos nodes reset "$n" 2>&1 | tail -2 || true
        fi
    fi
done
if [[ $DO_RESET -eq 1 ]]; then
    echo "[run] polling up to 360s for reset nodes to boot…"
    for attempt in $(seq 1 12); do
        sleep 30
        LIVE=()
        for n in "${NODES_ALL[@]}"; do
            timeout 10 ssh -o ConnectTimeout=7 -o StrictHostKeyChecking=no "$n" 'true' 2>/dev/null && LIVE+=("$n")
        done
        echo "   [t=$((attempt*30))s] reachable: ${LIVE[*]:-none} (${#LIVE[@]}/${#NODES_ALL[@]})"
        [[ ${#LIVE[@]} -eq ${#NODES_ALL[@]} ]] && break
    done
fi
[[ ${#LIVE[@]} -gt 0 ]] || { echo "FATAL: no reachable nodes"; exit 1; }
echo "[run] LIVE nodes: ${LIVE[*]}"

echo "[run] 3. deploy bundle to live nodes"
BUNDLE="$BUNDLE" bash "$REPO/a4/runs/iv_pos_9/sweep/deploy_sweep_nodes.sh" "${LIVE[@]}" || \
    echo "[run] (some deploys failed — chain will only use verified nodes below)"

echo "[run] 4. generate screening manifest over live set"
MANIFEST="$RUN/screening.chain"
PYTHONPATH="$REPO" python3 "$REPO/a4/runs/iv_pos_9/sweep/generate_sweep_manifests.py" \
    --stage screening --guests $GUESTS --seeds $SEEDS --nodes "${LIVE[@]}" \
    --out "$MANIFEST"
echo "   manifest: $MANIFEST"
grep -cvE '^#|^$' "$MANIFEST" | xargs echo "   jobs:"

echo "[run] 5. launch chain_dispatcher in tmux '$TMUX_SESS'"
mkdir -p "$RESULTS"
tmux kill-session -t "$TMUX_SESS" 2>/dev/null || true
tmux new-session -d -s "$TMUX_SESS" \
    "MANIFEST='$MANIFEST' CHAIN_NAME=sweepb3 RESULTS_BASE='$RESULTS' \
     LOG_FILE='$RUN/chain.log' POLL_SEC=20 \
     bash '$REPO/a4/runs/iv_pos_9/sweep/chain_dispatcher.sh' 2>&1 | tee -a '$RUN/chain_console.log'"
echo "[run] LAUNCHED. monitor:  tmux attach -t $TMUX_SESS   (or tail $RUN/chain.log)"
