#!/usr/bin/env bash
# IV.POS.9 Track-B — deploy the sweep bundle to POS nodes (run ON coinbase).
# SSH-bypass model (POS_PLAYBOOK §12.52): assumes each node is already booted + ssh-reachable.
# Per node: scp bundle -> /root, extract to /root/a4_campaign, verify imports + assert each
# guest binary is a clean sweep build (load_rs2=1, planted_bug=none) BEFORE it can ever run.
#
# Usage (on coinbase):
#   BUNDLE=/tmp/ivg_sweep/sweep_37f8e36e8565.tar.gz \
#     bash deploy_sweep_nodes.sh zone idex meld pact stoi tinyman
set -uo pipefail

BUNDLE="${BUNDLE:?set BUNDLE=/tmp/ivg_sweep/sweep_<short>.tar.gz}"
[[ -f "$BUNDLE" ]] || { echo "FATAL: bundle not found: $BUNDLE" >&2; exit 1; }
NODES=("$@")
[[ ${#NODES[@]} -gt 0 ]] || { echo "usage: BUNDLE=... $0 node1 [node2 ...]" >&2; exit 2; }
BASENAME="$(basename "$BUNDLE")"
GUESTS=(g1_ecall_control g2_mem_stress g3_accelerator)

ok=(); fail=()
for n in "${NODES[@]}"; do
    echo "===== [deploy] $n ====="
    if ! scp -q -o ConnectTimeout=15 -o StrictHostKeyChecking=no "$BUNDLE" "${n}:/root/${BASENAME}"; then
        echo "[deploy] $n: SCP FAILED (unreachable / not booted) — skipping"; fail+=("$n"); continue
    fi
    # Build the per-guest guard self-check loop remotely.
    guard_checks=""
    for g in "${GUESTS[@]}"; do
        guard_checks+="python3 -m a4.pos.fingerprint_guard /root/a4_campaign/builds/sweep/28e53771_clean__${g}/risc0-host --profile sweep || exit 7; "
    done
    if ssh -o ConnectTimeout=15 -o StrictHostKeyChecking=no "$n" "set -e
        cd /root && rm -rf a4_campaign && tar -xzf ${BASENAME} && rm -f ${BASENAME}
        test -x a4_campaign/builds/sweep/28e53771_clean__g1_ecall_control/risc0-host
        cd /root/a4_campaign/repo
        python3 -c 'import a4.pos.fingerprint_guard, a4.standalone.cli, a4.standalone.v6_uniform_driver, a4.standalone.variants'
        command -v python >/dev/null || { echo 'FATAL: python (not just python3) missing'; exit 8; }
        ${guard_checks}
        echo OK_${n}"; then
        echo "[deploy] $n: OK"; ok+=("$n")
    else
        echo "[deploy] $n: VERIFY FAILED"; fail+=("$n")
    fi
done
echo
echo "[deploy] SUMMARY ok=(${ok[*]:-}) fail=(${fail[*]:-})"
[[ ${#fail[@]} -eq 0 ]]
