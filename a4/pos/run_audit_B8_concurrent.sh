#!/usr/bin/env bash
# Phase 7d Inc 4 B8 — dispatch seq + par campaigns on POS.
#
# Usage (on coinbase after bundle scp):
#   bash a4/pos/run_audit_B8_concurrent.sh bitcoin
#   bash a4/pos/run_audit_B8_concurrent.sh flare bitcoin bitcoincash bitcoingold litecoin

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

SEQ_NODE="${1:-}"
shift || true
PAR_NODES=("$@")

if [[ -z "$SEQ_NODE" ]]; then
    echo "Usage: bash a4/pos/run_audit_B8_concurrent.sh SEQ_NODE [PAR_NODE ...]" >&2
    echo "  SEQ_NODE: single node for b8_seq (5 jobs queued serially)" >&2
    echo "  PAR_NODES: 5 nodes for b8_par (1 job each, true parallel)" >&2
    exit 2
fi

if [[ ${#PAR_NODES[@]} -lt 5 ]]; then
    echo "ERROR: b8_par needs 5 nodes; got ${#PAR_NODES[@]}" >&2
    exit 1
fi

echo "=== B8 sequential dispatch (1 node) ==="
bash a4/pos/run_inc4_pos.sh b8_seq "$SEQ_NODE"

echo "=== B8 parallel dispatch (5 nodes) ==="
bash a4/pos/run_inc4_pos.sh b8_par "${PAR_NODES[@]}"

echo "B8 POS campaigns complete. Collect DBs to:"
echo "  a4/audits/audit_output/inc4_b8/seq/"
echo "  a4/audits/audit_output/inc4_b8/par/"
echo "Then run on WSL:"
echo "  python3 -m a4.audits.B8_concurrent_isolation"
