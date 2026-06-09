#!/usr/bin/env bash
# Phase 7b — run all five IV.POS.7 smoke variants on POS (coinbase mgmt → test node).
#
# Prereqs (on coinbase, after git pull):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   Bundle at ~/a4_campaign_<sha>.tar.gz (see prepare_bundle note below)
#
# Usage (in tmux):
#   bash a4/pos/run_smoke_7b_pos.sh flare
#   bash a4/pos/run_smoke_7b_pos.sh          # picks first free default node
#
# Bundle rebuild on coinbase (after git pull; host is NOT in git — must exist locally):
#   find workspace -name risc0-host -type f
#   bash a4/pos/prepare_bundle.sh --allow-dirty
#   cp bundles/a4_campaign_*.tar.gz ~/

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first:" >&2
    echo "  source /srv/testbed/pos/cli/venv3/bin/activate" >&2
    exit 1
fi

NODE="${1:-}"
if [[ -z "$NODE" ]]; then
    NODE=$(pos nodes list | awk '$2=="host" && $3=="booted" && $4=="None" {print $1; exit}')
fi
if [[ -z "$NODE" ]]; then
    echo "ERROR: no free node; pass one explicitly: bash a4/pos/run_smoke_7b_pos.sh flare" >&2
    exit 1
fi

BUNDLE=$(ls -t ~/a4_campaign_*.tar.gz 2>/dev/null | head -1 || true)
if [[ -z "$BUNDLE" ]]; then
    BUNDLE=$(ls -t "$REPO_ROOT"/bundles/a4_campaign_*.tar.gz 2>/dev/null | head -1 || true)
fi
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: no bundle found. On coinbase run:" >&2
    echo "  find workspace -name risc0-host -type f" >&2
    echo "  bash a4/pos/prepare_bundle.sh --allow-dirty   # or --host <path>" >&2
    echo "  cp bundles/a4_campaign_*.tar.gz ~/" >&2
    exit 1
fi

echo "=== Phase 7b POS smoke ==="
echo "  node:   $NODE"
echo "  bundle: $BUNDLE"
echo "  log:    /tmp/smoke_7b_pos.log"
echo

MANIFESTS=(
    a4/pos/manifests/smoke_7b/pos_smoke_7b_zoned.json
    a4/pos/manifests/smoke_7b/pos_smoke_7b_kindUCB_zoned_v1.json
    a4/pos/manifests/smoke_7b/pos_smoke_7b_kindUCB_zoned_v2_noQ.json
    a4/pos/manifests/smoke_7b/pos_smoke_7b_kindTS_zoned_v2.json
    a4/pos/manifests/smoke_7b/pos_smoke_7b_cTS_semantic_v2.json
)

FAIL=0
for mf in "${MANIFESTS[@]}"; do
    echo "--- dispatch: $mf ---"
    if ! python -m a4.pos.dispatch_pos \
        --manifest "$mf" \
        --bundle "$BUNDLE" \
        --nodes "$NODE" \
        --allocation-duration 240 \
        --await \
        2>&1 | tee -a /tmp/smoke_7b_pos.log; then
        echo "FAIL: $mf" >&2
        FAIL=1
    fi
done

if [[ $FAIL -ne 0 ]]; then
    echo "Phase 7b: one or more dispatches failed" >&2
    exit 1
fi
echo "Phase 7b: all five dispatches finished. Collect DBs from POS result folder."
