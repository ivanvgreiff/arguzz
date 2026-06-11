#!/usr/bin/env bash
# Phase 7 Task 3 — V5 bandit-fix validation (single job, N=200) on flare.
#
# Prereqs on coinbase:
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   git pull (see a4/pos/coinbase_git_pull_fix.sh if conflicts)
#   Bundle at ~/a4_campaign_<sha>.tar.gz (scp from WSL)
#
# Usage:
#   bash a4/pos/run_smoke_7b_v5_fixed_pos.sh flare

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv: source /srv/testbed/pos/cli/venv3/bin/activate" >&2
    exit 1
fi

NODE="${1:-flare}"
BUNDLE=$(ls -t ~/a4_campaign_*.tar.gz 2>/dev/null | head -1 || true)
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: no ~/a4_campaign_*.tar.gz — scp bundle from WSL first" >&2
    exit 1
fi

MF="a4/pos/manifests/smoke_7b/pos_smoke_7b_v5_fixed_validation.json"
LOG="/tmp/smoke_7b_v5_fixed_pos.log"

echo "=== Phase 7 Task 3: V5 fixed validation ==="
echo "  node:   $NODE"
echo "  bundle: $BUNDLE"
echo "  manifest: $MF"
echo "  log:    $LOG"

python -m a4.pos.dispatch_pos \
    --manifest "$MF" \
    --bundle "$BUNDLE" \
    --nodes "$NODE" \
    --allocation-duration 120 \
    --await \
    2>&1 | tee "$LOG"

echo "Done. Collect DB from POS results folder (pos_smoke_7b_v5_fixed_*)."
