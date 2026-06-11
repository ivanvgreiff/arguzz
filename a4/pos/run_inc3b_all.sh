#!/usr/bin/env bash
# Inc 3b optimized dispatch — B1 POS then B7 gamma (~20-30 min wall on POS).
# Run on coinbase: source /srv/testbed/pos/cli/venv3/bin/activate && bash a4/pos/run_inc3b_all.sh
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
echo "=== Inc 3b §A.2 B1 verify (POS, 5-way, ~10 min) ==="
bash "$DIR/run_inc3b_b1_verify_pos.sh" "$@"
echo "=== Inc 3b §B.2 B7 gamma (parallel pairs + verbose, ~10 min) ==="
bash "$DIR/run_inc3b_b7_gamma.sh" intra "${1:-flare}" "${2:-octorand}"
echo "=== Inc 3b dispatch complete ==="
