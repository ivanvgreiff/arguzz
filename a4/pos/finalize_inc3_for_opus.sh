#!/usr/bin/env bash
# Collect coinbase B1 shards, merge, re-run B2, print gate summary for Opus.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO/a4/audits/audit_output"
SHARD_LOCAL="$OUT/b1_verify_shards"
REMOTE="${POS_USER:-ivgreiff}@${POS_HOST:-coinbase.net.in.tum.de}"
PORT="${POS_PORT:-10022}"

mkdir -p "$SHARD_LOCAL"
scp -P "$PORT" "$REMOTE:~/b1_verify_work/out/B1_V"*.json "$SHARD_LOCAL/" 2>/dev/null || {
    echo "WARN: could not scp all shards yet" >&2
    ls -la "$SHARD_LOCAL" || true
    exit 2
}

cd "$REPO"
python3 a4/audits/merge_b1_verify_shards.py \
    --shard-dir "$SHARD_LOCAL" \
    --output "$OUT/B1_hook_fidelity.json" \
    --prevalidate "$OUT/B1_hook_fidelity.json"

python3 a4/audits/B2_multicycle_replay.py
python3 a4/audits/B7_seed_reproducibility.py --smoke-dir "$OUT/inc3_b7/"

echo ""
echo "=== Inc 3 gate summary ==="
python3 - <<'PY'
import json
from pathlib import Path
out = Path("a4/audits/audit_output")
for name in ["B1_hook_fidelity", "B2_multicycle_replay", "B4_bandit_db_traceability", "B7_seed_reproducibility"]:
    p = out / f"{name}.json"
    if p.exists():
        d = json.loads(p.read_text())
        print(f"{name}: {d.get('verdict', '?')}")
PY
