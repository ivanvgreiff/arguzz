#!/usr/bin/env bash
# Inc 3b §A.2 — B1 full strict verifier with patched host on coinbase login.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
OUT="$REPO/a4/audits/audit_output/inc3b"
B1_DIR="${B1_DB_DIR:-$REPO/a4/audits/audit_output/inc3_b1}"
HOST="${B1_HOST:-$REPO/workspace/output/target/release/risc0-host}"
WORK=~/b1_verify_inc3b

mkdir -p "$OUT" "$WORK/out"
if [[ ! -x "$HOST" ]]; then
    echo "ERROR: patched host not found: $HOST" >&2
    exit 1
fi
echo "host=$(sha256sum "$HOST" | awk '{print $1}')"

for vk in V1 V2 V3 V4 V5; do
    echo ">>> B1 $vk"
    PYTHONUNBUFFERED=1 python3 a4/audits/B1_hook_fidelity.py \
        --db-dir "$B1_DIR" \
        --variants "$vk" \
        --host "$HOST" \
        --output "$WORK/out/B1_${vk}.json" \
        > "$WORK/${vk}.log" 2>&1 &
done
wait
for vk in V1 V2 V3 V4 V5; do
    tail -1 "$WORK/${vk}.log"
    cp "$WORK/out/B1_${vk}.json" "$OUT/"
done
python3 a4/audits/merge_b1_verify_shards.py \
    --shard-dir "$WORK/out" \
    --output "$OUT/B1_merged.json" \
    --prevalidate "$REPO/a4/audits/audit_output/B1_hook_fidelity.json" 2>/dev/null || \
python3 a4/audits/merge_b1_verify_shards.py \
    --shard-dir "$WORK/out" \
    --output "$OUT/B1_merged.json"
echo "Done — shards in $OUT"
