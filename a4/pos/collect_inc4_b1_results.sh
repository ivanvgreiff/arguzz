#!/usr/bin/env bash
# a4/pos/collect_inc4_b1_results.sh — Collect Inc 4 B1 verify results.
#
# Runs on COINBASE. Searches TWO locations per variant (in this order):
#   1. Coinbase's POS upload mirror: /srv/testbed/results/$USER/a4/<campaign>/
#      (where pos_upload sends results — survives node reset)
#   2. Each POS node's /root/b1_verify_results/ (transient — wiped on reset)
#
# This dual-source check is critical (added 2026-06-13 PM after collection-gap
# incident): when a node is reset between verifier completion and collection
# (e.g. because the SAME allocation gets re-purposed for the next dispatch),
# /root/b1_verify_results/ on the node is gone but the result IS in
# /srv/testbed/results/ from the in-job `pos_upload` call.
#
# Output tree:
#   ~/arguzz_b1_collect/
#       pos_inc4_b12_b1_in1_1/   B1_V1.json … B1_V5.json
#       pos_inc4_b12_b1_in100/   B1_V1.json … B1_V5.json
#       pos_inc4_b11_b1/         B1_V1.json … B1_V5.json
#
# After this script: rsync to WSL
#   rsync -av coinbase:~/arguzz_b1_collect/ \
#       /root/arguzz/a4/audits/audit_output/inc4_b1/
set -uo pipefail

NODES=(flare octorand opulous algofi meld)
CAMPAIGNS=(pos_inc4_b12_b1_in1_1 pos_inc4_b12_b1_in100 pos_inc4_b11_b1)
DEST="$HOME/arguzz_b1_collect"
TESTBED_ROOT="/srv/testbed/results/${USER:-ivgreiff}/a4"
mkdir -p "$DEST"

# Helper: validate a B1 JSON has the expected variant + nonzero total
validate_json() {
    local path="$1" v="$2"
    python3 -c "
import json,sys
try:
    d=json.load(open('$path'))
    pv=d['per_variant']['$v']
    if pv.get('total',0)>0:
        print(f\"{pv['pass']}/{pv['total']}\")
        sys.exit(0)
except Exception:
    pass
sys.exit(1)
" 2>/dev/null
}

for c in "${CAMPAIGNS[@]}"; do
    mkdir -p "$DEST/$c"
    for v in V1 V2 V3 V4 V5; do
        found=0; src=""

        # --------- SOURCE 1: testbed upload mirror (preferred, persistent) -------
        # pos_upload lands B1_<v>.json beside pos_<campaign>_<v>.log under
        # /srv/testbed/results/<user>/a4/<campaign>/<timestamp>/<node>/
        if [[ $found -eq 0 ]]; then
            cand=""
            while IFS= read -r f; do
                dir=$(dirname "$f")
                compgen -G "$dir/*${c}_${v}*" > /dev/null 2>&1 || continue
                ts=$(stat -c '%Y' "$f" 2>/dev/null) || continue
                if [[ -z "$cand" ]]; then
                    cand="$f"
                    cand_ts="$ts"
                elif [[ "$ts" -gt "$cand_ts" ]]; then
                    cand="$f"
                    cand_ts="$ts"
                fi
            done < <(find "$TESTBED_ROOT" -type f -name "B1_${v}.json" 2>/dev/null)
            if [[ -n "$cand" && -f "$cand" ]]; then
                cp "$cand" "$DEST/$c/B1_${v}.json" 2>/dev/null
                if pass=$(validate_json "$DEST/$c/B1_${v}.json" "$v"); then
                    echo "  ✓ $c/$v from testbed [$pass] ($cand)"
                    found=1; src="testbed"
                fi
            fi
        fi

        # --------- SOURCE 2: SSH to each node, check /root/ (fallback) ------------
        if [[ $found -eq 0 ]]; then
            for n in "${NODES[@]}"; do
                remote="/root/b1_verify_results/${c}_${v}/B1_${v}.json"
                if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no -o LogLevel=ERROR \
                    "root@$n" "test -f $remote" 2>/dev/null; then
                    scp -q -o StrictHostKeyChecking=no -o LogLevel=ERROR \
                        "root@$n:$remote" "$DEST/$c/B1_${v}.json" 2>/dev/null && {
                        if pass=$(validate_json "$DEST/$c/B1_${v}.json" "$v"); then
                            echo "  ✓ $c/$v from $n:/root/ [$pass]"
                            found=1; src="$n:/root"
                            break
                        fi
                    }
                fi
            done
        fi

        [[ $found -eq 0 ]] && echo "  ✗ $c/$v: NOT FOUND in testbed or any node /root/"
    done
done

echo
echo "Collection complete. Output in $DEST/"
ls -la "$DEST"/*/

# Surface any campaign that's incomplete
echo
echo "=== Coverage summary ==="
for c in "${CAMPAIGNS[@]}"; do
    n=$(ls "$DEST/$c"/B1_V*.json 2>/dev/null | wc -l)
    echo "  $c: $n/5 variants collected"
done
