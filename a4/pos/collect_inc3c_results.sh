#!/usr/bin/env bash
# Pull Inc 3c Phase δ artifacts from POS results into local inc3c/.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
OUT="$REPO/a4/audits/audit_output/inc3c"
REMOTE="${INC3C_REMOTE:-ivgreiff@coinbase.net.in.tum.de}"
PORT="${INC3C_PORT:-10022}"
BASE="/srv/testbed/results/ivgreiff/a4/pos_inc3c_phase_delta"

mkdir -p "$OUT/diffs" "$OUT/fingerprint/flare" "$OUT/fingerprint/octorand"

# Latest allocation dir on POS
ALLOC=$(ssh -p "$PORT" "$REMOTE" "ls -td ${BASE}/*/ 2>/dev/null | head -1" || true)
if [[ -z "$ALLOC" ]]; then
    echo "ERROR: no results under $BASE" >&2
    exit 1
fi
echo "Collecting from $ALLOC"

for suffix in octoaA octoaB octobA octobB octogA octogB octodA octodB flareCtrlA flareCtrlB; do
    for seed in 999 1000 1001; do
        pat="*zoned_seed${seed}_n50_${suffix}.db"
        remote_db=$(ssh -p "$PORT" "$REMOTE" "find $ALLOC -name 'pos_inc3c_phase_delta_zoned_seed${seed}_n50_${suffix}.db' 2>/dev/null | head -1" || true)
        if [[ -n "$remote_db" ]]; then
            scp -P "$PORT" "$REMOTE:$remote_db" "$OUT/" 2>/dev/null || true
            remote_log="${remote_db%.db}.log"
            scp -P "$PORT" "$REMOTE:$remote_log" "$OUT/" 2>/dev/null || true
            break
        fi
    done
done

for node in flare octorand; do
    fp=$(ssh -p "$PORT" "$REMOTE" "find $ALLOC -path '*/${node}/fingerprint/env.txt' 2>/dev/null | head -1 | xargs dirname 2>/dev/null" || true)
    if [[ -n "$fp" ]]; then
        scp -P "$PORT" "$REMOTE:${fp}/*" "$OUT/fingerprint/${node}/" 2>/dev/null || true
    fi
done

echo "Collected $(ls -1 "$OUT"/*.db 2>/dev/null | wc -l) DBs to $OUT"
