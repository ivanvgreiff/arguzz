#!/usr/bin/env bash
# Pull Inc 3d Phase B artifacts from POS into a4/audits/audit_output/inc3d/.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
PASS="${INC3D_PASS:-1}"
OUT="$REPO/a4/audits/audit_output/inc3d/p${PASS}"
REMOTE="${INC3D_REMOTE:-ivgreiff@coinbase.net.in.tum.de}"
PORT="${INC3D_PORT:-10022}"
# PASS=b2 maps to the B4 mem-fingerprint campaign (Phase B2)
if [[ "$PASS" = "b2" ]]; then
    OUT="$REPO/a4/audits/audit_output/inc3d/b2"
    BASE="/srv/testbed/results/ivgreiff/a4/pos_inc3d_phase_b2"
else
    BASE="/srv/testbed/results/ivgreiff/a4/pos_inc3d_phase_b_p${PASS}"
fi

mkdir -p "$OUT/diffs" "$OUT/fingerprint/"{flare,octorand,opulous,meld}

SUFFIXES=(
    octoaA octoaB octobA octobB
    opugA opugB melddA melddB
    flareCtrlA flareCtrlB
)

echo "Pass $PASS — searching $BASE"
DB_PREFIX="pos_inc3d_phase_b_p${PASS}"
[[ "$PASS" = "b2" ]] && DB_PREFIX="pos_inc3d_phase_b2"
for suffix in "${SUFFIXES[@]}"; do
    for seed in 999 1000 1001; do
        remote_db=$(ssh -p "$PORT" "$REMOTE" \
            "find $BASE -name '${DB_PREFIX}_zoned_seed${seed}_n50_${suffix}.db' 2>/dev/null | sort -r | head -1" || true)
        if [[ -n "$remote_db" ]]; then
            scp -P "$PORT" "$REMOTE:$remote_db" "$OUT/" 2>/dev/null || true
            remote_log="${remote_db%.db}.log"
            scp -P "$PORT" "$REMOTE:$remote_log" "$OUT/" 2>/dev/null || true
            echo "  got $suffix (seed $seed)"
            break
        fi
    done
done

for node in flare octorand opulous meld; do
    fp=$(ssh -p "$PORT" "$REMOTE" \
        "find $BASE -path '*/${node}/fingerprint/env.txt' 2>/dev/null | sort -r | head -1 | xargs dirname 2>/dev/null" || true)
    if [[ -n "$fp" ]]; then
        scp -P "$PORT" "$REMOTE:${fp}/*" "$OUT/fingerprint/${node}/" 2>/dev/null || true
    fi
done

echo "Collected $(ls -1 "$OUT"/*.db 2>/dev/null | wc -l) DBs to $OUT"
