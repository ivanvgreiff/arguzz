#!/bin/bash
# Inc 3d Phase B local regression test.
# Runs the patched host N times with mutation 27 (MEM_VAL_MOD step 3259) and
# verifies the verbose/accum/coverage tag SHAs are stable run-to-run.
#
# After each Phase B patch:
#   * before-B1: gold hashes are
#       v=ac56a7278b17faa7  accum=bf4891cb80a0d2b1  cov=b99b53555d06c752
#   * after-B1: verbose and accum hashes will change (new attrs in opening tag).
#     Coverage hash MUST remain unchanged.
#   * after-B2 (without A4_FTW291_TRACE=1): all three hashes must equal the B1 baseline.
#   * after-B3 (without A4_COVERAGE_TOUCH_VERBOSE=1): verbose/accum hashes will be empty;
#     coverage hash must remain unchanged, and the new <a4_ftw291_95_count> tag must appear.
#
# Usage:
#   inc3d_local_regression.sh [N=30] [HOST=/root/arguzz/workspace/output/target/release/risc0-host]
set -u
N=${1:-30}
HOST=${2:-/root/arguzz/workspace/output/target/release/risc0-host}
CFG=/tmp/inc3d_repro/mut27.json
OUT=/tmp/inc3d_regression
mkdir -p "$OUT"
cd "$(dirname "$HOST")/../.." || exit 1   # cd into workspace/output

if [ ! -x "$HOST" ]; then
    echo "ERROR: host binary not found or not executable: $HOST" >&2
    exit 2
fi
if [ ! -f "$CFG" ]; then
    echo "ERROR: mutation config not found: $CFG" >&2
    echo "Re-create with:" >&2
    echo "  mkdir -p /tmp/inc3d_repro" >&2
    echo '  echo ''{"mutation_type": "MEM_VAL_MOD", "step": 3259, "txn_idx": 29184, "word": 4294967295}'' > /tmp/inc3d_repro/mut27.json' >&2
    exit 2
fi

echo "=== Inc 3d local regression test ==="
echo "  host: $HOST"
echo "  host sha: $(sha256sum "$HOST" | cut -c1-16)..."
echo "  config: $CFG"
echo "  runs: $N"
echo ""

START=$(date +%s)
for i in $(seq 1 "$N"); do
    pad=$(printf '%03d' $i)
    A4_MUTATION_CONFIG=$CFG \
    A4_COVERAGE_TOUCH=1 \
    A4_COVERAGE_TOUCH_VERBOSE=1 \
    A4_FAMILY_RESIDUE=1 \
    CONSTRAINT_CONTINUE=1 \
    timeout 120 "$HOST" --in1 5 --in4 10 > "$OUT/run_${pad}.log" 2>&1 || true
    if (( i % 10 == 0 )); then
        elapsed=$(( $(date +%s) - START ))
        echo "  run $i/$N done (elapsed ${elapsed}s)"
    fi
done
echo "=== Done. Total: $(( $(date +%s) - START ))s ==="
echo ""
echo "=== Hash distribution (CONTENT-ONLY: B1 self-id attrs stripped) ==="
echo "Pre-B1 gold hashes: v=ac56a7278b17faa7  accum=bf4891cb80a0d2b1  cov=b99b53555d06c752"
echo ""
echo "verbose body:"
for f in $OUT/run_*.log; do
    [ -s "$f" ] || continue
    grep -oE '<a4_touch_verbose[^>]*>\[.*\]</a4_touch_verbose>' "$f" 2>/dev/null \
        | sed -E 's@<a4_touch_verbose[^>]*>@<a4_touch_verbose>@' \
        | sha256sum | cut -c1-16
done | sort | uniq -c
echo ""
echo "accum_verbose body:"
for f in $OUT/run_*.log; do
    [ -s "$f" ] || continue
    grep -oE '<a4_accum_touch_verbose[^>]*>\[.*\]</a4_accum_touch_verbose>' "$f" 2>/dev/null \
        | sed -E 's@<a4_accum_touch_verbose[^>]*>@<a4_accum_touch_verbose>@' \
        | sha256sum | cut -c1-16
done | sort | uniq -c
echo ""
echo "coverage:"
for f in $OUT/run_*.log; do
    [ -s "$f" ] || continue
    grep -o '<a4_touch_coverage>.*</a4_touch_coverage>' "$f" 2>/dev/null | sha256sum | cut -c1-16
done | sort | uniq -c
echo ""
echo "ftw291_95_count (witgen+accum, body hash):"
for f in $OUT/run_*.log; do
    [ -s "$f" ] || continue
    grep -h '<a4_ftw291_95_count' "$f" | sha256sum | cut -c1-16
done | sort | uniq -c

if grep -l '<a4_ftw291_95_count' "$OUT"/run_*.log > /dev/null 2>&1; then
    echo ""
    echo "B3 counter sample:"
    grep -h '<a4_ftw291_95_count' "$OUT"/run_001.log
fi
if grep -l 'mut="' "$OUT"/run_*.log > /dev/null 2>&1; then
    echo ""
    echo "B1 self-id sample (mut + pid + seq should appear):"
    grep -ho '<a4_touch_verbose [^>]*>' "$OUT"/run_001.log | head -1
fi
