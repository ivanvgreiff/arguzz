#!/usr/bin/env bash
# Inc 3b §A.3 — paired fuzz determinism pre-fix vs post-fix host (reward fields).
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"
OUT="$REPO/a4/audits/audit_output/inc3b"
PRE_HOST="${PRE_HOST:-$HOME/arguzz_backups/risc0-host.FIXED.bin}"
POST_HOST="${POST_HOST:-$REPO/workspace/output/target/release/risc0-host}"
NUM="${NUM:-100}"
SEED="${SEED:-12345}"
WORK="${WORK:-/tmp/inc3b_smoke_ensemble}"

mkdir -p "$OUT" "$WORK"
for h in "$PRE_HOST" "$POST_HOST"; do
    if [[ ! -x "$h" ]]; then
        echo "ERROR: host not executable: $h" >&2
        exit 1
    fi
done

echo "pre=$(sha256sum "$PRE_HOST" | awk '{print $1}')"
echo "post=$(sha256sum "$POST_HOST" | awk '{print $1}')"

python3 -m a4.standalone.cli fuzz \
    --selector zoned --seed "$SEED" --num "$NUM" \
    --host "$PRE_HOST" --db "$WORK/pre.db" \
    -- --in1 5 --in4 10 > "$WORK/pre.log" 2>&1

python3 -m a4.standalone.cli fuzz \
    --selector zoned --seed "$SEED" --num "$NUM" \
    --host "$POST_HOST" --db "$WORK/post.db" \
    -- --in1 5 --in4 10 > "$WORK/post.log" 2>&1

python3 - "$WORK" "$OUT/smoke_ensemble.json" <<'PY'
import json, sqlite3, sys
from pathlib import Path

work = Path(sys.argv[1])
out = Path(sys.argv[2])
pre_db, post_db = work / "pre.db", work / "post.db"

def rows(path):
    c = sqlite3.connect(path)
    return c.execute(
        "SELECT id, kind, step, num_failures FROM mutations ORDER BY id"
    ).fetchall()

ra, rb = rows(pre_db), rows(post_db)
diffs = [i for i, (a, b) in enumerate(zip(ra, rb), 1) if a != b]
report = {
    "total_mutations": len(ra),
    "mutations_diff": len(diffs),
    "diff_mutation_ids": diffs[:50],
    "verdict": "PASS" if len(diffs) <= 10 else "REVIEW",
}
out.write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
PY

cat "$OUT/smoke_ensemble.json"
echo "Smoke ensemble done."
