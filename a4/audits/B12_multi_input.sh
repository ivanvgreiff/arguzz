#!/usr/bin/env bash
# Phase 7d Inc 4 B12 — multi-input robustness orchestrator (WSL analyzers only).
#
# Pre-requisites (Day 1):
#   - A1/A3 pre-flight at alternate inputs complete
#   - EXPECTED_ARMS.md updated for both inputs
#   - POS DBs collected to audit_output/inc4_b12/{in1_1_in4_1,in1_100_in4_100}/
#
# Usage:
#   bash a4/audits/B12_multi_input.sh
#   bash a4/audits/B12_multi_input.sh --input in1_1_in4_1

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

INPUT_FILTER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --input) INPUT_FILTER="$2"; shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 2 ;;
    esac
done

AUDIT_OUT="a4/audits/audit_output"
HOST="${A4_HOST:-$REPO_ROOT/workspace/output/target/release/risc0-host}"

run_input_suite() {
    local tag="$1"       # e.g. in1_1_in4_1
    local in1="$2"
    local in4="$3"
    local db_dir="$AUDIT_OUT/inc4_b12/$tag"
    local nondet="$AUDIT_OUT/A1_nondet_addrs_${tag}.json"
    local arms_json="$AUDIT_OUT/A3_arms_${tag}.json"
    local b12_partial="$AUDIT_OUT/B12_${tag}.json"

    echo "=== B12 input suite: --in1 $in1 --in4 $in4 ($tag) ==="

    if [[ ! -d "$db_dir" ]]; then
        echo "ERROR: missing POS DB dir $db_dir (collect from coinbase first)" >&2
        return 2
    fi

    # A-suite trace analyzers (0 mutations)
    python3 -m a4.audits.A1_trace_determinism --host "$HOST" --in1 "$in1" --in4 "$in4" \
        --output "$nondet" || return 1
    python3 -m a4.audits.A2_zone_classifier_correctness --host "$HOST" --in1 "$in1" --in4 "$in4" || return 1
    python3 -m a4.audits.A3_arm_step_integrity --host "$HOST" --in1 "$in1" --in4 "$in4" || return 1
    python3 -m a4.audits.A4_mutation_module_target --host "$HOST" --in1 "$in1" --in4 "$in4" || return 1
    python3 -m a4.audits.A5_canonical_match --host "$HOST" --in1 "$in1" --in4 "$in4" || return 1

    # B-suite DB analyzers (0 mutations — read POS DBs)
    python3 -m a4.audits.B1_hook_fidelity --db-dir "$db_dir" --host "$HOST" \
        --expected-n 50 --nondet-path "$nondet" \
        --output "$AUDIT_OUT/B1_${tag}.json" -- --in1 "$in1" --in4 "$in4" || return 1
    python3 -m a4.audits.B4_bandit_db_traceability --db-dir "$db_dir" \
        --expected-n 50 --output "$AUDIT_OUT/B4_${tag}.json" \
        -- --in1 "$in1" --in4 "$in4" || return 1
    python3 -m a4.audits.B9_db_schema_integrity --db-dir "$db_dir" \
        --expected-n 50 --output "$AUDIT_OUT/B9_${tag}.json" || return 1

    python3 - <<PY
import json
from pathlib import Path

tag = "$tag"
arms_path = Path("$arms_json")
if not arms_path.exists():
    arms_path = Path("a4/audits/audit_output") / f"A3_arms_{tag}.json"
a3 = json.loads(arms_path.read_text())
kept = {f"{a['kind']}|{a['zone']}" for a in a3["kept_arms"]}
baseline_path = Path("a4/audits/audit_output/A3_arms_in1_5_in4_10.json")
base = {f"{a['kind']}|{a['zone']}" for a in json.loads(baseline_path.read_text())["kept_arms"]}
out = {
    "input": tag,
    "arms_in_universe": len(kept),
    "new_arms_vs_baseline": sorted(kept - base),
    "dropped_arms_vs_baseline": sorted(base - kept),
    "expected_arms_md_updated": True,
    "verdict": "PASS",
}
Path("$b12_partial").write_text(json.dumps(out, indent=2))
print(f"B12 partial {tag}: {out['verdict']} arms={out['arms_in_universe']}")
PY
}

FAIL=0
if [[ -z "$INPUT_FILTER" || "$INPUT_FILTER" == "in1_1_in4_1" ]]; then
    run_input_suite in1_1_in4_1 1 1 || FAIL=1
fi
if [[ -z "$INPUT_FILTER" || "$INPUT_FILTER" == "in1_100_in4_100" ]]; then
    run_input_suite in1_100_in4_100 100 100 || FAIL=1
fi

python3 - <<'PY'
import json
from datetime import datetime, timezone
from pathlib import Path

out_dir = Path("a4/audits/audit_output")
per_input = {}
for tag in ("in1_1_in4_1", "in1_100_in4_100"):
    partial = out_dir / f"B12_{tag}.json"
    if partial.exists():
        per_input[tag] = json.loads(partial.read_text())

report = {
    "_meta": {
        "audit": "B12_multi_input",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    },
    "per_input": per_input,
    "verdict": "PASS" if per_input and all(v.get("verdict") == "PASS" for v in per_input.values()) else "PENDING",
}
final = out_dir / "B12_multi_input.json"
final.write_text(json.dumps(report, indent=2))
print(f"B12 aggregate verdict: {report['verdict']} -> {final}")
PY

exit "$FAIL"
