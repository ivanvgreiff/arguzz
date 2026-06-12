#!/usr/bin/env bash
# Inc 3d Phase B — B1/B2/B3 instrumented host POS capture.
#
# PRE-RESERVATION: same as Inc 3c (ONE multi-node entry, --allocation-duration 0).
# SPREAD plan only (matches Inc 3c phase δ layout).
#
# Usage (coinbase, after bundle prep):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   export INC3D_B_BUNDLE=~/bundles/a4_campaign_<git>.tar.gz
#
#   # Pass 1: verbose + B2 FTW trace (large logs ~100 MB/run)
#   INC3D_PASS=1 SPREAD=1 bash a4/pos/run_inc3d_phase_b.sh 2>&1 | tee ~/inc3d_p1_dispatch.log
#
#   # Pass 2: B3 counter only (no verbose, no FTW trace)
#   INC3D_PASS=2 SPREAD=1 bash a4/pos/run_inc3d_phase_b.sh 2>&1 | tee ~/inc3d_p2_dispatch.log
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first" >&2
    exit 1
fi

PASS="${INC3D_PASS:-1}"
if [[ "$PASS" != "1" && "$PASS" != "2" ]]; then
    echo "ERROR: INC3D_PASS must be 1 or 2" >&2
    exit 1
fi

BUNDLE="${INC3D_B_BUNDLE:-}"
for candidate in \
    "$HOME/bundles/"a4_campaign_*.tar.gz \
    "$HOME/a4_campaign_inc3d_b.tar.gz"; do
    if [[ -z "$BUNDLE" && -f "$candidate" ]]; then
        BUNDLE="$candidate"
    fi
done
if [[ -z "$BUNDLE" || ! -f "$BUNDLE" ]]; then
    echo "ERROR: set INC3D_B_BUNDLE to instrumented-host tarball (632094ef…)" >&2
    exit 1
fi

EXPECTED="632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1"
ACTUAL=$(tar -xOf "$BUNDLE" a4_campaign/bundle.json | grep -o '"host_sha256": "[^"]*"' | awk '{print $2}' | tr -d '"')
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    echo "ERROR: bundle host sha mismatch" >&2
    echo "  expected $EXPECTED" >&2
    echo "  actual   $ACTUAL" >&2
    exit 1
fi

if ! tar -xOf "$BUNDLE" a4_campaign/repo/a4/core/executor.py 2>/dev/null \
     | grep -q "_A4_DIAG_LINE_RE"; then
    echo "ERROR: bundle missing Inc 3d executor diagnostic passthrough." >&2
    echo "       Rebuild bundle after pulling latest executor.py changes." >&2
    exit 1
fi

if [[ "${SPREAD:-0}" != "1" ]]; then
    echo "ERROR: Inc 3d Phase B requires SPREAD=1 (same layout as Inc 3c phase δ)." >&2
    exit 1
fi

OUT="${INC3D_OUT:-$HOME/inc3d_out_p${PASS}}"
mkdir -p "$OUT"
CAMPAIGN="pos_inc3d_phase_b_p${PASS}"

echo "INC3D_B_BUNDLE=$BUNDLE"
echo "host_sha256=$ACTUAL"
echo "INC3D_PASS=$PASS"
echo "campaign_name=$CAMPAIGN"
echo "executor passthrough: present"

write_manifest() {
    local seed="$1" suffix="$2" out="$3" verbose="$4" ftw_trace="$5"
    A4_MANIFEST_CAMPAIGN="$CAMPAIGN" \
    A4_MANIFEST_SUFFIX="$suffix" \
    A4_MANIFEST_SEED="$seed" \
    A4_MANIFEST_VERBOSE="$verbose" \
    A4_MANIFEST_FTW="$ftw_trace" \
    python3 - <<'PY' > "$out"
import json, os
job = {
    "strategy": "zoned",
    "seed": int(os.environ["A4_MANIFEST_SEED"]),
    "n": 50,
    "telemetry_level": "full",
    "run_suffix": os.environ["A4_MANIFEST_SUFFIX"],
    "coverage_touch_verbose": os.environ["A4_MANIFEST_VERBOSE"] == "1",
    "ftw291_trace": os.environ["A4_MANIFEST_FTW"] == "1",
}
print(json.dumps({
    "name": os.environ["A4_MANIFEST_CAMPAIGN"],
    "image": "debian-trixie",
    "guest_args": ["--in1", "5", "--in4", "10"],
    "jobs": [job],
}, indent=2))
PY
}

if [[ "$PASS" = "1" ]]; then
    VERBOSE=1
    FTW=1
    echo "Pass 1: A4_COVERAGE_TOUCH_VERBOSE=1 + A4_FTW291_TRACE=1 (expect large logs)"
else
    VERBOSE=0
    FTW=0
    echo "Pass 2: B3 counter only (no verbose, no FTW trace)"
fi

dispatch() {
    local manifest="$1" node="$2"
    echo "=== dispatch $node $(basename "$manifest") ==="
    PYTHONUNBUFFERED=1 python -m a4.pos.dispatch_pos \
        --manifest "$manifest" --bundle "$BUNDLE" --nodes "$node" \
        --allocation-duration 0 --await --await-timeout 5400
}

run_node_pair() {
    local node="$1" seed="$2" sa="$3" sb="$4"
    local tmp
    tmp=$(mktemp -d)
    write_manifest "$seed" "$sa" "$tmp/$sa.json" "$VERBOSE" "$FTW"
    write_manifest "$seed" "$sb" "$tmp/$sb.json" "$VERBOSE" "$FTW"
    dispatch "$tmp/$sa.json" "$node"
    dispatch "$tmp/$sb.json" "$node"
    rm -rf "$tmp"
}

( for pair in "999 octoaA octoaB" "999 octobA octobB"; do
      set -- $pair; run_node_pair octorand "$1" "$2" "$3"
  done ) > "$OUT/octo.log" 2>&1 &
PID_OCTO=$!
( run_node_pair opulous 1000 opugA opugB ) > "$OUT/opulous.log" 2>&1 &
PID_OPU=$!
( run_node_pair meld 1001 melddA melddB ) > "$OUT/meld.log" 2>&1 &
PID_MELD=$!
( run_node_pair flare 999 flareCtrlA flareCtrlB ) > "$OUT/flare.log" 2>&1 &
PID_FLARE=$!

fail=0
for name in OCTO OPU MELD FLARE; do
    pid_var="PID_$name"
    log_var="$(echo "$name" | tr A-Z a-z).log"
    if ! wait "${!pid_var}"; then
        echo "$name FAILED"; tail -100 "$OUT/$log_var"; fail=1
    fi
done
[[ "$fail" = 0 ]] || exit 1

echo "Inc 3d Phase B Pass $PASS complete. Logs under $OUT."
echo "Collect with: INC3D_PASS=$PASS bash a4/pos/collect_inc3d_results.sh"
