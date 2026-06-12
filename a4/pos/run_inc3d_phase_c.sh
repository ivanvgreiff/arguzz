#!/usr/bin/env bash
# Inc 3d Phase C — closure campaign to achieve 100% certainty on the race.
#
# Modes (set MODE=…):
#   path_a1         RAYON_NUM_THREADS=1, no fingerprint, B P1 host (632094ef…)
#                   SPREAD plan (4 nodes × 5 pairs).
#   path_a1_octobb  single octobB run on octorand (completes the missing pair
#                   from the first path_a1 dispatch).
#   path_a2         RAYON_NUM_THREADS=1 + RISC0_THREADS=1 + OMP_NUM_THREADS=1
#                   ("scorched earth" single-thread mode).  SPREAD plan.
#   b5_default      preflight fingerprint ON, default parallelism, B5 host
#                   (1bd8e9ec…).  SPREAD plan.
#   b5_rayon1       preflight fingerprint ON + RAYON_NUM_THREADS=1, B5 host.
#                   SPREAD plan.  Head-to-head with b5_default.
#   b5_wide         preflight fingerprint + WIDE per-cell hashes ON.  Very
#                   large logs (~30 MB/run).  SPREAD plan.
#
# Bundle selection (auto):
#   path_a*  ->  $INC3D_C_BUNDLE_BP1   (default ~/INC3D_PHASE_C_BUNDLE.tar.gz)
#                expected host_sha256 = 632094ef… (B P1)
#   b5_*     ->  $INC3D_C_BUNDLE_B5    (default ~/INC3D_PHASE_C_B5_BUNDLE.tar.gz)
#                expected host_sha256 = 1bd8e9ec… (B5)
#
# Override at runtime to use a different bundle.
#
# Optional: INC3D_C_RUN_TAG=<tag>  -> appends "_<tag>" to the campaign name so
# multiple dispatches of the same MODE do not overwrite each other on POS.
#
# Usage (coinbase, after bundle prep + calendar reservation):
#   source /srv/testbed/pos/cli/venv3/bin/activate
#   export INC3D_C_BUNDLE_BP1=~/INC3D_PHASE_C_BUNDLE.tar.gz
#   export INC3D_C_BUNDLE_B5=~/INC3D_PHASE_C_B5_BUNDLE.tar.gz
#
#   MODE=path_a1   SPREAD=1 bash a4/pos/run_inc3d_phase_c.sh 2>&1 | tee ~/c_path_a1.log
#   MODE=b5_default SPREAD=1 bash a4/pos/run_inc3d_phase_c.sh 2>&1 | tee ~/c_b5_default.log
#   MODE=b5_rayon1  SPREAD=1 bash a4/pos/run_inc3d_phase_c.sh 2>&1 | tee ~/c_b5_rayon1.log
#   MODE=path_a1_octobb bash a4/pos/run_inc3d_phase_c.sh 2>&1 | tee ~/c_path_a1_octobb.log

set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python >/dev/null 2>&1; then
    echo "ERROR: activate POS venv first" >&2
    exit 1
fi

MODE="${MODE:-}"
case "$MODE" in
    path_a1|path_a1_octobb|path_a2|b5_default|b5_rayon1|b5_wide) ;;
    *)
        echo "ERROR: set MODE=path_a1|path_a1_octobb|path_a2|b5_default|b5_rayon1|b5_wide" >&2
        exit 1
        ;;
esac

EXPECTED_BP1="632094efdcf713387b3f9cfb69b3a6e25e89cf48a29413e0f7ae0e1e89dadee1"
EXPECTED_B5="1bd8e9ec3a95547126490ef3087f33bf90234a0d6800ad962a2fa9a124890788"

case "$MODE" in
    path_a*)
        BUNDLE="${INC3D_C_BUNDLE_BP1:-$HOME/INC3D_PHASE_C_BUNDLE.tar.gz}"
        EXPECTED="$EXPECTED_BP1"
        ;;
    b5_*)
        BUNDLE="${INC3D_C_BUNDLE_B5:-$HOME/INC3D_PHASE_C_B5_BUNDLE.tar.gz}"
        EXPECTED="$EXPECTED_B5"
        ;;
esac

if [[ ! -f "$BUNDLE" ]]; then
    echo "ERROR: bundle not found at $BUNDLE" >&2
    echo "       Set INC3D_C_BUNDLE_BP1 or INC3D_C_BUNDLE_B5 to override." >&2
    exit 1
fi

ACTUAL=$(tar -xOf "$BUNDLE" a4_campaign/bundle.json | grep -o '"host_sha256": "[^"]*"' | awk '{print $2}' | tr -d '"')
if [[ "$ACTUAL" != "$EXPECTED" ]]; then
    echo "ERROR: bundle host sha mismatch for MODE=$MODE" >&2
    echo "  expected $EXPECTED" >&2
    echo "  actual   $ACTUAL" >&2
    exit 1
fi

# Sanity: bundle must contain Phase C launcher knobs (RAYON / PREFLIGHT plumbing).
N_KNOBS=$(tar -xOf "$BUNDLE" a4_campaign/repo/a4/pos/run_campaign_pos.sh \
    | grep -c "A4_PREFLIGHT_FINGERPRINT\|A4_RAYON_THREADS" || true)
if [[ "$N_KNOBS" -lt 4 ]]; then
    echo "ERROR: bundle missing Phase C launcher knobs (expected >=4 matches, got $N_KNOBS)." >&2
    echo "       Rebuild bundle after re-applying Phase C edits to run_campaign_pos.sh." >&2
    exit 1
fi

# SPREAD enforcement: only path_a1_octobb is a single-node run, rest require SPREAD=1.
if [[ "$MODE" != "path_a1_octobb" ]]; then
    if [[ "${SPREAD:-0}" != "1" ]]; then
        echo "ERROR: Inc 3d Phase C MODE=$MODE requires SPREAD=1." >&2
        exit 1
    fi
fi

RUN_TAG="${INC3D_C_RUN_TAG:-}"
CAMP_BASE="pos_inc3d_phase_c_${MODE}"
if [[ -n "$RUN_TAG" ]]; then
    CAMP_BASE="${CAMP_BASE}_${RUN_TAG}"
fi
OUT="${INC3D_OUT:-$HOME/inc3d_out_c_${MODE}${RUN_TAG:+_$RUN_TAG}}"
mkdir -p "$OUT"

# Mode -> jobspec knobs (per-MODE constants).
PREFLIGHT_FP=0
PREFLIGHT_WIDE=0
RAYON=""
RISC0=""
OMP=""
case "$MODE" in
    path_a1)        RAYON=1 ;;
    path_a1_octobb) RAYON=1 ;;
    path_a2)        RAYON=1; RISC0=1; OMP=1 ;;
    b5_default)     PREFLIGHT_FP=1 ;;
    b5_rayon1)      PREFLIGHT_FP=1; RAYON=1 ;;
    b5_wide)        PREFLIGHT_FP=1; PREFLIGHT_WIDE=1 ;;
esac

echo "INC3D Phase C — MODE=$MODE"
echo "  bundle:       $BUNDLE"
echo "  host_sha256:  $ACTUAL"
echo "  campaign:     $CAMP_BASE"
echo "  out dir:      $OUT"
echo "  preflight_fp: $PREFLIGHT_FP   preflight_wide: $PREFLIGHT_WIDE"
echo "  RAYON: ${RAYON:-(default)}   RISC0: ${RISC0:-(default)}   OMP: ${OMP:-(default)}"

write_manifest() {
    local seed="$1" suffix="$2" out="$3"
    A4_MANIFEST_CAMPAIGN="$CAMP_BASE" \
    A4_MANIFEST_SUFFIX="$suffix" \
    A4_MANIFEST_SEED="$seed" \
    A4_MANIFEST_PFFP="$PREFLIGHT_FP" \
    A4_MANIFEST_PFWIDE="$PREFLIGHT_WIDE" \
    A4_MANIFEST_RAYON="$RAYON" \
    A4_MANIFEST_RISC0="$RISC0" \
    A4_MANIFEST_OMP="$OMP" \
    python3 - <<'PY' > "$out"
import json, os
def _opt_int(name):
    v = os.environ.get(name, "")
    return int(v) if v else None
job = {
    "strategy": "zoned",
    "seed": int(os.environ["A4_MANIFEST_SEED"]),
    "n": 50,
    "telemetry_level": "full",
    "run_suffix": os.environ["A4_MANIFEST_SUFFIX"],
    "preflight_fingerprint": os.environ["A4_MANIFEST_PFFP"] == "1",
    "preflight_fingerprint_wide": os.environ["A4_MANIFEST_PFWIDE"] == "1",
    "rayon_threads": _opt_int("A4_MANIFEST_RAYON"),
    "risc0_threads": _opt_int("A4_MANIFEST_RISC0"),
    "omp_threads":   _opt_int("A4_MANIFEST_OMP"),
}
print(json.dumps({
    "name": os.environ["A4_MANIFEST_CAMPAIGN"],
    "image": "debian-trixie",
    "guest_args": ["--in1", "5", "--in4", "10"],
    "jobs": [job],
}, indent=2))
PY
}

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
    write_manifest "$seed" "$sa" "$tmp/$sa.json"
    write_manifest "$seed" "$sb" "$tmp/$sb.json"
    dispatch "$tmp/$sa.json" "$node"
    dispatch "$tmp/$sb.json" "$node"
    rm -rf "$tmp"
}

if [[ "$MODE" = "path_a1_octobb" ]]; then
    tmp=$(mktemp -d)
    write_manifest 999 octobB "$tmp/octobB.json"
    dispatch "$tmp/octobB.json" octorand
    rm -rf "$tmp"
    echo "Inc 3d Phase C MODE=path_a1_octobb complete (single octobB run)."
    echo "Collect with: INC3D_PASS=c_${MODE}${RUN_TAG:+_$RUN_TAG} bash a4/pos/collect_inc3d_results.sh"
    exit 0
fi

# SPREAD plan: 4 nodes in parallel, 5 pairs total (octorand has 2 pairs: α + β).
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

echo "Inc 3d Phase C MODE=$MODE complete. Logs under $OUT."
echo "Collect with: INC3D_PASS=c_${MODE}${RUN_TAG:+_$RUN_TAG} bash a4/pos/collect_inc3d_results.sh"
