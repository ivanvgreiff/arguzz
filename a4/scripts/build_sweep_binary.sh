#!/usr/bin/env bash
# Build a Track-B (multi-guest coverage sweep) risc0-host from the CLEAN worktree,
# stamp its build-provenance fingerprint, archive it READ-ONLY, and self-check the guard.
#
# Isolation invariants (IV.POS.9 B1.1):
#   - source  = workspace/risc0-clean-28e53771   (clean D2.H baseline; NEVER risc0-modified)
#   - build   = workspace/output-trackb          (its own target/; points only at the worktree)
#   - archive = a4/builds/sweep/28e53771_clean__<guest_slug>/  (read-only 0555)
#   - planted_bug = none, load_rs2_present = 1    (asserted by the guard before any run)
#
# Usage:  bash a4/scripts/build_sweep_binary.sh [guest_slug]   (default: g0_baseline)
#         DRY_RUN=1 bash a4/scripts/build_sweep_binary.sh ...   (print env/paths, no build)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WT="$ROOT/workspace/risc0-clean-28e53771"        # clean Track-B worktree
OUT_WS="$ROOT/workspace/output-trackb"           # isolated Track-B build workspace
BUILD_DIR="$ROOT/a4/builds/sweep"
GUEST_SLUG="${1:-g0_baseline}"
COMMIT_LABEL="28e53771_clean"
OUT_DIR="$BUILD_DIR/${COMMIT_LABEL}__${GUEST_SLUG}"

# --- safety: refuse to run if the wiring isn't isolated (defense in depth) ---
if grep -rq "workspace/risc0-modified" "$OUT_WS"/host/Cargo.toml "$OUT_WS"/methods/Cargo.toml "$OUT_WS"/methods/guest/Cargo.toml 2>/dev/null; then
    echo "FATAL: $OUT_WS still references the SHARED risc0-modified tree — isolation broken, aborting." >&2
    exit 3
fi
test -d "$WT" || { echo "FATAL: clean worktree $WT missing" >&2; exit 3; }

# --- per-guest source swap: copy this guest's source into the build workspace BEFORE building ---
# (Track-B guest sources are versioned in a4/runs/iv_pos_9/sweep/guests/<slug>/; the build
#  workspace is scratch. Swapping before provenance makes guest_src_sha reflect the right guest.)
GUEST_SRC_DIR="$ROOT/a4/runs/iv_pos_9/sweep/guests/$GUEST_SLUG"
if [[ -f "$GUEST_SRC_DIR/guest_main.rs" && -f "$GUEST_SRC_DIR/host_main.rs" ]]; then
    echo "[build_sweep] swapping in guest source from $GUEST_SRC_DIR"
    cp "$GUEST_SRC_DIR/guest_main.rs" "$OUT_WS/methods/guest/src/main.rs"
    cp "$GUEST_SRC_DIR/host_main.rs" "$OUT_WS/host/src/main.rs"
else
    echo "[build_sweep] WARN: no source dir at $GUEST_SRC_DIR — building current output-trackb content" >&2
fi

# --- provenance fields, derived from the actual worktree (un-spoofable) ---
RISC0_SHA="$(git -C "$WT" rev-parse HEAD)"
LOAD_RS2_PRESENT="$(grep -c 'fn load_rs2' "$WT/risc0/circuit/rv32im/src/execute/rv32im.rs" || true)"
INSTR_HASH="$(cat \
    "$WT/risc0/circuit/rv32im/src/prove/witgen/mod.rs" \
    "$WT/risc0/circuit/rv32im-sys/kernels/cxx/ffi.cpp" 2>/dev/null | sha256sum | awk '{print $1}')"
GUEST_SRC="$OUT_WS/methods/guest/src/main.rs"
GUEST_SRC_SHA="$(sha256sum "$GUEST_SRC" | awk '{print $1}')"

if [[ "$LOAD_RS2_PRESENT" -lt 1 ]]; then
    echo "FATAL: clean worktree reports load_rs2 absent (=vulnerable!) — wrong baseline, aborting." >&2
    exit 3
fi

echo "[build_sweep] guest_slug=$GUEST_SLUG"
echo "[build_sweep] worktree=$WT @ ${RISC0_SHA:0:12}  load_rs2_present=$LOAD_RS2_PRESENT (expect 1)"
echo "[build_sweep] build_ws=$OUT_WS   archive=$OUT_DIR"
echo "[build_sweep] instrumentation_hash=${INSTR_HASH:0:16}  guest_src_sha=${GUEST_SRC_SHA:0:16}"

if [[ "${DRY_RUN:-0}" == "1" ]]; then
    echo "[build_sweep] DRY_RUN=1 — skipping cargo build + archive"; exit 0
fi

# --- build (compiles entirely against the clean worktree via output-trackb's Cargo paths) ---
export A4_PLANTED_BUG="none"
export A4_ISREAD_SCOPE=""
export A4_RISC0_HEAD_SHA="$RISC0_SHA"
export A4_LOAD_RS2_PRESENT="$LOAD_RS2_PRESENT"
export A4_INSTRUMENTATION_HASH="$INSTR_HASH"
echo "[build_sweep] cargo build --release -p risc0-host (planted_bug=none) ..."
( cd "$OUT_WS" && cargo build --release -p risc0-host )

# --- archive READ-ONLY (0555 = read+execute, no write → cannot be accidentally overwritten) ---
HOST_BIN="$OUT_WS/target/release/risc0-host"
test -f "$HOST_BIN" || { echo "FATAL: build produced no binary at $HOST_BIN" >&2; exit 4; }
mkdir -p "$OUT_DIR"
# clear any prior read-only copy first (chmod +w so cp can overwrite intentionally)
[[ -f "$OUT_DIR/risc0-host" ]] && chmod u+w "$OUT_DIR/risc0-host"
cp "$HOST_BIN" "$OUT_DIR/risc0-host"
HOST_SHA="$(sha256sum "$OUT_DIR/risc0-host" | awk '{print $1}')"
cat > "$OUT_DIR/fingerprint.json" <<EOF
{
  "track": "B_sweep",
  "commit_label": "$COMMIT_LABEL",
  "guest_slug": "$GUEST_SLUG",
  "risc0_head_sha": "$RISC0_SHA",
  "load_rs2_present": $LOAD_RS2_PRESENT,
  "planted_bug": "none",
  "isread_scope": "",
  "instrumentation_hash": "$INSTR_HASH",
  "guest_src_sha256": "$GUEST_SRC_SHA",
  "host_sha256": "$HOST_SHA"
}
EOF
chmod 0555 "$OUT_DIR/risc0-host"          # read-only + executable
chmod 0444 "$OUT_DIR/fingerprint.json"

# --- self-check: the archived binary must PASS the sweep guard ---
echo "[build_sweep] guard self-check (must PASS as 'sweep'):"
python3 -m a4.pos.fingerprint_guard "$OUT_DIR/risc0-host" --profile sweep \
  || { echo "FATAL: archived binary FAILS the sweep guard — do not deploy." >&2; exit 5; }

echo "[build_sweep] DONE -> $OUT_DIR/risc0-host (read-only)"
