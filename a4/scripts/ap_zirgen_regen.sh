#!/usr/bin/env bash
# AP Route 1: offline zirgen codegen → vendored copy into risc0-modified.
#
# RISC Zero never runs zirgen at cargo build time; build.rs compiles committed
# kernels/cxx/*.cpp and the rv32im crate uses committed src/zirgen/*.rs.
# The /root/arguzz/zirgen clone is reference-only — we mimic the vendor workflow:
#   bazel codegen (offline) → bootstrap copy → cargo build.
#
# A4 harness (NOT zirgen output — never overwritten by bootstrap):
#   kernels/cxx/{ffi.cpp,witgen.h,eval_check.cpp}
#   rv32im/src/prove/witgen/mod.rs (A4_MUTATION_CONFIG, etc.)
#
# Prerequisites:
#   - Run build spike first: bash a4/scripts/ap_zirgen_build_spike.sh
#   - bazelisk on PATH (USE_BAZEL_VERSION=6.0.0 from zirgen/.bazelversion)
#   - zirgen clone at $ROOT/zirgen (not part of arguzz repo; user-provided)
#   - First build: large LLVM/MLIR fetch + compile (30–90+ min typical)
#
# Strategy (Option B default — AP self-consistent on df6fb9d):
#   1. control-regen   — unmodified .zir → install + snapshot (patched baseline)
#   2. honest-gate     — rebuild host, confirm guest proves+verifies (HARD gate)
#   3. holed-regen      — MemoryReadNoIsRead .zir → install + snapshot (bench)
#   4. build --from-regen
#
# control-check (byte/semantic diff vs committed) is OPTIONAL comparability (Option A).
# Failure does NOT block AP if honest-gate passes — committed circuit may come from
# a different zirgen revision with no recorded pin.
#
# Usage:
#   bash a4/scripts/ap_zirgen_regen.sh control-regen    # install unmodified + snapshot
#   bash a4/scripts/ap_zirgen_regen.sh control-check    # diff vs committed (soft/info)
#   bash a4/scripts/ap_zirgen_regen.sh honest-gate      # hard: guest honest proof
#   bash a4/scripts/ap_zirgen_regen.sh holed-regen      # install holed + snapshot
#   bash a4/scripts/ap_zirgen_regen.sh semantic-diff    # PolyExt opcode diff (info)
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ZIRGEN="$ROOT/zirgen"
RISC0="$ROOT/workspace/risc0-modified"
BOOTSTRAP="$ZIRGEN/zirgen/bootstrap"
MEM_ZIR="$ZIRGEN/zirgen/circuit/rv32im/v2/dsl/mem.zir"
INST_ZIR="$ZIRGEN/zirgen/circuit/rv32im/v2/dsl/inst.zir"
SNAP_BASE="$ROOT/a4/builds/ap/regen-snapshots"
export USE_BAZEL_VERSION="${USE_BAZEL_VERSION:-6.0.0}"
AP_ZIRGEN_ROOT="$ROOT"
# shellcheck source=/dev/null
source "$ROOT/a4/scripts/ap_zirgen_bazel_common.sh"

# Paths bootstrap rv32im_v2 may overwrite (see bootstrap/src/main.rs rv32im_v2).
# Deliberately excludes ffi.cpp, witgen.h, eval_check.cpp (A4 harness).
REGEN_PATHS=(
    "risc0/circuit/rv32im/src/zirgen"
    "risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp"
    "risc0/circuit/rv32im-sys/kernels/cxx/steps.h"
    "risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_0.cpp"
    "risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_1.cpp"
    "risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_2.cpp"
    "risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_3.cpp"
    "risc0/circuit/rv32im-sys/kernels/cxx/layout.cpp.inc"
    "risc0/circuit/rv32im-sys/kernels/cxx/layout.h.inc"
    "risc0/circuit/rv32im-sys/kernels/cxx/defs.cpp.inc"
    "risc0/circuit/rv32im-sys/kernels/cxx/types.h.inc"
    "risc0/circuit/rv32im-sys/kernels/cuda/steps.cu"
    "risc0/circuit/rv32im-sys/kernels/cuda/steps.cuh"
    "risc0/circuit/rv32im-sys/kernels/cuda/eval_check_0.cu"
    "risc0/circuit/rv32im-sys/kernels/cuda/eval_check_1.cu"
    "risc0/circuit/rv32im-sys/kernels/cuda/eval_check_2.cu"
    "risc0/circuit/rv32im-sys/kernels/cuda/eval_check_3.cu"
    "risc0/circuit/rv32im-sys/kernels/cuda/eval_check.cuh"
    "risc0/circuit/rv32im-sys/kernels/cuda/layout.cu.inc"
    "risc0/circuit/rv32im-sys/kernels/cuda/layout.cuh.inc"
)

usage() {
    sed -n '1,35p' "$0"
    exit "${1:-0}"
}

require_bazel() {
    if ! command -v bazelisk >/dev/null 2>&1 && ! command -v bazel >/dev/null 2>&1; then
        echo "ERROR: bazelisk/bazel not found. Install bazelisk and set USE_BAZEL_VERSION=6.0.0" >&2
        exit 1
    fi
}

zirgen_head() {
    git -C "$ZIRGEN" rev-parse HEAD
}

snap_dir() {
    local label="$1"
    echo "$SNAP_BASE/${label}-$(zirgen_head | cut -c1-12)"
}

ap_zir_edits_present() {
    grep -q "MemoryReadNoIsRead" "$MEM_ZIR" \
        && grep -q "MemoryReadNoIsRead(cycle, addr)" "$INST_ZIR"
}

stash_ap_zir_edits() {
    if ap_zir_edits_present; then
        echo "[regen] stashing AP .zir edits"
        git -C "$ZIRGEN" stash push -m "ap-b2-holed-zir" \
            -- zirgen/circuit/rv32im/v2/dsl/mem.zir \
               zirgen/circuit/rv32im/v2/dsl/inst.zir
        return 0
    fi
    return 1
}

restore_ap_zir_edits() {
    if git -C "$ZIRGEN" stash list | grep -q "ap-b2-holed-zir"; then
        echo "[regen] restoring AP .zir edits from stash"
        git -C "$ZIRGEN" stash pop
    elif ! ap_zir_edits_present; then
        echo "ERROR: holed .zir edits missing and no stash to restore" >&2
        exit 1
    fi
}

restore_committed_circuit() {
    echo "[regen] restoring committed circuit (strip Route 2 surgical patches)"
    git -C "$RISC0" checkout HEAD -- \
        risc0/circuit/rv32im/src/zirgen \
        risc0/circuit/rv32im-sys/kernels/cxx \
        risc0/circuit/rv32im-sys/kernels/cuda
}

snapshot_regen() {
    local dest="$1"
    mkdir -p "$dest"
    for rel in "${REGEN_PATHS[@]}"; do
        if [[ -e "$RISC0/$rel" ]]; then
            mkdir -p "$dest/$(dirname "$rel")"
            rsync -a "$RISC0/$rel" "$dest/$rel"
        fi
    done
    echo "$(zirgen_head)" > "$dest/zirgen_head.txt"
    date -Iseconds > "$dest/snapshot_time.txt"
    echo "[regen] snapshot -> $dest"
}

restore_snapshot() {
    local src="$1"
    for rel in "${REGEN_PATHS[@]}"; do
        if [[ -e "$src/$rel" ]]; then
            mkdir -p "$RISC0/$(dirname "$rel")"
            rsync -a "$src/$rel" "$RISC0/$rel"
        fi
    done
}

run_bootstrap() {
    local mode="$1"  # check | install
    local extra=()
    [[ "$mode" == "check" ]] && extra+=(--check)
    ap_zirgen_ensure_conda_pruned
    echo "[regen] zirgen $(zirgen_head) bootstrap rv32im-v2 ($mode) [native bazel]"
    (cd "$ZIRGEN" && ZIRGEN_AP_NATIVE_BAZEL=1 cargo run --manifest-path zirgen/bootstrap/Cargo.toml --release -- \
        rv32im-v2 \
        --output "$RISC0" \
        "${extra[@]}")
}

install_codegen_artifacts() {
    local bazel_out="$ZIRGEN/bazel-bin/zirgen/circuit/rv32im/v2/dsl"
    local rs_dest="$RISC0/risc0/circuit/rv32im/src/zirgen"
    local cxx_dest="$RISC0/risc0/circuit/rv32im-sys/kernels/cxx"
    local cuda_dest="$RISC0/risc0/circuit/rv32im-sys/kernels/cuda"

    echo "[regen] bazel build //zirgen/circuit/rv32im/v2/dsl:codegen"
    ap_zirgen_bazel_build "//zirgen/circuit/rv32im/v2/dsl:codegen"

    if [[ ! -d "$bazel_out" ]]; then
        echo "ERROR: missing bazel output dir $bazel_out" >&2
        exit 1
    fi

    echo "[regen] installing artifacts from $bazel_out"
    mkdir -p "$rs_dest" "$cxx_dest" "$cuda_dest"

    for f in poly_ext.rs info.rs taps.rs layout.rs.inc; do
        [[ -f "$bazel_out/$f" ]] && cp "$bazel_out/$f" "$rs_dest/"
    done
    for f in "$bazel_out"/*.rs.inc; do
        [[ -f "$f" ]] && cp "$f" "$rs_dest/"
    done

    for f in steps.cpp steps.h rust_poly_fp_{0..3}.cpp layout.cpp.inc layout.h.inc defs.cpp.inc types.h.inc; do
        [[ -f "$bazel_out/$f" ]] && cp "$bazel_out/$f" "$cxx_dest/"
    done

    for f in steps.cu steps.cuh eval_check_{0..3}.cu eval_check.cuh layout.cu.inc layout.cuh.inc defs.cu.inc types.cuh.inc; do
        [[ -f "$bazel_out/$f" ]] && cp "$bazel_out/$f" "$cuda_dest/"
    done

    echo "[regen] install complete"
}

control_regen() {
    require_bazel
    local stashed=0
    stash_ap_zir_edits && stashed=1 || true
    trap '[[ "${stashed:-0}" -eq 1 ]] && git -C "$ZIRGEN" stash pop 2>/dev/null || true' EXIT

    echo "[regen] === control-regen: df6fb9d unmodified .zir → install + snapshot ==="
    install_codegen_artifacts
    local dest
    dest="$(snap_dir control)"
    snapshot_regen "$dest"
    echo "[regen] CONTROL REGEN DONE: $dest"
    echo "[regen] next: bash a4/scripts/ap_zirgen_regen.sh honest-gate"
}

control_check() {
    require_bazel
    local stashed=0
    stash_ap_zir_edits && stashed=1 || true
    trap '[[ "${stashed:-0}" -eq 1 ]] && git -C "$ZIRGEN" stash pop 2>/dev/null || true' EXIT

    restore_committed_circuit
    echo "[regen] === control-check: df6fb9d unmodified vs committed (Option A comparability) ==="
    if run_bootstrap check; then
        echo "[regen] CONTROL CHECK PASS: df6fb9d reproduces committed artifacts (AP joinable with CVE/sweep)"
    else
        echo "[regen] CONTROL CHECK FAIL (informational for Option B — not a blocker if honest-gate passes)"
        return 1
    fi
}

honest_gate() {
    local control_snap="${1:-$(snap_dir control)}"
    if [[ ! -f "$control_snap/zirgen_head.txt" ]]; then
        echo "ERROR: no control snapshot at $control_snap — run control-regen first" >&2
        exit 1
    fi
    echo "[regen] === honest-gate: df6fb9d control circuit must prove+verify guest ==="
    restore_snapshot "$control_snap"
    bash "$ROOT/a4/scripts/build_ap_binaries.sh" --from-regen --control-only
    python3 "$ROOT/a4/scripts/ap_b1_verify.py" --honest-only || {
        echo "[regen] HONEST GATE FAIL: df6fb9d control regen does not verify guest" >&2
        exit 1
    }
    echo "[regen] HONEST GATE PASS"
}

holed_regen() {
    require_bazel
    restore_ap_zir_edits
    if ! ap_zir_edits_present; then
        echo "ERROR: MemoryReadNoIsRead edits required in mem.zir + inst.zir" >&2
        exit 1
    fi
    echo "[regen] === holed-regen: MemoryReadNoIsRead .zir → install + snapshot ==="
    install_codegen_artifacts
    local dest
    dest="$(snap_dir holed)"
    snapshot_regen "$dest"
    echo "[regen] HOLED REGEN DONE: $dest"
    echo "[regen] next: bash a4/scripts/build_ap_binaries.sh --from-regen"
}

semantic_diff() {
    restore_committed_circuit
    python3 "$ROOT/a4/scripts/ap_zirgen_semantic_diff.py" \
        --committed "$RISC0" \
        --control "$(snap_dir control)" 2>/dev/null || {
        echo "[regen] semantic-diff: run control-regen first, or script missing" >&2
        exit 1
    }
}

main() {
    local cmd="${1:-}"
    case "$cmd" in
        control-regen) control_regen ;;
        control-check) control_check ;;
        honest-gate)   honest_gate "${2:-}" ;;
        holed-regen)   holed_regen ;;
        semantic-diff) semantic_diff ;;
        -h|--help|"")  usage 0 ;;
        *) echo "unknown command: $cmd" >&2; usage 2 ;;
    esac
}

main "$@"
