#!/usr/bin/env bash
# Build AP bench-isread and patched risc0-host binaries with fingerprints.
#
# Outputs:
#   a4/builds/ap/bench-isread/risc0-host + fingerprint.json
#   a4/builds/ap/patched/risc0-host + fingerprint.json
#
# Modes:
#   default          — surgical FOLD-neutralization on committed circuit (PRIMARY)
#   --from-regen     — Option B: both from df6fb9d zirgen snapshots
#   --control-only   — build patched only from control snapshot (honest-gate)
#
# Usage:
#   bash a4/scripts/build_ap_binaries.sh [--skip-build] [--from-regen] [--control-only]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RISC0_DIR="$ROOT/workspace/risc0-modified"
OUTPUT_DIR="$ROOT/workspace/output"
BUILD_DIR="$ROOT/a4/builds/ap"
PATCH_SCRIPT="$ROOT/a4/scripts/ap_isread_patch.py"
SNAP_BASE="$ROOT/a4/builds/ap/regen-snapshots"

SKIP_BUILD=0
FROM_REGEN=0
CONTROL_ONLY=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --skip-build) SKIP_BUILD=1; shift ;;
        --from-regen) FROM_REGEN=1; shift ;;
        --control-only) CONTROL_ONLY=1; FROM_REGEN=1; shift ;;
        -h|--help)
            sed -n '1,18p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

find_latest_snap() {
    local label="$1"
    local d
    d="$(ls -d "$SNAP_BASE/${label}-"* 2>/dev/null | sort | tail -1 || true)"
    if [[ -z "$d" || ! -f "$d/zirgen_head.txt" ]]; then
        echo "ERROR: no ${label} snapshot under $SNAP_BASE — run ap_zirgen_regen.sh ${label}-regen" >&2
        exit 1
    fi
    echo "$d"
}

restore_snapshot() {
    local src="$1"
    echo "[build_ap] restore snapshot $src"
    while IFS= read -r rel; do
        [[ -z "$rel" || "$rel" =~ ^# ]] && continue
        if [[ -e "$src/$rel" ]]; then
            mkdir -p "$RISC0_DIR/$(dirname "$rel")"
            rsync -a "$src/$rel" "$RISC0_DIR/$rel"
        fi
    done <<EOF
risc0/circuit/rv32im/src/zirgen
risc0/circuit/rv32im-sys/kernels/cxx/steps.cpp
risc0/circuit/rv32im-sys/kernels/cxx/steps.h
risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_0.cpp
risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_1.cpp
risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_2.cpp
risc0/circuit/rv32im-sys/kernels/cxx/rust_poly_fp_3.cpp
risc0/circuit/rv32im-sys/kernels/cxx/layout.cpp.inc
risc0/circuit/rv32im-sys/kernels/cxx/layout.h.inc
risc0/circuit/rv32im-sys/kernels/cxx/defs.cpp.inc
risc0/circuit/rv32im-sys/kernels/cxx/types.h.inc
risc0/circuit/rv32im-sys/kernels/cuda/steps.cu
risc0/circuit/rv32im-sys/kernels/cuda/steps.cuh
risc0/circuit/rv32im-sys/kernels/cuda/eval_check_0.cu
risc0/circuit/rv32im-sys/kernels/cuda/eval_check_1.cu
risc0/circuit/rv32im-sys/kernels/cuda/eval_check_2.cu
risc0/circuit/rv32im-sys/kernels/cuda/eval_check_3.cu
risc0/circuit/rv32im-sys/kernels/cuda/eval_check.cuh
risc0/circuit/rv32im-sys/kernels/cuda/layout.cu.inc
risc0/circuit/rv32im-sys/kernels/cuda/layout.cuh.inc
risc0/circuit/rv32im-sys/kernels/cuda/defs.cu.inc
risc0/circuit/rv32im-sys/kernels/cuda/types.cuh.inc
EOF
}

RISC0_SHA="$(git -C "$RISC0_DIR" rev-parse HEAD)"
ZIRGEN_SHA=""
if [[ -d "$ROOT/zirgen/.git" ]]; then
    ZIRGEN_SHA="$(git -C "$ROOT/zirgen" rev-parse HEAD 2>/dev/null || true)"
fi
LOAD_RS2_PRESENT="$(grep -c 'fn load_rs2' "$RISC0_DIR/risc0/circuit/rv32im/src/execute/rv32im.rs" || true)"
INSTR_HASH="$(sha256sum "$PATCH_SCRIPT" | awk '{print $1}')"

write_fingerprint() {
    local out_dir="$1"
    local planted_bug="$2"
    local isread_scope="$3"
    local host_path="$4"
    local circuit_source="${5:-surgical}"
    mkdir -p "$out_dir"
    cp "$host_path" "$out_dir/risc0-host"
    chmod +x "$out_dir/risc0-host"
    local host_sha
    host_sha="$(sha256sum "$out_dir/risc0-host" | awk '{print $1}')"
    cat > "$out_dir/fingerprint.json" <<EOF
{
  "risc0_head_sha": "$RISC0_SHA",
  "zirgen_head_sha": "$ZIRGEN_SHA",
  "circuit_source": "$circuit_source",
  "load_rs2_present": $LOAD_RS2_PRESENT,
  "instrumentation_hash": "$INSTR_HASH",
  "planted_bug": "$planted_bug",
  "isread_scope": "$isread_scope",
  "host_sha256": "$host_sha",
  "build_label": "$planted_bug"
}
EOF
}

build_host() {
    local planted_bug="$1"
    local isread_scope="$2"
    export A4_PLANTED_BUG="$planted_bug"
    export A4_ISREAD_SCOPE="$isread_scope"
    export A4_RISC0_HEAD_SHA="$RISC0_SHA"
    export A4_LOAD_RS2_PRESENT="$LOAD_RS2_PRESENT"
    export A4_INSTRUMENTATION_HASH="$INSTR_HASH"
    echo "[build_ap] cargo build --release (planted_bug=$planted_bug)"
    (cd "$OUTPUT_DIR" && cargo build --release -p risc0-host)
}

if [[ $SKIP_BUILD -eq 0 ]]; then
    if [[ $FROM_REGEN -eq 1 ]]; then
        CONTROL_SNAP="$(find_latest_snap control)"
        echo "[build_ap] Option B: df6fb9d self-consistent pair"
        echo "[build_ap] control snapshot: $CONTROL_SNAP"

        echo "[build_ap] === patched (control) — df6fb9d unmodified regen ==="
        restore_snapshot "$CONTROL_SNAP"
        build_host "none" ""
        write_fingerprint "$BUILD_DIR/patched" "none" "" "$OUTPUT_DIR/target/release/risc0-host" "zirgen_control"

        if [[ $CONTROL_ONLY -eq 0 ]]; then
            HOLED_SNAP="$(find_latest_snap holed)"
            echo "[build_ap] holed snapshot: $HOLED_SNAP"
            echo "[build_ap] === bench-isread — df6fb9d holed regen (no surgical patch) ==="
            restore_snapshot "$HOLED_SNAP"
            build_host "isread" "reg_only"
            write_fingerprint "$BUILD_DIR/bench-isread" "isread" "reg_only" \
                "$OUTPUT_DIR/target/release/risc0-host" "zirgen_holed"
        fi
    else
        echo "[build_ap] === patched (control) ==="
        python3 "$PATCH_SCRIPT" revert
        build_host "none" ""
        write_fingerprint "$BUILD_DIR/patched" "none" "" "$OUTPUT_DIR/target/release/risc0-host" "committed"

        echo "[build_ap] === bench-isread (planted) — surgical fold-neutralization (committed) ==="
        python3 "$PATCH_SCRIPT" apply
        build_host "isread" "reg_only"
        write_fingerprint "$BUILD_DIR/bench-isread" "isread" "reg_only" \
            "$OUTPUT_DIR/target/release/risc0-host" "surgical"
    fi
else
    echo "[build_ap] --skip-build: refreshing fingerprints only"
    write_fingerprint "$BUILD_DIR/patched" "none" "" "$BUILD_DIR/patched/risc0-host"
    write_fingerprint "$BUILD_DIR/bench-isread" "isread" "reg_only" "$BUILD_DIR/bench-isread/risc0-host"
fi

echo "[build_ap] DONE"
echo "  patched:      $BUILD_DIR/patched/risc0-host"
echo "  bench-isread: $BUILD_DIR/bench-isread/risc0-host"
