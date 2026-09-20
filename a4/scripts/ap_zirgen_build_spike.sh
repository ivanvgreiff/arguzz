#!/usr/bin/env bash
# Isolated zirgen build spike — native host toolchain (no zig bootstrap, no conda).
#
# Stage 1: //zirgen/Main:gen_zirgen   (LLVM/MLIR codegen binary)
# Stage 2: //zirgen/circuit/rv32im/v2/dsl:codegen  (circuit OUTS)
#
# Usage:
#   USE_BAZEL_VERSION=6.0.0 bash a4/scripts/ap_zirgen_build_spike.sh [--stage 1|2|all]
#
# Logs: a4/runs/iv_pos_9/ap/build_spike.log
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
AP_ZIRGEN_ROOT="$ROOT"
ZIRGEN="$ROOT/zirgen"
LOG="$ROOT/a4/runs/iv_pos_9/ap/build_spike.log"
export USE_BAZEL_VERSION="${USE_BAZEL_VERSION:-6.0.0}"

# shellcheck source=/dev/null
source "$ROOT/a4/scripts/ap_zirgen_bazel_common.sh"

STAGE="${1:-all}"
if [[ "$STAGE" == "--stage" ]]; then
    STAGE="${2:-all}"
fi

require_bazel() {
    command -v bazelisk >/dev/null 2>&1 || command -v bazel >/dev/null 2>&1 || {
        echo "ERROR: bazelisk not found" >&2
        exit 1
    }
}

mkdir -p "$(dirname "$LOG")"
{
    echo "=== ap_zirgen_build_spike $(date -Iseconds) ==="
    echo "zirgen HEAD: $(git -C "$ZIRGEN" rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "USE_BAZEL_VERSION=$USE_BAZEL_VERSION"
    echo "toolchain: native host (ZIRGEN_AP_NATIVE_BAZEL=1, no bootstrap_linux_amd64)"
    require_bazel

    case "$STAGE" in
        1)
            ap_zirgen_bazel_build "//zirgen/Main:gen_zirgen"
            ;;
        2)
            ap_zirgen_bazel_build "//zirgen/circuit/rv32im/v2/dsl:codegen"
            ;;
        all|*)
            ap_zirgen_bazel_build "//zirgen/Main:gen_zirgen"
            ap_zirgen_bazel_build "//zirgen/circuit/rv32im/v2/dsl:codegen"
            ;;
    esac

    echo "[spike] SUCCESS"
    echo "Next: bash a4/scripts/ap_zirgen_regen.sh control-regen"
} 2>&1 | tee -a "$LOG"
