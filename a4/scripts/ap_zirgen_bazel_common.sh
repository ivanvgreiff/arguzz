# Shared Bazel flags for AP zirgen builds on this host (WSL + gcc/clang native).
# Source from ap_zirgen_build_spike.sh and ap_zirgen_regen.sh — do not execute directly.
#
# Avoids:
#   --config=bootstrap_linux_amd64  → zig hermetic libunwind strict-deps failure
# rules_conda → ap_zirgen_conda_prune.sh apply (once)

ap_zirgen_ensure_conda_pruned() {
    local root="${AP_ZIRGEN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
    bash "$root/a4/scripts/ap_zirgen_conda_prune.sh" apply
}

# shellcheck disable=SC2034
AP_BAZEL_NATIVE_FLAGS=(
    --spawn_strategy=local
    --genrule_strategy=local
    --strategy=Javac=local
)

ap_zirgen_bazel_build() {
    local target="$1"
    shift || true
    local root="${AP_ZIRGEN_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
    ap_zirgen_ensure_conda_pruned
    (cd "$root/zirgen" && bazelisk build "${AP_BAZEL_NATIVE_FLAGS[@]}" "$@" "$target")
}

export ZIRGEN_AP_NATIVE_BAZEL=1
