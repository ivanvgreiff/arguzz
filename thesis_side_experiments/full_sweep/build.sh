#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CARGO_TARGET_DIR="${ROOT}/target"

cd "${ROOT}"
cargo build --release

echo ""
echo "Built full_sweep host (isolated target dir; does NOT touch workspace/output or minimal_add):"
echo "  ${CARGO_TARGET_DIR}/release/thesis-full-sweep-host"
