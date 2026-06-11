#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export CARGO_TARGET_DIR="${ROOT}/target"

cd "${ROOT}"
cargo build --release

echo ""
echo "Built isolated host (does NOT replace workspace/output binary):"
echo "  ${CARGO_TARGET_DIR}/release/thesis-minimal-host"
