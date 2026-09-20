#!/usr/bin/env bash
# Temporarily disable rules_conda in zirgen/WORKSPACE for C++-only builds.
# py3_env is only referenced by clang_format toolchain (CI aspect), not gen_zirgen/codegen.
#
# Usage:
#   bash a4/scripts/ap_zirgen_conda_prune.sh apply
#   bash a4/scripts/ap_zirgen_conda_prune.sh restore
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WS="$ROOT/zirgen/WORKSPACE"
BACKUP="$ROOT/a4/builds/ap/zirgen_WORKSPACE.bak"

apply() {
    if grep -q 'AP conda-prune' "$WS" 2>/dev/null; then
        echo "[conda-prune] WORKSPACE already patched"
        return 0
    fi
    if [[ ! -f "$BACKUP" ]]; then
        cp "$WS" "$BACKUP"
        echo "[conda-prune] backed up WORKSPACE -> $BACKUP"
    fi
    python3 - <<'PY'
from pathlib import Path
ws = Path("/root/arguzz/zirgen/WORKSPACE")
text = ws.read_text()
start = text.index('http_archive(\n    name = "rules_conda"')
# Remove rules_conda block AND clang_format toolchain (depends on @py3_env).
end = text.index('http_archive(\n    name = "com_google_googletest"')
replacement = '''# AP conda-prune: rules_conda + py3_env + clang_format toolchain disabled.
# py3_env only supplies clang-format for CI (--config=ci); not gen_zirgen/codegen.
# Restore: bash a4/scripts/ap_zirgen_conda_prune.sh restore

'''
ws.write_text(text[:start] + replacement + text[end:])
print("[conda-prune] WORKSPACE patched")
PY
}

restore() {
    if [[ -f "$BACKUP" ]]; then
        cp "$BACKUP" "$WS"
        echo "[conda-prune] WORKSPACE restored from backup"
    else
        echo "[conda-prune] no backup at $BACKUP" >&2
        exit 1
    fi
}

case "${1:-}" in
    apply) apply ;;
    restore) restore ;;
    *) echo "usage: $0 apply|restore" >&2; exit 2 ;;
esac
