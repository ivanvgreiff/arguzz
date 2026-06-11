#!/usr/bin/env bash
# a4/pos/prepare_bundle.sh
#
# Build the campaign bundle that will be SCP'd to the POS management node and
# then shipped to each test node via `pos.nodes.copy(<node>, <tarball>, '/root/')`
# (revised path — no longer through /srv/testbed/files; see POS_PLAYBOOK.md §4.3).
#
# Output:  ./bundles/a4_campaign_<git-short>.tar.gz
#          ./bundles/a4_campaign_<git-short>.bundle.json   (manifest)
#
# Pre-conditions:
#   - risc0-host exists (default: workspace/output/target/release/risc0-host)
#   - its sha256 matches ~/arguzz_backups/risc0-host.FIXED.sha256
#
# If the default path is missing, locate your binary and pass --host:
#   find workspace -name risc0-host -type f
#   bash a4/pos/prepare_bundle.sh --host workspace/output/target/release/risc0-host --allow-dirty
#   - git working tree is clean (warn if not; pivot §10.2 step 1)
#
# Usage:
#   bash a4/pos/prepare_bundle.sh
#   # optional: --output-dir DIR --include-wheels --allow-dirty
#
# Notes:
#   - This is bundle-only; it does NOT touch POS. Upload to the management
#     node is a separate manual step (scp / sftp / etc; see README).
#   - The bundle is self-contained: repo source @ git commit + fixed
#     risc0-host + scripts + manifest. By default does NOT vendor wheels
#     (per H.10: outbound internet is available on POS test nodes, so the
#     runner does `pip install` online — fast bundle prep). Use --include-wheels
#     to also pack a wheelhouse for offline / hardened runs.

set -euo pipefail

# ----- defaults ----------------------------------------------------------
OUTPUT_DIR="bundles"
INCLUDE_WHEELS=0
ALLOW_DIRTY=0
SKIP_HOST_SHA=0
HOST_BINARY="workspace/output/target/release/risc0-host"
EXPECTED_SHA_FILE="$HOME/arguzz_backups/risc0-host.FIXED.sha256"

# ----- arg parsing -------------------------------------------------------
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir)   OUTPUT_DIR="$2"; shift 2 ;;
        --include-wheels) INCLUDE_WHEELS=1; shift ;;
        --allow-dirty)  ALLOW_DIRTY=1; shift ;;
        --skip-host-sha) SKIP_HOST_SHA=1; shift ;;
        --host)         HOST_BINARY="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,30p' "$0"; exit 0 ;;
        *)              echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

# ----- 1. git state ------------------------------------------------------
GIT_COMMIT=$(git rev-parse HEAD)
GIT_SHORT=$(git rev-parse --short=12 HEAD)
DIRTY=0
if ! git diff --quiet HEAD || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
    DIRTY=1
fi
if [[ $DIRTY -eq 1 && $ALLOW_DIRTY -eq 0 ]]; then
    echo "ERROR: git working tree is dirty. Commit, stash, or rerun with --allow-dirty." >&2
    git status --short
    exit 1
fi

# ----- 2. binary verification --------------------------------------------
if [[ ! -x "$HOST_BINARY" ]]; then
    for candidate in \
        workspace/output/target/release/risc0-host \
        workspace/risc0-modified/target/release/risc0-host; do
        if [[ -x "$candidate" ]]; then
            echo "[prepare_bundle] using discovered host: $candidate"
            HOST_BINARY="$candidate"
            break
        fi
    done
fi
if [[ ! -x "$HOST_BINARY" ]]; then
    echo "ERROR: host binary not found or not executable: $HOST_BINARY" >&2
    echo "  Run: find workspace -name risc0-host -type f" >&2
    echo "  Then: bash a4/pos/prepare_bundle.sh --host <path> --allow-dirty" >&2
    exit 1
fi
HOST_SHA=$(sha256sum "$HOST_BINARY" | awk '{print $1}')
if [[ $SKIP_HOST_SHA -eq 1 ]]; then
    echo "[prepare_bundle] host sha256 (unpinned): $HOST_SHA"
elif [[ -f "$EXPECTED_SHA_FILE" ]]; then
    EXPECTED_SHA=$(awk '{print $1}' "$EXPECTED_SHA_FILE")
    if [[ "$HOST_SHA" != "$EXPECTED_SHA" ]]; then
        echo "ERROR: host binary sha256 mismatch." >&2
        echo "  expected ($EXPECTED_SHA_FILE): $EXPECTED_SHA" >&2
        echo "  actual ($HOST_BINARY):         $HOST_SHA" >&2
        echo "  Use --skip-host-sha for post-fix Opus host (Inc 3b)." >&2
        exit 1
    fi
    echo "[prepare_bundle] host sha256 verified: $HOST_SHA"
else
    echo "[prepare_bundle] WARN: no expected sha file at $EXPECTED_SHA_FILE; skipping verification"
fi

# ----- 3. staging dir ----------------------------------------------------
mkdir -p "$OUTPUT_DIR"
STAGE=$(mktemp -d -t a4bundle.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/a4_campaign"
mkdir -p "$ROOT/bin" "$ROOT/scripts" "$ROOT/repo"

# Copy repo (tracked-only via git archive — same content as `git checkout` would produce)
echo "[prepare_bundle] archiving git tree @ $GIT_SHORT"
git archive --format=tar HEAD | tar -x -C "$ROOT/repo"

# Add untracked test results / bundles / etc? — no, keep deterministic from git.

# Copy the binary
cp "$HOST_BINARY" "$ROOT/bin/risc0-host"
chmod +x "$ROOT/bin/risc0-host"

# Copy POS scripts (also present in repo/, but staged top-level for convenience)
cp a4/pos/run_campaign_pos.sh "$ROOT/scripts/run_campaign_pos.sh"
cp a4/pos/benchmark_pos.sh    "$ROOT/scripts/benchmark_pos.sh"
chmod +x "$ROOT/scripts/"*.sh

# Optional: vendor Python wheels (offline pip install on test node)
if [[ $INCLUDE_WHEELS -eq 1 ]]; then
    echo "[prepare_bundle] vendoring Python wheels into $ROOT/wheels/"
    mkdir -p "$ROOT/wheels"
    pip download \
        --dest "$ROOT/wheels" \
        --quiet \
        -r <(python3 -c "import tomllib, pathlib; d=tomllib.loads(pathlib.Path('pyproject.toml').read_text()); print('\n'.join(d.get('project',{}).get('dependencies',[])))")
fi

# ----- 4. manifest -------------------------------------------------------
CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
PYVERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
cat > "$ROOT/bundle.json" <<EOF
{
  "git_commit": "$GIT_COMMIT",
  "git_short": "$GIT_SHORT",
  "dirty": $([[ $DIRTY -eq 1 ]] && echo "true" || echo "false"),
  "host_binary_path": "bin/risc0-host",
  "host_sha256": "$HOST_SHA",
  "include_wheels": $INCLUDE_WHEELS,
  "python_version_expected": "$PYVERSION",
  "created_at_utc": "$CREATED_AT",
  "notes": "Bundle for POS testbed run. See a4/pos/README.md."
}
EOF

# ----- 5. tar ------------------------------------------------------------
TARNAME="$OUTPUT_DIR/a4_campaign_${GIT_SHORT}.tar.gz"
JSONNAME="$OUTPUT_DIR/a4_campaign_${GIT_SHORT}.bundle.json"
echo "[prepare_bundle] creating $TARNAME"
tar -czf "$TARNAME" -C "$STAGE" a4_campaign
cp "$ROOT/bundle.json" "$JSONNAME"

SIZE=$(du -sh "$TARNAME" | awk '{print $1}')
echo
echo "[prepare_bundle] DONE"
echo "  bundle:    $TARNAME  ($SIZE)"
echo "  manifest:  $JSONNAME"
echo
echo "Next steps:"
echo "  1. scp $TARNAME <username>@coinbase.net.in.tum.de:~/  (port 10022)"
echo "  2. On the management node, dispatch via:"
echo "       python -m a4.pos.dispatch_pos \\"
echo "         --manifest a4/pos/manifests/pos_smoke_v1.json \\"
echo "         --bundle ~/$(basename "$TARNAME") \\"
echo "         --nodes mtgox"
