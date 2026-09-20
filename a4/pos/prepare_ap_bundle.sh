#!/usr/bin/env bash
# prepare_ap_bundle.sh — bundle for AP.B2 POS (dual risc0-host: patched + bench-isread).
set -euo pipefail

OUTPUT_DIR="bundles"
ALLOW_DIRTY=0
PATCHED_HOST="a4/builds/ap/patched/risc0-host"
BENCH_HOST="a4/builds/ap/bench-isread/risc0-host"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --allow-dirty) ALLOW_DIRTY=1; shift ;;
        --patched-host) PATCHED_HOST="$2"; shift 2 ;;
        --bench-host) BENCH_HOST="$2"; shift 2 ;;
        -h|--help) sed -n '1,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

GIT_COMMIT=$(git rev-parse HEAD)
GIT_SHORT=$(git rev-parse --short=12 HEAD)
DIRTY=0
if ! git diff --quiet HEAD || [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
    DIRTY=1
fi
if [[ $DIRTY -eq 1 && $ALLOW_DIRTY -eq 0 ]]; then
    echo "ERROR: dirty tree — commit or use --allow-dirty" >&2
    exit 1
fi

for h in "$PATCHED_HOST" "$BENCH_HOST"; do
    [[ -x "$h" ]] || { echo "ERROR: missing host $h" >&2; exit 1; }
done

PATCHED_SHA=$(sha256sum "$PATCHED_HOST" | awk '{print $1}')
BENCH_SHA=$(sha256sum "$BENCH_HOST" | awk '{print $1}')

mkdir -p "$OUTPUT_DIR"
STAGE=$(mktemp -d -t apbundle.XXXXXX)
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/a4_ap_campaign"
mkdir -p "$ROOT/bin" "$ROOT/repo" "$ROOT/configs/screen"

echo "[prepare_ap_bundle] archiving git @ $GIT_SHORT"
git archive --format=tar HEAD | tar -x -C "$ROOT/repo"

if [[ $DIRTY -eq 1 ]]; then
    echo "[prepare_ap_bundle] overlay dirty files"
    while IFS= read -r f; do
        [[ -f "$f" ]] || continue
        mkdir -p "$ROOT/repo/$(dirname "$f")"
        cp "$f" "$ROOT/repo/$f"
    done < <(git diff --name-only HEAD; git ls-files --others --exclude-standard)
fi

cp "$PATCHED_HOST" "$ROOT/bin/risc0-host-patched"
cp "$BENCH_HOST" "$ROOT/bin/risc0-host-bench-isread"
chmod +x "$ROOT/bin/"*

CREATED_AT=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
cat > "$ROOT/bundle.json" <<EOF
{
  "git_commit": "$GIT_COMMIT",
  "git_short": "$GIT_SHORT",
  "dirty": $([[ $DIRTY -eq 1 ]] && echo "true" || echo "false"),
  "patched_host": "bin/risc0-host-patched",
  "patched_sha256": "$PATCHED_SHA",
  "bench_host": "bin/risc0-host-bench-isread",
  "bench_sha256": "$BENCH_SHA",
  "created_at_utc": "$CREATED_AT",
  "notes": "AP.B2 dual-host bundle (IsRead planted bug benchmark)"
}
EOF

TARNAME="$OUTPUT_DIR/a4_ap_campaign_${GIT_SHORT}.tar.gz"
echo "[prepare_ap_bundle] creating $TARNAME"
tar -czf "$TARNAME" -C "$STAGE" a4_ap_campaign
cp "$ROOT/bundle.json" "$OUTPUT_DIR/a4_ap_campaign_${GIT_SHORT}.bundle.json"

echo "[prepare_ap_bundle] DONE"
echo "  patched_sha=$PATCHED_SHA"
echo "  bench_sha=$BENCH_SHA"
echo "  bundle=$TARNAME ($(du -sh "$TARNAME" | awk '{print $1}'))"
