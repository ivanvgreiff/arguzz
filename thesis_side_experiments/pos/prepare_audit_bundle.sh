#!/usr/bin/env bash
# Build POS bundle for E5 acceptance audit (frozen host + audit run list).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SWEEP="$ROOT/thesis_side_experiments/full_sweep"
FROZEN="$SWEEP/frozen_host/thesis-full-sweep-host.e0frozen"
EXPECTED_SHA="84ae495e5afd8261324d7daf09a02d1f9cb8437aad4edbb2de478362e2728b45"

if [[ ! -x "$FROZEN" ]]; then
    echo "ERROR: frozen host missing: $FROZEN" >&2
    exit 1
fi
if [[ ! -f "$SWEEP/audit/run_list.json" ]]; then
    echo "ERROR: run audit/build_run_list.py first" >&2
    exit 1
fi

ACTUAL=$(sha256sum "$FROZEN" | awk '{print $1}')
if [[ "$ACTUAL" != "$EXPECTED_SHA" ]]; then
    echo "ERROR: frozen sha mismatch: $ACTUAL" >&2
    exit 1
fi

cp "$FROZEN" /tmp/risc0-host
chmod +x /tmp/risc0-host

cd "$ROOT"
bash a4/pos/prepare_bundle.sh --host /tmp/risc0-host --allow-dirty --skip-host-sha

TAR=$(ls -t bundles/a4_campaign_*.tar.gz | head -1)
JSON=$(ls -t bundles/a4_campaign_*.bundle.json | head -1)

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
tar -xzf "$TAR" -C "$STAGE"

THESIS="$STAGE/a4_campaign/thesis"
mkdir -p "$THESIS"
cp "$ROOT/thesis_side_experiments/pos/thesis_audit_run.sh" "$STAGE/a4_campaign/scripts/thesis_audit_run.sh"
chmod +x "$STAGE/a4_campaign/scripts/thesis_audit_run.sh"
cp "$ROOT/thesis_side_experiments/pos/thesis_audit_run.sh" "$THESIS/thesis_audit_run.sh"
chmod +x "$THESIS/thesis_audit_run.sh"
cp "$SWEEP/audit/run_list.json" "$THESIS/audit_run_list.json"

OUT="$ROOT/bundles/thesis_e5_audit_$(basename "$TAR" .tar.gz | sed 's/a4_campaign/thesis/').tar.gz"
tar -czf "$OUT" -C "$STAGE" a4_campaign
cp "$JSON" "${OUT%.tar.gz}.bundle.json"

HOST_SHA=$(python3 -c "import json; print(json.load(open('${JSON}'))['host_sha256'])")
if [[ "$HOST_SHA" != "$EXPECTED_SHA" ]]; then
    echo "ERROR: bundle host_sha256=$HOST_SHA" >&2
    exit 1
fi

echo "[prepare_audit_bundle] DONE"
echo "  bundle: $OUT"
echo "  host_sha256: $HOST_SHA"
