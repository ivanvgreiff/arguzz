#!/usr/bin/env bash
# Build POS bundle for E5 full_sweep (frozen thesis-full-sweep-host + sample set + configs).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SWEEP="$ROOT/thesis_side_experiments/full_sweep"
FROZEN="$SWEEP/frozen_host/thesis-full-sweep-host.e0frozen"
EXPECTED_SHA="84ae495e5afd8261324d7daf09a02d1f9cb8437aad4edbb2de478362e2728b45"

if [[ ! -x "$FROZEN" ]]; then
    echo "ERROR: frozen host missing: $FROZEN" >&2
    exit 1
fi
ACTUAL=$(sha256sum "$FROZEN" | awk '{print $1}')
if [[ "$ACTUAL" != "$EXPECTED_SHA" ]]; then
    echo "ERROR: frozen sha mismatch: $ACTUAL" >&2
    exit 1
fi

if [[ ! -f "$SWEEP/artifacts/e5/sample_set.json" ]]; then
    echo "ERROR: run sample_e5.py --bake-a4 first" >&2
    exit 1
fi

cp "$FROZEN" /tmp/risc0-host
chmod +x /tmp/risc0-host

cd "$ROOT"
bash a4/pos/prepare_bundle.sh --host /tmp/risc0-host --allow-dirty --skip-host-sha

TAR=$(ls -t bundles/a4_campaign_*.tar.gz | head -1)
JSON=$(ls -t bundles/a4_campaign_*.bundle.json | head -1)
echo "[prepare_e5_bundle] base bundle: $TAR"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
tar -xzf "$TAR" -C "$STAGE"

THESIS="$STAGE/a4_campaign/thesis"
mkdir -p "$THESIS/configs" "$THESIS/e5_configs"
cp "$ROOT/thesis_side_experiments/pos/thesis_run_e5.sh" "$STAGE/a4_campaign/scripts/thesis_run_e5.sh"
chmod +x "$STAGE/a4_campaign/scripts/thesis_run_e5.sh"
cp "$ROOT/thesis_side_experiments/pos/thesis_run_e5.sh" "$THESIS/thesis_run_e5.sh"
chmod +x "$THESIS/thesis_run_e5.sh"
cp "$SWEEP/artifacts/e5/sample_set.json" "$THESIS/e5_sample_set.json"
cp "$SWEEP/artifacts/e5/configs/"*.json "$THESIS/e5_configs/" 2>/dev/null || true
cp "$SWEEP/artifacts/e5/configs/"*.json "$THESIS/configs/" 2>/dev/null || true

OUT="$ROOT/bundles/thesis_e5_full_sweep_$(basename "$TAR" .tar.gz | sed 's/a4_campaign/thesis/').tar.gz"
tar -czf "$OUT" -C "$STAGE" a4_campaign
cp "$JSON" "${OUT%.tar.gz}.bundle.json"

HOST_SHA=$(python3 -c "import json; print(json.load(open('${JSON}'))['host_sha256'])")
if [[ "$HOST_SHA" != "$EXPECTED_SHA" ]]; then
    echo "ERROR: bundle host_sha256=$HOST_SHA" >&2
    exit 1
fi

echo "[prepare_e5_bundle] DONE"
echo "  bundle: $OUT"
echo "  host_sha256: $HOST_SHA"
echo "  extras: thesis_run_e5.sh + e5_sample_set.json + e5 configs"
