#!/usr/bin/env bash
# Build POS bundle from frozen thesis-minimal-host + thesis extras.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MINIMAL="$ROOT/thesis_side_experiments/minimal_add"
FROZEN="$MINIMAL/frozen_host/thesis-minimal-host.e0frozen"
EXPECTED_SHA="5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23"

if [[ ! -x "$FROZEN" ]]; then
    echo "ERROR: frozen host missing: $FROZEN" >&2
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
echo "[prepare_thesis_bundle] base bundle: $TAR"

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
tar -xzf "$TAR" -C "$STAGE"

THESIS_STAGE="$STAGE/a4_campaign/thesis"
mkdir -p "$THESIS_STAGE/configs"
cp "$ROOT/thesis_side_experiments/pos/thesis_run_pos.sh" "$STAGE/a4_campaign/scripts/thesis_run_pos.sh"
chmod +x "$STAGE/a4_campaign/scripts/thesis_run_pos.sh"
cp "$ROOT/thesis_side_experiments/pos/thesis_run_pos.sh" "$THESIS_STAGE/thesis_run_pos.sh"
chmod +x "$THESIS_STAGE/thesis_run_pos.sh"

if [[ -f "$MINIMAL/artifacts/e2/configs/manifest_e2.json" ]]; then
    cp "$MINIMAL/artifacts/e2/configs/manifest_e2.json" "$THESIS_STAGE/manifest_e2.json"
    cp "$MINIMAL/artifacts/e2/configs/manifest_e2.json" "$THESIS_STAGE/manifest.json"
    cp "$MINIMAL/artifacts/e2/configs/manifest_smoke.json" "$THESIS_STAGE/manifest_smoke.json" 2>/dev/null || true
    cp "$MINIMAL/artifacts/e2/configs/"a4_*.json "$THESIS_STAGE/configs/" 2>/dev/null || true
elif [[ -f "$MINIMAL/artifacts/e2/configs/manifest_smoke.json" ]]; then
    cp "$MINIMAL/artifacts/e2/configs/manifest_smoke.json" "$THESIS_STAGE/manifest_smoke.json"
    cp "$MINIMAL/artifacts/e2/configs/manifest.json" "$THESIS_STAGE/manifest_full.json"
    cp "$MINIMAL/artifacts/e2/configs/"*.json "$THESIS_STAGE/configs/" 2>/dev/null || true
    # exclude manifest copies from configs dir
    rm -f "$THESIS_STAGE/configs/manifest.json" "$THESIS_STAGE/configs/manifest_smoke.json" 2>/dev/null || true
else
    echo "WARN: run bake_e2_configs.py first" >&2
fi

OUT="$ROOT/bundles/thesis_minimal_add_$(basename "$TAR" .tar.gz | sed 's/a4_campaign/thesis/').tar.gz"
tar -czf "$OUT" -C "$STAGE" a4_campaign
cp "$JSON" "${OUT%.tar.gz}.bundle.json"

HOST_SHA=$(python3 -c "import json; print(json.load(open('${JSON}'))['host_sha256'])")
if [[ "$HOST_SHA" != "$EXPECTED_SHA" ]]; then
    echo "ERROR: bundle host_sha256=$HOST_SHA" >&2
    exit 1
fi

echo "[prepare_thesis_bundle] DONE"
echo "  bundle: $OUT"
echo "  host_sha256: $HOST_SHA"
echo "  extras: thesis_run_pos.sh + e2 configs + manifest_smoke.json"
