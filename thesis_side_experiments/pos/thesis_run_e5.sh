#!/bin/bash
# On-node runner for E5 distribution study (thin direct-host path).
# Env: THESIS_MANIFEST, THESIS_RESULTS, THESIS_SHARD_ID, THESIS_SHARD_COUNT (optional)

set -euo pipefail

WORK="${WORK:-/root/a4_campaign}"
HOST="$WORK/bin/risc0-host"
MANIFEST="${THESIS_MANIFEST:-$WORK/thesis/e5_sample_set.json}"
RESULTS="${THESIS_RESULTS:-$WORK/thesis/e5_results}"
EXPECTED_SHA="${THESIS_HOST_SHA:-84ae495e5afd8261324d7daf09a02d1f9cb8437aad4edbb2de478362e2728b45}"
SHARD_ID="${THESIS_SHARD_ID:-0}"
SHARD_COUNT="${THESIS_SHARD_COUNT:-1}"

mkdir -p "$RESULTS"

upload_results() {
    if command -v pos_upload >/dev/null 2>&1; then
        pos_upload "$RESULTS" -r -f || true
    fi
}
trap upload_results EXIT

if [[ ! -x "$HOST" ]]; then
    echo "FATAL: missing host $HOST" >&2
    exit 1
fi

ACTUAL_SHA=$(sha256sum "$HOST" | awk '{print $1}')
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
    echo "FATAL: host sha mismatch got=$ACTUAL_SHA expected=$EXPECTED_SHA" >&2
    exit 1
fi

export CONSTRAINT_CONTINUE=1
export A4_COVERAGE_TOUCH=1
export A4_COVERAGE_TOUCH_VERBOSE=1
export A4_FAMILY_RESIDUE=1
export A4_GLOBAL_RESIDUE=1

python3 - <<'PY' "$MANIFEST" "$WORK" "$HOST" "$RESULTS" "$SHARD_ID" "$SHARD_COUNT"
import gzip, hashlib, json, os, random, subprocess, sys
from pathlib import Path

manifest_path, work, host, results, shard_id, shard_count = sys.argv[1:7]
shard_id, shard_count = int(shard_id), int(shard_count)
work = Path(work)
results = Path(results)
data = json.loads(Path(manifest_path).read_text())
samples = data["samples"] if isinstance(data, dict) else data

def shard_ok(i):
    if shard_count <= 1:
        return True
    return (i % shard_count) == shard_id

env_base = {
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_COVERAGE_TOUCH_VERBOSE": "1",
    "A4_FAMILY_RESIDUE": "1",
    "A4_GLOBAL_RESIDUE": "1",
}

def run_one(sample, log_path):
    env = {**os.environ, **env_base}
    if sample["fuzzer"] == "arguzz":
        cmd = [
            host, "--trace", "--inject",
            "--inject-step", str(sample["inject_step"]),
            "--inject-kind", sample["mutation_type"],
            "--seed", str(sample["seed"]),
        ]
    else:
        cfg_rel = sample.get("a4_config_path", "")
        name = Path(cfg_rel).name if cfg_rel else ""
        cfg = work / "thesis" / "e5_configs" / name
        if not cfg.exists():
            cfg = work / "thesis" / "configs" / name
        # SKIP: no config FILE means A4 had no valid target at this position
        # (build_a4_sample_config returned None). Must skip, NOT hand the host the
        # configs *directory* (which .exists() reports True for -> <a4_error>).
        if not name or not cfg.is_file():
            return None
        cmd = [host]
        env["A4_MUTATION_CONFIG"] = str(cfg)
    p = subprocess.run(cmd, capture_output=True, env=env, timeout=600)
    text = (p.stdout + p.stderr).decode("utf-8", errors="replace")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(str(log_path) + ".gz", "wt") as f:
        f.write(text)
    return text, cmd, env

det_ids = set()
if shard_count <= 1:
    random.seed(42)
    det_ids = {s["sample_id"] for s in random.sample(samples, max(1, len(samples)//10))}

lines = []
for i, sample in enumerate(samples):
    if not shard_ok(i):
        continue
    sid = sample["sample_id"]
    log_gz = results / f"{sid}.log.gz"
    if run_one(sample, log_gz.with_suffix("")) is None:
        lines.append(f"{sid}\tSKIP_NO_CONFIG\tshard={shard_id}/{shard_count}")
        print(f"skip {sid} (no valid A4 target / config)", flush=True)
        continue
    if sid in det_ids or (hash(sid) % 10 == 0 and shard_count > 1):
        run_one(sample, results / f"{sid}.rerun")
    lines.append(f"{sid}\tPASS\tshard={shard_id}/{shard_count}")
    print(f"done {sid}", flush=True)

(results / "run_summary.txt").write_text("\n".join(lines) + "\n")
PY

echo "[thesis_run_e5] shard $SHARD_ID/$SHARD_COUNT done; results=$RESULTS"
