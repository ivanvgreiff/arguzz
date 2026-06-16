#!/bin/bash
# On-node audit runner: full witness dump for baseline + 37 targets + controls.
set -euo pipefail

WORK="${WORK:-/root/a4_campaign}"
HOST="$WORK/bin/risc0-host"
MANIFEST="${THESIS_MANIFEST:-$WORK/thesis/audit_run_list.json}"
RESULTS="${THESIS_RESULTS:-$WORK/thesis/e5_audit_results}"
EXPECTED_SHA="${THESIS_HOST_SHA:-84ae495e5afd8261324d7daf09a02d1f9cb8437aad4edbb2de478362e2728b45}"
NODE="$(hostname -s)"

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
export A4_INSPECT=1
export A4_DUMP_ALL_TXNS=1

python3 - <<'PY' "$MANIFEST" "$HOST" "$RESULTS" "$NODE"
import gzip, json, os, subprocess, sys
from pathlib import Path

manifest_path, host, results, node = sys.argv[1:5]
results = Path(results)
data = json.loads(Path(manifest_path).read_text())
runs = data["runs"]

env_base = {
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_COVERAGE_TOUCH_VERBOSE": "1",
    "A4_FAMILY_RESIDUE": "1",
    "A4_GLOBAL_RESIDUE": "1",
    "A4_INSPECT": "1",
    "A4_DUMP_ALL_TXNS": "1",
}

def run_cmd(cmd, log_path, env):
    p = subprocess.run(
        cmd,
        capture_output=True,
        env=env,
        timeout=900,
    )
    text = (p.stdout + p.stderr).decode("utf-8", errors="replace")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(str(log_path) + ".gz", "wt", encoding="utf-8") as f:
        f.write(text)
    return p.returncode, text

lines = []
for entry in runs:
    kind = entry["kind"]
    run_id = entry["run_id"]
    repeat = entry.get("repeat", 1)

    if kind == "baseline":
        cmd = [host, "--trace"]
        for i in range(repeat):
            suffix = "" if i == 0 else ".rerun"
            rid = f"{run_id}{suffix}"
            log = results / f"{node}__{rid}"
            rc, _ = run_cmd(cmd, log, {**os.environ, **env_base})
            status = "PASS" if rc == 0 else "ERR"
            lines.append(f"{rid}\t{status}\trc={rc}")
            print(f"done {rid} rc={rc}", flush=True)
        continue

    cmd = [
        host, "--trace", "--inject",
        "--inject-step", str(entry["inject_step"]),
        "--inject-kind", entry["mutation_type"],
        "--seed", str(entry["seed"]),
    ]
    log = results / f"{node}__{run_id}"
    rc, _ = run_cmd(cmd, log, {**os.environ, **env_base})
    status = "PASS" if rc == 0 else "ERR"
    lines.append(f"{run_id}\t{status}\trc={rc}\texpect={entry.get('expect','')}")
    print(f"done {run_id} rc={rc}", flush=True)

(results / f"{node}__run_summary.txt").write_text("\n".join(lines) + "\n")
PY

echo "[thesis_audit_run] node=$NODE done; results=$RESULTS"
