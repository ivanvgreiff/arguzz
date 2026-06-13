#!/bin/bash
# thesis_side_experiments/pos/thesis_run_pos.sh
#
# On-node runner for thesis E2/E3 smoke and matrix runs.
# Reads manifest from $WORK/thesis/manifest_smoke.json (or THESIS_MANIFEST env).
# Runs each entry twice; checks determinism; uploads results on EXIT.

set -euo pipefail

WORK="${WORK:-/root/a4_campaign}"
HOST="$WORK/bin/risc0-host"
MANIFEST="${THESIS_MANIFEST:-$WORK/thesis/manifest_smoke.json}"
RESULTS="${THESIS_RESULTS:-$WORK/thesis/results}"
EXPECTED_SHA="5337f9448d7946c5785f1506b0fbfbfa07d32d6542e60c9cc158a22ce0611d23"

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

if [[ ! -f "$MANIFEST" ]]; then
    echo "FATAL: manifest not found: $MANIFEST" >&2
    exit 1
fi

echo "[thesis_run_pos] host sha ok; manifest=$MANIFEST; results=$RESULTS"

python3 - <<'PY' "$MANIFEST" "$WORK" "$HOST" "$RESULTS"
import json, os, subprocess, sys
from pathlib import Path

manifest_path, work, host, results = sys.argv[1:5]
data = json.loads(Path(manifest_path).read_text())
runs = data["runs"] if isinstance(data, dict) and "runs" in data else data
work = Path(work)
results = Path(results)
det_summary = results / "determinism_summary.txt"

env = {
    **os.environ,
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_COVERAGE_TOUCH_VERBOSE": "1",
    "A4_FAMILY_RESIDUE": "1",
    "A4_GLOBAL_RESIDUE": "1",
}

def strip_volatile(line: str) -> str:
    """Remove Prover/Verifier timing and other wall-clock fields before compare."""
    import re
    s = re.sub(r'"time"\s*:\s*"[^"]*"', '"time":"STRIPPED"', line)
    s = re.sub(
        r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        "TIMESTAMP",
        s,
    )
    return s

def extract_sig(text: str) -> str:
    lines = []
    for ln in text.splitlines():
        if "<constraint_fail>" in ln or "<fault>" in ln:
            lines.append(strip_volatile(ln.strip()))
        if '"context":"Prover"' in ln or '"context":"Verifier"' in ln:
            lines.append(strip_volatile(ln.strip()))
        if "panicked at host/src/main.rs" in ln:
            lines.append(strip_volatile(ln.strip()))
        if "<a4_global_residue_nonzero>" in ln or "<a4_family_residue>" in ln:
            lines.append(strip_volatile(ln.strip()))
    return "\n".join(sorted(lines))

def run_cmd(cmd, extra_env=None):
    e = {**env, **(extra_env or {})}
    p = subprocess.run(cmd, capture_output=True, text=True, env=e, timeout=600)
    return p.stdout + p.stderr

lines = []
for entry in runs:
    run_id = entry["run_id"]
    run_type = entry["run_type"]
    log1 = results / f"{run_id}.log"
    log2 = results / f"{run_id}.rerun.log"

    if run_type == "arguzz":
        kind = entry.get("inject_kind") or entry["kind"]
        if kind == "INSTR_WORD_MOD" and entry["kind"] == "INSTR_WORD_MOD":
            kind = "INSTR_WORD_MOD"
        cmd = [
            host, "--trace", "--inject",
            "--inject-step", str(entry["arguzz_step"]),
            "--inject-kind", kind,
            "--seed", str(entry["seed"]),
        ]
        extra = None
    elif run_type == "a4":
        cfg_rel = entry.get("config_file", "")
        cfg = work / "thesis" / cfg_rel if not Path(cfg_rel).is_absolute() else Path(cfg_rel)
        if not cfg.exists():
            cfg = work / "artifacts" / "e2" / cfg_rel
        if not cfg.exists():
            raise SystemExit(f"missing config for {run_id}: {cfg}")
        cmd = [host]
        extra = {"A4_MUTATION_CONFIG": str(cfg)}
    else:
        raise SystemExit(f"unknown run_type {run_type}")

    out1 = run_cmd(cmd, extra)
    log1.write_text(out1)
    out2 = run_cmd(cmd, extra)
    log2.write_text(out2)

    sig1 = extract_sig(out1)
    sig2 = extract_sig(out2)
    ok = sig1 == sig2
    status = "PASS" if ok else "FAIL"
    line = f"{run_id}\t{status}\tsig_bytes={len(sig1.encode())}"
    lines.append(line)
    print(line, flush=True)

det_summary.write_text("\n".join(lines) + "\n")
PY

echo "[thesis_run_pos] done; determinism summary at $RESULTS/determinism_summary.txt"
