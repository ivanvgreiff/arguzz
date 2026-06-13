#!/usr/bin/env python3
"""P1 WSL dry-run: run smoke manifest locally + analyze + gate."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HOST = ROOT / "frozen_host" / "thesis-minimal-host.e0frozen"
CFG = ROOT / "artifacts" / "e2" / "configs"
SMOKE = CFG / "manifest_smoke.json"
LOG_DIR = ROOT / "artifacts" / "e2" / "p1_dryrun" / "logs"
OUT_DIR = ROOT / "artifacts" / "e2" / "p1_dryrun" / "analysis"
E1 = ROOT / "artifacts" / "e1"
REPORT = ROOT / "artifacts" / "e2" / "P1_REPORT.json"

sys.path.insert(0, str(ROOT.parent.parent))

from thesis_side_experiments.bias_campaign.run_common import DEFAULT_ENV  # noqa: E402
from thesis_side_experiments.minimal_add.host_guard import assert_frozen_host  # noqa: E402


def run_local(entry: dict, log_path: Path) -> None:
    env = {**os.environ, **DEFAULT_ENV}
    if entry["run_type"] == "arguzz":
        kind = entry.get("inject_kind") or entry["kind"]
        cmd = [
            str(HOST),
            "--trace",
            "--inject",
            "--inject-step",
            str(entry["arguzz_step"]),
            "--inject-kind",
            kind,
            "--seed",
            str(entry["seed"]),
        ]
    else:
        cfg = CFG / Path(entry["config_file"]).name
        cmd = [str(HOST)]
        env["A4_MUTATION_CONFIG"] = str(cfg.resolve())

    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(proc.stdout + proc.stderr)


def main() -> None:
    assert_frozen_host(HOST)
    if not SMOKE.exists():
        raise SystemExit(f"missing {SMOKE} — run bake_e2_configs.py first")

    smoke = json.loads(SMOKE.read_text())
    runs = smoke["runs"]
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Running {len(runs)} smoke entries × 2 (determinism)…", flush=True)
    for entry in runs:
        run_id = entry["run_id"]
        run_local(entry, LOG_DIR / f"{run_id}.log")
        run_local(entry, LOG_DIR / f"{run_id}.rerun.log")
        print(f"  done {run_id}", flush=True)

    analyze = ROOT / "analyze_logs.py"
    subprocess.run(
        [
            sys.executable,
            str(analyze),
            "--manifest",
            str(SMOKE),
            "--log-dir",
            str(LOG_DIR),
            "--out-dir",
            str(OUT_DIR),
            "--e1-dir",
            str(E1),
            "--rerun-suffix",
            ".rerun",
        ],
        check=True,
    )

    analysis = json.loads((OUT_DIR / "analysis_report.json").read_text())
    arguzz_deviations = [d for d in analysis["deviations"] if d.startswith("arguzz")]
    gate = {
        "forced_value_path": (CFG / "manifest.json").exists(),
        "configs_baked": len(list(CFG.glob("a4_*.json"))) > 0,
        "analyze_logs_ok": not analysis["deviations"] and not analysis["determinism_failures"],
        "arguzz_matches_e1": len(arguzz_deviations) == 0,
        "determinism_all": len(analysis["determinism_failures"]) == 0,
        "smoke_run_count": len(runs),
        "proof_invocations": len(runs) * 2,
        "deviations": analysis["deviations"],
        "determinism_failures": analysis["determinism_failures"],
        "gate_pass": (
            not analysis["deviations"]
            and not analysis["determinism_failures"]
        ),
    }

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(json.dumps(gate, indent=2))

    md = [
        "# P1 Report — E2 POS prep (WSL dry-run)",
        "",
        f"**Status:** {'PASS' if gate['gate_pass'] else 'FAIL'}",
        "",
        "## Gate",
    ]
    for k, v in gate.items():
        if k != "gate_pass":
            md.append(f"- **{k}**: {v}")
    md.append(f"\n**Gate passed:** {gate['gate_pass']}")
    (REPORT.with_suffix(".md")).write_text("\n".join(md) + "\n")
    print((REPORT.with_suffix(".md")).read_text())

    if not gate["gate_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
