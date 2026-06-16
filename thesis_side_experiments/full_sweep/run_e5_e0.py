#!/usr/bin/env python3
"""E5-E0: clean baseline + one-time context capture (no Arguzz↔A4 offset)."""

from __future__ import annotations

import gzip
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "e5" / "context"
HOST = ROOT / "frozen_host" / "thesis-full-sweep-host.e0frozen"
GUEST_ELF = (
    ROOT
    / "target/riscv-guest/thesis-full-sweep-methods/thesis-full-sweep-guest/riscv32im-risc0-zkvm-elf/release/thesis-full-sweep-guest"
)

REPO = ROOT.parents[1]
sys.path.insert(0, str(REPO))

from a4.core.constraint_parser import parse_all_constraint_failures  # noqa: E402
from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.core.insn_decode import INSN_KIND_NAMES  # noqa: E402
from a4.core.trace_parser import parse_all_a4_cycles, parse_all_all_txns  # noqa: E402
from a4.core.touch_coverage import parse_family_residues, parse_global_residue  # noqa: E402
from thesis_side_experiments.bias_campaign.run_common import DEFAULT_ENV  # noqa: E402
from thesis_side_experiments.full_sweep.host_guard import assert_frozen_full_sweep  # noqa: E402
from thesis_side_experiments.full_sweep.region_map import build_region_map_rules  # noqa: E402

TRACE_RE = re.compile(r"<trace>(\{.*?\})</trace>")
BASELINE_OUTPUT = "269358329"


def run_host(env: dict, trace: bool = False) -> str:
    cmd = [str(HOST)]
    if trace:
        cmd.append("--trace")
    proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=600)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise RuntimeError(f"host failed rc={proc.returncode}")
    return out


def global_nonzero(output: str) -> bool:
    g = parse_global_residue(output)
    if g and g.get("nonzero"):
        return True
    fam = parse_family_residues(output) or []
    return any(f.get("nonzero") for f in fam)


def applicability(major: int, minor: int) -> List[str]:
    apps = ["any"]
    if major in (0, 3, 4):
        apps.append("compute")
    if major == 5:
        apps.append("load")
    if major == 6:
        apps.append("store")
    if major == 1 and minor in (5, 6, 7):
        apps.append("branch")
    if major == 2 and minor in (0, 1, 2, 3):
        apps.append("branch")
    return apps


def build_sites(cycles: list, trace_steps: dict) -> dict:
    sites: Dict[str, List[dict]] = {
        "compute": [],
        "load": [],
        "store": [],
        "branch": [],
        "any": [],
    }
    for c in cycles:
        if c.major > 6 or c.step == 0:
            continue
        kind = INSN_KIND_NAMES.get(c.major * 8 + c.minor, f"M{c.major}m{c.minor}")
        tr = trace_steps.get(c.step, {})
        entry = {
            "step": c.step,
            "pc": c.pc,
            "pc_hex": f"0x{c.pc:08x}",
            "major": c.major,
            "minor": c.minor,
            "kind": kind,
            "assembly": tr.get("assembly", ""),
            "instruction": tr.get("instruction", ""),
        }
        for app in applicability(c.major, c.minor):
            sites[app].append(entry)
    return sites


def parse_trace_steps(output: str) -> dict:
    out = {}
    for line in output.splitlines():
        m = TRACE_RE.search(line)
        if not m:
            continue
        d = json.loads(m.group(1))
        step = int(d["step"])
        if step == 0:
            continue
        out[step] = d
    return out


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    host_sha = assert_frozen_full_sweep(HOST)

    env = {**dict(__import__("os").environ), **DEFAULT_ENV}
    runs = []
    for i in (1, 2):
        out = run_host(env)
        path = ART / f"baseline_run{i}.log.gz"
        with gzip.open(path, "wt") as f:
            f.write(out)
        fails = parse_all_constraint_failures(out)
        runs.append(
            {
                "run": i,
                "output_ok": BASELINE_OUTPUT in out,
                "verifier_ok": '"context":"Verifier"' in out and '"status":"success"' in out,
                "constraint_fails": len(fails),
                "global_nonzero": global_nonzero(out),
            }
        )

    if not all(r["output_ok"] and r["verifier_ok"] for r in runs):
        raise SystemExit("baseline output/verifier failed")
    if any(r["constraint_fails"] or r["global_nonzero"] for r in runs):
        raise SystemExit("baseline must have 0 failures and 0 residue")

    inspect_env = {**env, "A4_INSPECT": "1", "A4_DUMP_ALL_TXNS": "1"}
    inspect_out = run_host(inspect_env)
    with gzip.open(ART / "trace_inspection.txt.gz", "wt") as f:
        f.write(inspect_out)

    cycles = parse_all_a4_cycles(inspect_out)
    txns = parse_all_all_txns(inspect_out)
    trace_out = run_host({**env, **{}}, trace=True)
    trace_steps = parse_trace_steps(trace_out)

    cycles_json = [
        {
            "cycle_idx": c.cycle_idx,
            "step": c.step,
            "pc": c.pc,
            "major": c.major,
            "minor": c.minor,
            "txn_idx": c.txn_idx,
        }
        for c in cycles
    ]
    txns_json = [
        {
            "txn_idx": t.txn_idx,
            "step": t.step,
            "type": "reg" if t.is_register() else "mem",
            "addr": t.addr,
            "word": t.word,
            "prev_word": getattr(t, "prev_word", None),
        }
        for t in txns
    ]
    (ART / "cycles.json").write_text(json.dumps(cycles_json, indent=2))
    (ART / "txns.json").write_text(json.dumps(txns_json, indent=2))

    region_map = build_region_map_rules()
    pcs = [c.pc for c in cycles if c.major <= 6 and c.step > 0]
    if pcs:
        region_map["guest_pc_min"] = hex(min(pcs))
        region_map["guest_pc_max"] = hex(max(pcs))
    (ART / "region_map.json").write_text(json.dumps(region_map, indent=2))

    sites = build_sites(cycles, trace_steps)
    (ART / "sites.json").write_text(json.dumps(sites, indent=2))

    if GUEST_ELF.exists():
        obj = subprocess.run(
            ["objdump", "-d", str(GUEST_ELF)],
            capture_output=True,
            text=True,
            check=False,
        )
        (ART / "guest.objdump.txt").write_text(obj.stdout or obj.stderr)
        (ART / "guest_elf_sha256.txt").write_text(
            __import__("hashlib").sha256(GUEST_ELF.read_bytes()).hexdigest() + "\n"
        )

    report = {
        "milestone": "E5-E0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "host_sha256": host_sha,
        "baseline_output": BASELINE_OUTPUT,
        "baseline_runs": runs,
        "cycle_count": len(cycles_json),
        "txn_count": len(txns_json),
        "site_counts": {k: len(v) for k, v in sites.items()},
        "gate_pass": True,
    }
    (ART / "E5_E0_REPORT.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
