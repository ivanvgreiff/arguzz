#!/usr/bin/env python3
"""E0 — Guest rebuild + site derivation + clean baseline."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts" / "e0"
HOST = ROOT / "target/release/thesis-minimal-host"
PRODUCTION_HOST = Path("/root/arguzz/workspace/output/target/release/risc0-host")

sys.path.insert(0, str(ROOT.parent.parent))

from a4.core.constraint_parser import parse_all_constraint_failures  # noqa: E402
from a4.core.executor import run_a4_inspection_with_step, run_baseline  # noqa: E402
from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.core.touch_coverage import (  # noqa: E402
    parse_family_residues,
    parse_global_residue,
)
from a4.standalone.mutations.pre_exec_reg_mod import REGISTER_NAMES  # noqa: E402
from thesis_side_experiments.bias_campaign.guest_sites import LOAD_OPS, STORE_OPS  # noqa: E402
from thesis_side_experiments.bias_campaign.run_common import DEFAULT_ENV  # noqa: E402
from thesis_side_experiments.bias_campaign.touch_parse import (  # noqa: E402
    parse_accum_verbose_set,
    parse_local_verbose_set,
)

TRACE_RE = re.compile(r"<trace>(\{.*?\})</trace>")

ROLES = ("load_x", "load_y", "add", "store", "read_back")


def dedupe_trace_lines(lines: List[str]) -> List[str]:
    trace_lines = [ln for ln in lines if ln.startswith("<trace>")]
    if not trace_lines:
        return []
    out: List[str] = []
    seen_nonzero = False
    for line in trace_lines:
        m = TRACE_RE.search(line)
        if not m:
            continue
        step = json.loads(m.group(1)).get("step")
        if step == 0 and seen_nonzero:
            break
        if step not in (0, None):
            seen_nonzero = True
        out.append(line)
    return out


def parse_trace_steps(trace_lines: List[str]) -> List[dict]:
    steps = []
    for line in trace_lines:
        m = TRACE_RE.search(line)
        if not m:
            continue
        data = json.loads(m.group(1))
        steps.append(
            {
                "step": int(data["step"]),
                "pc": int(data["pc"]),
                "instruction": data.get("instruction", ""),
                "assembly": data.get("assembly", ""),
            }
        )
    return steps


def discover_roles(trace_lines: List[str]) -> Dict[str, dict]:
    steps = parse_trace_steps(trace_lines)
    matches: List[Tuple[int, Dict[str, dict]]] = []

    for i in range(len(steps) - 4):
        a, b, c, d, e = steps[i : i + 5]
        if (
            a["instruction"] in LOAD_OPS
            and b["instruction"] in LOAD_OPS
            and c["instruction"] == "Add"
            and d["instruction"] in STORE_OPS
            and e["instruction"] in LOAD_OPS
        ):
            matches.append(
                (
                    i,
                    {
                        "load_x": a,
                        "load_y": b,
                        "add": c,
                        "store": d,
                        "read_back": e,
                    },
                )
            )

    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one guest Lw,Lw,Add,Sw,Lw sequence; found {len(matches)}"
        )

    _idx, roles = matches[0]
    guest_adds = [roles["add"]]
    guest_lws = [roles["load_x"], roles["load_y"], roles["read_back"]]
    if len(guest_adds) != 1 or len(guest_lws) < 2:
        raise RuntimeError("guest body sanity failed after sequence match")
    return roles


def cycles_as_dicts(data: InspectionData) -> List[dict]:
    return [
        {
            "step": c.step,
            "pc": c.pc,
            "major": c.major,
            "minor": c.minor,
            "cycle_idx": c.cycle_idx,
        }
        for c in data.cycles
    ]


def infer_offset_for_guest_add(data: InspectionData, add_role: dict) -> int:
    """Derive Arguzz→A4 offset from the guest add only (not runtime Add ops)."""
    cycles = cycles_as_dicts(data)
    arguzz_step = add_role["step"]
    arguzz_pc = add_role["pc"]
    target_pc = arguzz_pc + 4
    for off in range(-5, 6):
        a4_step = arguzz_step + off
        for c in cycles:
            if c.get("step") != a4_step:
                continue
            if c.get("pc") == target_pc and c.get("major", 99) <= 4:
                return off
    raise RuntimeError(
        f"could not infer A4 offset from guest add step={arguzz_step} pc={arguzz_pc}"
    )


def cycle_at_a4_step(data: InspectionData, a4_step: int):
    cycles = [c for c in data.cycles if c.step == a4_step]
    if len(cycles) != 1:
        raise RuntimeError(f"expected one A4 cycle at step {a4_step}; found {len(cycles)}")
    return cycles[0]


def txn_summary(txns) -> List[dict]:
    rows = []
    for t in txns:
        reg_idx = t.register_index() if t.is_register() else None
        rows.append(
            {
                "txn_idx": t.txn_idx,
                "txn_type": "reg" if t.is_register() else "mem",
                "register": REGISTER_NAMES[reg_idx] if reg_idx is not None else None,
                "op": "READ" if t.is_read() else "WRITE",
                "word": t.word,
                "prev_word": t.prev_word,
            }
        )
    return rows


def validate_txn_shape(role: str, txns) -> None:
    reg_r = [t for t in txns if t.is_register() and t.is_read()]
    reg_w = [t for t in txns if t.is_register() and t.is_write()]
    mem_r = [t for t in txns if not t.is_register() and t.is_read()]
    mem_w = [t for t in txns if not t.is_register() and t.is_write()]

    if role in ("load_x", "load_y"):
        if not reg_w:
            raise RuntimeError(f"{role}: expected rd WRITE; got {txn_summary(txns)}")
    elif role == "add":
        if len(reg_r) < 2 or not reg_w:
            raise RuntimeError(f"{role}: expected ≥2 reg READ + rd WRITE; got {txn_summary(txns)}")
    elif role == "store":
        if not mem_w or not reg_r:
            raise RuntimeError(f"{role}: expected mem WRITE + rs READ; got {txn_summary(txns)}")
    elif role == "read_back":
        if not mem_r or not reg_w:
            raise RuntimeError(f"{role}: expected mem READ + rd WRITE; got {txn_summary(txns)}")


def production_host_stat() -> Dict[str, Any]:
    if not PRODUCTION_HOST.exists():
        return {"path": str(PRODUCTION_HOST), "exists": False}
    st = PRODUCTION_HOST.stat()
    return {
        "path": str(PRODUCTION_HOST),
        "exists": True,
        "mtime_iso": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
        "size_bytes": st.st_size,
    }


def run_host_trace() -> str:
    proc = subprocess.run([str(HOST), "--trace"], capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    if proc.returncode != 0:
        raise RuntimeError(f"baseline --trace failed exit={proc.returncode}")
    if '"output":"7"' not in out and '"output": "7"' not in out:
        raise RuntimeError("baseline journal output 7 not found")
    if '"context":"Verifier"' not in out or '"status":"success"' not in out:
        raise RuntimeError("baseline verifier success not found")
    return out


def global_nonzero(output: str) -> bool:
    g = parse_global_residue(output)
    if g and g.get("nonzero"):
        return True
    fam = parse_family_residues(output) or []
    return any(f.get("nonzero") for f in fam)


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {
        "milestone": "E0",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "host": str(HOST),
        "guest_args": [],
        "production_host_before_build": production_host_stat(),
    }

    prod_mtime_before = PRODUCTION_HOST.stat().st_mtime if PRODUCTION_HOST.exists() else None

    build = subprocess.run(["./build.sh"], cwd=ROOT, capture_output=True, text=True)
    (ART / "build_stdout.txt").write_text(build.stdout + build.stderr)
    if build.returncode != 0:
        raise SystemExit(f"build.sh failed: {build.returncode}")
    if not HOST.exists():
        raise SystemExit(f"missing host binary: {HOST}")

    report["production_host_after_build"] = production_host_stat()
    if prod_mtime_before is not None:
        after = PRODUCTION_HOST.stat().st_mtime
        report["production_host_mtime_unchanged"] = after == prod_mtime_before
        if after != prod_mtime_before:
            raise SystemExit("production risc0-host mtime changed during experiment build")

    trace_out = run_host_trace()
    trace_lines = dedupe_trace_lines(trace_out.splitlines())
    (ART / "baseline_trace_deduped.txt").write_text("\n".join(trace_lines) + "\n")

    roles = discover_roles(trace_lines)
    (ART / "roles.json").write_text(json.dumps(roles, indent=2))

    data = InspectionData.from_inspection(str(HOST), [])
    offset = infer_offset_for_guest_add(data, roles["add"])
    report["arguzz_to_a4_step_offset"] = offset

    site_card: Dict[str, Any] = {"offset": offset, "roles": {}}
    for role in ROLES:
        step_info = roles[role]
        a4_step = step_info["step"] + offset
        cycle = cycle_at_a4_step(data, a4_step)
        dump_out, _cycles, _step_txns, txns = run_a4_inspection_with_step(str(HOST), [], a4_step)
        (ART / f"step_{a4_step}_{role}_dump.txt").write_text(dump_out)
        validate_txn_shape(role, txns)
        site_card["roles"][role] = {
            "arguzz_step": step_info["step"],
            "arguzz_pc": step_info["pc"],
            "arguzz_pc_hex": f"0x{step_info['pc']:08x}",
            "instruction": step_info["instruction"],
            "assembly": step_info["assembly"],
            "a4_step": a4_step,
            "a4_pc": cycle.pc,
            "cycle_idx": cycle.cycle_idx,
            "major": cycle.major,
            "minor": cycle.minor,
            "txns": txn_summary(txns),
        }

    (ART / "site_card.json").write_text(json.dumps(site_card, indent=2))

    determinism: List[dict] = []
    for run_id in (1, 2):
        out = run_baseline(str(HOST), [], DEFAULT_ENV)
        path = ART / f"baseline_touch_run{run_id}.txt"
        path.write_text(out)
        failures = parse_all_constraint_failures(out)
        local_verbose = parse_local_verbose_set(out)
        accum_verbose = parse_accum_verbose_set(out)
        determinism.append(
            {
                "run": run_id,
                "path": str(path.relative_to(ROOT)),
                "constraint_fail_count": len(failures),
                "global_nonzero": global_nonzero(out),
                "local_verbose_count": len(local_verbose) if local_verbose is not None else None,
                "accum_verbose_count": len(accum_verbose) if accum_verbose is not None else None,
                "local_verbose": sorted(local_verbose) if local_verbose is not None else None,
                "accum_verbose": sorted(accum_verbose) if accum_verbose is not None else None,
            }
        )

    r1, r2 = determinism
    if r1["constraint_fail_count"] or r2["constraint_fail_count"]:
        raise SystemExit("baseline must have zero constraint failures")
    if r1["global_nonzero"] or r2["global_nonzero"]:
        raise SystemExit("baseline must have zero global/family residue")
    if r1["local_verbose"] != r2["local_verbose"]:
        raise SystemExit("local touch verbose sets differ between baseline runs")
    if r1["accum_verbose"] != r2["accum_verbose"]:
        raise SystemExit("accum touch verbose sets differ between baseline runs")

    universe = {
        "local_verbose": r1["local_verbose"],
        "accum_verbose": r1["accum_verbose"],
        "local_count": r1["local_verbose_count"],
        "accum_count": r1["accum_verbose_count"],
        "mutation_target_roles": {
            "LOAD_VAL_MOD": "load_x",
            "COMP_OUT_MOD": "add",
            "STORE_OUT_MOD": "store",
            "INSTR_WORD_MOD": "add",
        },
    }
    (ART / "baseline_universe.json").write_text(json.dumps(universe, indent=2))

    report["site_card"] = site_card
    report["determinism"] = {
        "runs_identical": True,
        "run_summaries": [
            {k: v for k, v in r.items() if k not in ("local_verbose", "accum_verbose")}
            for r in determinism
        ],
    }
    report["acceptance"] = {
        "production_host_mtime_unchanged": report.get("production_host_mtime_unchanged", True),
        "baseline_output_7": True,
        "baseline_verifier_ok": True,
        "baseline_zero_failures": True,
        "baseline_zero_global": True,
        "touch_sets_reproducible": True,
        "five_roles_identified": True,
        "a4_txn_shapes_validated": True,
        "gate_pass": True,
    }

    (ART / "E0_REPORT.json").write_text(json.dumps(report, indent=2))

    md_lines = [
        "# E0 Report — Guest Rebuild + Site Derivation + Baseline",
        "",
        "**Status:** PASS",
        "",
        f"Host: `{HOST}`",
        f"Arguzz→A4 step offset: **{offset}** (empirical, not assumed)",
        "",
        "## Production isolation",
        f"- mtime unchanged after `./build.sh`: **{report.get('production_host_mtime_unchanged')}**",
        "",
        "## Site card (five roles)",
        "",
        "| Role | Arguzz step | A4 step | Assembly |",
        "|------|-------------|---------|----------|",
    ]
    for role in ROLES:
        r = site_card["roles"][role]
        md_lines.append(
            f"| {role} | {r['arguzz_step']} | {r['a4_step']} | `{r['assembly']}` |"
        )

    md_lines.extend(
        [
            "",
            "## Baseline determinism (2×, DEFAULT_ENV)",
            f"- constraint_fail: **0** / **0**",
            f"- global residue: **0** / **0**",
            f"- local touch verbose size: **{r1['local_verbose_count']}** (identical 2×)",
            f"- accum touch verbose size: **{r1['accum_verbose_count']}** (identical 2×)",
            "",
            "## Frozen artifacts",
            "- `artifacts/e0/site_card.json`",
            "- `artifacts/e0/baseline_universe.json`",
            "- `artifacts/e0/baseline_trace_deduped.txt`",
            "- `artifacts/e0/E0_REPORT.json`",
        ]
    )
    (ART / "E0_REPORT.md").write_text("\n".join(md_lines) + "\n")
    print((ART / "E0_REPORT.md").read_text())


if __name__ == "__main__":
    main()
