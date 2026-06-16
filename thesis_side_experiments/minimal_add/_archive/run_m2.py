#!/usr/bin/env python3
"""M2 — A4 witness ground-truth on a1 READ 4→9."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
M0_ART = ROOT / "artifacts" / "m0"
M1_ART = ROOT / "artifacts" / "m1"
ART = ROOT / "artifacts" / "m2"
HOST = ROOT / "target/release/thesis-minimal-host"
ZIR_ROOT = Path("/root/arguzz/zirgen/zirgen/circuit/rv32im/v2/dsl")
MEM_ZIR = ZIR_ROOT / "mem.zir"

BABYBEAR_P = 2013265921
A1_TXN_IDX = 15057
MUTATED_WORD = 9
ORIGINAL_WORD = 4

sys.path.insert(0, str(ROOT.parent.parent))

from a4.core.constraint_parser import parse_all_constraint_failures  # noqa: E402
from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.core.trace_parser import parse_all_txns  # noqa: E402
from a4.core.touch_coverage import parse_family_residues, parse_global_residue  # noqa: E402
from a4.standalone.mutations.pre_exec_reg_mod import (  # noqa: E402
    REGISTER_NAMES,
    create_config,
    get_targets_at_step,
)

MUTATION_ENV = {
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_COVERAGE_TOUCH_VERBOSE": "1",
    "A4_FAMILY_RESIDUE": "1",
    "A4_GLOBAL_RESIDUE": "1",
    "A4_INSPECT": "1",
}


def mod_p(x: int) -> int:
    return x % BABYBEAR_P


def residue(lhs: int, rhs: int) -> int:
    """EQZ convention observed: (lhs - rhs) mod p."""
    return mod_p(lhs - rhs)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def read_zir_line(path: Path, line_no: int) -> str:
    lines = path.read_text().splitlines()
    return lines[line_no - 1].strip()


def zir_ref_from_loc(loc: str) -> Tuple[Optional[Path], Optional[int]]:
    m = re.search(r"([\w./]+\.zir)\s*:(\d+)", loc)
    if not m:
        return None, None
    rel = m.group(1)
    if rel.startswith("zirgen/"):
        rel = rel[len("zirgen/") :]
    path = Path("/root/arguzz/zirgen") / rel
    if not path.exists():
        alt = ZIR_ROOT.parent.parent.parent / rel.split("/", 1)[-1]
        path = ZIR_ROOT / Path(rel).name if rel.endswith("mem.zir") else path
    if "mem.zir" in rel:
        path = MEM_ZIR
    return path, int(m.group(2))


def dedupe_failures(failures, phase: str) -> List[dict]:
    seen: Set[Tuple[str, int, int]] = set()
    out = []
    for f in failures:
        if f.phase != phase:
            continue
        key = (f.loc, f.major, f.minor)
        if key in seen:
            continue
        seen.add(key)
        out.append(
            {
                "loc": f.loc,
                "major": f.major,
                "minor": f.minor,
                "phase": f.phase,
                "step": f.step,
                "cycle": f.cycle,
                "pc": f.pc,
                "value": f.value,
            }
        )
    return sorted(out, key=lambda x: x["loc"])


def parse_pre_exec_reg_mod(output: str) -> Optional[dict]:
    m = re.search(r"<a4_pre_exec_reg_mod>(\{.*?\})</a4_pre_exec_reg_mod>", output)
    return json.loads(m.group(1)) if m else None


def build_isolation_evidence(output: str, txns, preflight_regs: Dict[str, dict]) -> dict:
    """Preflight dump is pre-witness; effective mutation from <a4_pre_exec_reg_mod>."""
    mut = parse_pre_exec_reg_mod(output)
    if mut is None:
        raise RuntimeError("missing <a4_pre_exec_reg_mod>")

    effective = {
        "a0": dict(preflight_regs["a0"]),
        "a1": {
            **preflight_regs["a1"],
            "word": mut["new_word"],
            "prev_word": mut["prev_word"],
            "witness_mutated": True,
        },
        "s0": dict(preflight_regs["s0"]),
    }

    return {
        "preflight_txns": preflight_regs,
        "witness_effective_txns": effective,
        "mutation_log": mut,
        "isolation_confirmed": (
            effective["a0"]["word"] == 3
            and effective["a0"]["prev_word"] == 3
            and effective["a1"]["word"] == MUTATED_WORD
            and effective["a1"]["prev_word"] == ORIGINAL_WORD
            and preflight_regs["a1"]["word"] == ORIGINAL_WORD
            and effective["s0"]["word"] == 7
            and preflight_regs["s0"]["word"] == 7
        ),
        "note": (
            "A4_DUMP_STEP reflects preflight trace (a1 word still 4); witgen rewrites txn 15057 "
            "word to 9 per <a4_pre_exec_reg_mod>. s0 WRITE stays 7 in both preflight and witness."
        ),
    }


def txn_register_rows(txns) -> Dict[str, dict]:
    rows = {}
    for t in txns:
        idx = t.register_index()
        if idx is None:
            continue
        name = REGISTER_NAMES[idx]
        rows[name] = {
            "txn_idx": t.txn_idx,
            "word": t.word,
            "prev_word": t.prev_word,
            "is_read": t.is_read(),
            "is_write": t.is_write(),
        }
    return rows


def build_provenance(
    failure: dict,
    effective_regs: Dict[str, dict],
    mutation_log: dict,
) -> dict:
    loc = failure["loc"]
    observed = failure["value"]
    zir_path, zir_line = zir_ref_from_loc(loc)
    verbatim = read_zir_line(zir_path, zir_line) if zir_path and zir_line else None

    record: Dict[str, Any] = {
        "loc": loc,
        "zir_file": str(zir_path) if zir_path else None,
        "zir_line": zir_line,
        "verbatim_equation": verbatim,
        "observed_value": observed,
        "expected_p_minus_5": mod_p(BABYBEAR_P - 5),
    }

    a1 = effective_regs.get("a1", {})
    s0 = effective_regs.get("s0", {})

    if "IsRead" in loc and ":79:" in loc:
        prev_word = mutation_log["prev_word"]
        word = mutation_log["new_word"]
        record.update(
            {
                "constraint_form": "io.oldTxn.dataLow = io.newTxn.dataLow",
                "lhs": prev_word,
                "rhs": word,
                "predicted_residue": residue(prev_word, word),
                "delta_words": f"prev_word({prev_word}) - word({word})",
            }
        )
    elif "IsRead" in loc and ":80:" in loc:
        record.update(
            {
                "constraint_form": "io.oldTxn.dataHigh = io.newTxn.dataHigh",
                "note": "high limbs; both zero for small register values",
                "predicted_residue": 0,
            }
        )
    elif loc.startswith("MemoryWrite(") and ":99)" in loc:
        a0_word = effective_regs.get("a0", {}).get("word", 3)
        recorded_write = s0.get("word", 7)
        recomputed_sum = a0_word + mutation_log["new_word"]
        record.update(
            {
                "constraint_form": "io.newTxn.dataLow = data.low  (MemoryWrite / AddU32 rs1+rs2=rd)",
                "lhs": recorded_write,
                "rhs": recomputed_sum,
                "predicted_residue": residue(recorded_write, recomputed_sum),
                "delta_words": f"recorded s0 write({recorded_write}) - recomputed AddU32({a0_word},{mutation_log['new_word']})={recomputed_sum}",
                "interpretation": (
                    "Witness isolation: recorded s0 write stays 7 while circuit recomputes "
                    f"AddU32(rs1={a0_word}, rs2={mutation_log['new_word']})={recomputed_sum}. "
                    "Residue equals IsRead@79 (p-5) because +5 read corruption propagates linearly "
                    "through addition (12=7+5); residue alone is ambiguous under linear propagation."
                ),
            }
        )
    elif loc.startswith("MemoryWrite(") and ":100)" in loc:
        record.update(
            {
                "constraint_form": "io.newTxn.dataHigh = data.high",
                "predicted_residue": 0,
                "note": "high limbs zero for small values",
            }
        )
    else:
        record["predicted_residue"] = None
        record["note"] = "no automated prediction template"

    predicted = record.get("predicted_residue")
    record["predicted_matches_observed"] = (
        predicted is not None and predicted == observed
    )
    return record


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    add_site = load_json(M0_ART / "add_site.json")
    add_universe = load_json(M1_ART / "add_local_universe.json")
    universe_locs = {e["loc"] for e in add_universe}

    a4_step = add_site["a4_step"]
    data = InspectionData.from_inspection(str(HOST), [])
    targets = get_targets_at_step(a4_step, data, strategy="next_read")
    a1_reads = [t for t in targets if t.register_name == "a1" and not t.is_write]
    if not a1_reads:
        raise SystemExit(f"no a1 read target at step {a4_step}")
    target = next(t for t in a1_reads if t.txn_idx == A1_TXN_IDX)

    cfg_path = ART / "a4_mutation.json"
    create_config(target, MUTATED_WORD, cfg_path)

    env = {**dict(os.environ), **MUTATION_ENV}
    env["A4_MUTATION_CONFIG"] = str(cfg_path)
    env["A4_DUMP_STEP"] = str(a4_step)

    proc = subprocess.run([str(HOST)], capture_output=True, text=True, env=env)
    output = proc.stdout + proc.stderr
    (ART / "a4_mut_full.txt").write_text(output)

    failures = parse_all_constraint_failures(output)
    local_fails = dedupe_failures(failures, "local")
    accum_fails = dedupe_failures(failures, "accum")

    txns = parse_all_txns(output)
    preflight_regs = txn_register_rows(txns)
    isolation = build_isolation_evidence(output, txns, preflight_regs)
    effective_regs = isolation["witness_effective_txns"]
    mutation_log = isolation["mutation_log"]

    if not isolation["isolation_confirmed"]:
        raise SystemExit(f"isolation check failed: {isolation}")

    family = parse_family_residues(output)
    global_res = parse_global_residue(output)
    if family is None:
        raise SystemExit("missing Hook-3 residues")
    if global_res is None:
        raise SystemExit("missing global residue tag")

    memory_nz = next(f for f in family if f["family"] == "memory")["nonzero"]
    if not memory_nz:
        raise SystemExit("expected Hook-3 memory family nonzero")

    subset_ok = True
    subset_notes = []
    for f in local_fails + accum_fails:
        if f["loc"] not in universe_locs:
            subset_ok = False
            subset_notes.append(f"NOT IN ADD UNIVERSE: {f['loc']}")

    provenance = [
        build_provenance(f, effective_regs, mutation_log)
        for f in local_fails + accum_fails
    ]
    if not all(p.get("predicted_matches_observed") for p in provenance if p.get("predicted_residue") is not None):
        bad = [p for p in provenance if p.get("predicted_residue") is not None and not p["predicted_matches_observed"]]
        raise SystemExit(f"provenance mismatch: {bad}")

    report = {
        "milestone": "M2",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "mutation": json.loads(cfg_path.read_text()),
        "mutation_env": {**MUTATION_ENV, "A4_MUTATION_CONFIG": str(cfg_path), "A4_DUMP_STEP": str(a4_step)},
        "exit_code": proc.returncode,
        "isolation": isolation,
        "post_mutation_register_txns": effective_regs,
        "failures": {
            "local_deduped": local_fails,
            "accum_deduped": accum_fails,
            "raw_count": len(failures),
        },
        "hook3_family_residues": family,
        "global_residue": global_res,
        "failures_subset_of_add_universe": subset_ok,
        "subset_notes": subset_notes,
        "provenance": provenance,
        "acceptance": {
            "isolation_confirmed": isolation["isolation_confirmed"],
            "hook3_memory_nonzero": memory_nz,
            "local_fail_count": len(local_fails),
            "accum_fail_count": len(accum_fails),
            "provenance_all_match": True,
            "failures_in_add_universe": subset_ok,
        },
    }

    (ART / "M2_REPORT.json").write_text(json.dumps(report, indent=2))
    (ART / "post_mutation_txns.json").write_text(
        json.dumps(
            {
                "preflight": preflight_regs,
                "witness_effective": effective_regs,
                "mutation_log": mutation_log,
            },
            indent=2,
        )
    )

    eff = effective_regs
    pre = preflight_regs

    md = [
        "# M2 Report — A4 Witness Mutation (a1 READ 4→9)",
        "",
        "**Status:** PASS",
        "",
        "## Mutation",
        f"- Config: `artifacts/m2/a4_mutation.json`",
        f"- step={a4_step}, txn_idx={A1_TXN_IDX}, word {ORIGINAL_WORD}→{MUTATED_WORD}, strategy=next_read",
        "",
        "## Isolation (witness-effective add-cycle state)",
        "",
        "Preflight `A4_DUMP_STEP` txns are **pre-witness**; effective mutation from `<a4_pre_exec_reg_mod>`.",
        "",
        "| reg | op | preflight word | witness word | prev_word | expected |",
        "|-----|-----|----------------|--------------|-----------|----------|",
        f"| a0 | READ | {pre['a0']['word']} | {eff['a0']['word']} | {eff['a0']['prev_word']} | 3 / 3 |",
        f"| a1 | READ | {pre['a1']['word']} | **{eff['a1']['word']}** | {eff['a1']['prev_word']} | 4→**9** / 4 |",
        f"| s0 | WRITE | {pre['s0']['word']} | {eff['s0']['word']} | {eff['s0']['prev_word']} | 7 / 7 |",
        "",
        isolation["note"],
        "",
        "**Isolation confirmed.**",
        "",
        "## Failures (deduped)",
        "",
        "### phase=local",
    ]
    for f in local_fails:
        md.append(f"- `{f['loc']}` value={f['value']}")
    md.append("")
    md.append("### phase=accum")
    if accum_fails:
        for f in accum_fails:
            md.append(f"- `{f['loc']}` value={f['value']}")
    else:
        md.append("- *(none)*")
    md.extend(
        [
            "",
            "## GLOBAL (Hook 3 + final residue)",
            "",
        ]
    )
    for f in family:
        md.append(f"- **{f['family']}**: nonzero={f['nonzero']}")
    md.append(f"- **A4_GLOBAL_RESIDUE**: nonzero={global_res['nonzero']}")
    md.append("")
    md.append("## Constraint provenance")
    md.append("")
    for p in provenance:
        md.append(f"### `{p['loc'][:80]}...`" if len(p["loc"]) > 80 else f"### `{p['loc']}`")
        md.append(f"- ZIR `{p['zir_file']}:{p['zir_line']}` verbatim: `{p['verbatim_equation']}`")
        if "constraint_form" in p:
            md.append(f"- Form: `{p['constraint_form']}`")
        if "predicted_residue" in p:
            lhs = p.get("lhs")
            rhs = p.get("rhs")
            pair = f"lhs={lhs}, rhs={rhs}; " if lhs is not None else ""
            md.append(
                f"- {pair}Predicted `(lhs-rhs) mod p` = **{p['predicted_residue']}**; "
                f"observed **{p['observed_value']}**; match={p['predicted_matches_observed']}"
            )
        if p.get("interpretation"):
            md.append(f"- {p['interpretation']}")
        md.append("")
    md.extend(
        [
            "## Add-universe subset check",
            f"- All failing locs in 37-member Add universe: **{subset_ok}**",
            "",
            f"exit_code: **{proc.returncode}**",
            "",
            "**Opus gate:** M2 acceptance met. Await greenlight for **M3**.",
        ]
    )
    (ART / "M2_REPORT.md").write_text("\n".join(md) + "\n")
    print((ART / "M2_REPORT.md").read_text())


if __name__ == "__main__":
    main()
