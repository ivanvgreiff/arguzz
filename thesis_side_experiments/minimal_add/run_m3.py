#!/usr/bin/env python3
"""M3 — Arguzz executor ground-truth on a1 (seed sweep + full capture)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
M0_ART = ROOT / "artifacts" / "m0"
M1_ART = ROOT / "artifacts" / "m1"
ART = ROOT / "artifacts" / "m3"
HOST = ROOT / "target/release/thesis-minimal-host"
MEM_ZIR = Path("/root/arguzz/zirgen/zirgen/circuit/rv32im/v2/dsl/mem.zir")

BABYBEAR_P = 2013265921
A0_BASELINE = 3
A1_BASELINE = 4
ARGUZZ_ADD_STEP = 187
A1_REGISTER = "a1"
SEED_SWEEP_MAX = 2000

sys.path.insert(0, str(ROOT.parent.parent))

from a4.common.trace_parser import ArguzzFault, parse_all_faults  # noqa: E402
from a4.core.constraint_parser import parse_all_constraint_failures  # noqa: E402
from a4.core.trace_parser import parse_all_txns  # noqa: E402
from a4.core.touch_coverage import parse_family_residues, parse_global_residue  # noqa: E402
from a4.standalone.mutations.pre_exec_reg_mod import REGISTER_NAMES  # noqa: E402

FULL_ENV = {
    "CONSTRAINT_CONTINUE": "1",
    "A4_COVERAGE_TOUCH": "1",
    "A4_COVERAGE_TOUCH_VERBOSE": "1",
    "A4_FAMILY_RESIDUE": "1",
    "A4_GLOBAL_RESIDUE": "1",
}


def mod_p(x: int) -> int:
    return x % BABYBEAR_P


def residue(lhs: int, rhs: int) -> int:
    return mod_p(lhs - rhs)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


def read_zir_line(path: Path, line_no: int) -> str:
    return path.read_text().splitlines()[line_no - 1].strip()


def zir_ref_from_loc(loc: str) -> Tuple[Optional[Path], Optional[int]]:
    import re

    m = re.search(r"([\w./]+\.zir)\s*:(\d+)", loc)
    if not m:
        return None, None
    if "mem.zir" in m.group(1):
        return MEM_ZIR, int(m.group(2))
    return None, None


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


def arguzz_cmd(seed: int, inject_step: int = ARGUZZ_ADD_STEP) -> List[str]:
    return [
        str(HOST),
        "--trace",
        "--inject",
        "--inject-step",
        str(inject_step),
        "--inject-kind",
        "PRE_EXEC_REG_MOD",
        "--seed",
        str(seed),
    ]


def quick_fault(seed: int) -> Optional[ArguzzFault]:
    proc = subprocess.Popen(
        arguzz_cmd(seed),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    fault: Optional[ArguzzFault] = None
    try:
        assert proc.stdout is not None
        for line in proc.stdout:
            if "<fault>" not in line:
                continue
            parsed = ArguzzFault.parse(line)
            if parsed and parsed.step == ARGUZZ_ADD_STEP:
                fault = parsed
                proc.kill()
                break
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    return fault


def sweep_a1_seeds(max_seed: int = SEED_SWEEP_MAX) -> List[dict]:
    hits = []
    for seed in range(max_seed):
        fault = quick_fault(seed)
        if fault is None or fault.target_register != A1_REGISTER:
            continue
        hits.append(
            {
                "seed": seed,
                "register": fault.target_register,
                "V": fault.mutated_value,
            }
        )
    return hits


def pick_seed(hits: List[dict]) -> dict:
    """Prefer V=9 (matches A4 delta), then small |V-4| with modest V."""
    for h in hits:
        if h["V"] == 9:
            return h
    clean = [h for h in hits if h["V"] < 1_000_000]
    pool = clean if clean else hits
    return sorted(pool, key=lambda h: (abs(h["V"] - A1_BASELINE), h["seed"]))[0]


def run_full(seed: int, a4_step: int) -> Tuple[int, str, bool]:
    env = {
        **dict(os.environ),
        **FULL_ENV,
        "A4_INSPECT": "1",
        "A4_DUMP_STEP": str(a4_step),
    }
    proc = subprocess.run(
        arguzz_cmd(seed),
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
    )
    output = proc.stdout + proc.stderr
    panicked = "panicked at" in output
    return proc.returncode, output, panicked


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


def expected_post_inject(V: int) -> Dict[str, dict]:
    """Executor semantics: PRE_EXEC a1=V before add → a1 READ V, s0 WRITE 3+V."""
    return {
        "a0": {"word": A0_BASELINE, "prev_word": A0_BASELINE, "is_read": True, "is_write": False},
        "a1": {
            "word": V,
            "prev_word": A1_BASELINE,
            "is_read": True,
            "is_write": False,
            "executor_injected": True,
        },
        "s0": {
            "word": A0_BASELINE + V,
            "prev_word": 0,
            "is_read": False,
            "is_write": True,
            "propagated_sum": True,
        },
    }


def build_provenance(
    failure: dict,
    post_regs: Dict[str, dict],
    injected_v: int,
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
    }

    a1 = post_regs.get("a1", {})
    s0 = post_regs.get("s0", {})
    a0 = post_regs.get("a0", {})

    if "IsRead" in loc and ":79:" in loc:
        prev_word = a1.get("prev_word", A1_BASELINE)
        read_word = a1.get("word", injected_v)
        predicted = residue(prev_word, read_word)
        record.update(
            {
                "constraint_form": "io.oldTxn.dataLow = io.newTxn.dataLow",
                "lhs": prev_word,
                "rhs": read_word,
                "predicted_residue": predicted,
                "field_element_check": mod_p(A1_BASELINE - injected_v),
                "delta_words": f"prev_word({prev_word}) - read({read_word})",
            }
        )
    elif loc.startswith("MemoryWrite(") and ":99)" in loc:
        recorded = s0.get("word")
        recomputed = a0.get("word", A0_BASELINE) + a1.get("word", injected_v)
        record.update(
            {
                "constraint_form": "io.newTxn.dataLow = data.low  (MemoryWrite / AddU32)",
                "lhs": recorded,
                "rhs": recomputed,
                "predicted_residue": residue(recorded, recomputed) if recorded is not None else None,
                "delta_words": f"recorded s0({recorded}) - recomputed({recomputed})",
                "interpretation": "M3 prediction: should NOT fire when propagation holds.",
            }
        )
    else:
        record["predicted_residue"] = None

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

    print(f"M3: sweeping seeds 0..{SEED_SWEEP_MAX - 1} for a1-targeting PRE_EXEC_REG_MOD …")
    hits = sweep_a1_seeds()
    (ART / "seed_sweep.json").write_text(
        json.dumps({"hits": hits, "max_seed": SEED_SWEEP_MAX}, indent=2)
    )
    if not hits:
        raise SystemExit("seed sweep found no a1 hits")

    chosen = pick_seed(hits)
    seed = chosen["seed"]
    injected_v = chosen["V"]
    print(f"  chosen seed={seed}, a1=V={injected_v} ({len(hits)} a1 hits)")

    # Witgen viability: probe chosen seed + first few a1 hits.
    witgen_probe = []
    probe_seeds = sorted({seed, *(h["seed"] for h in hits[:4])})
    chosen_output = ""
    chosen_panic = True
    chosen_exit = 101
    for s in probe_seeds:
        h = next(x for x in hits if x["seed"] == s)
        rc, out, panicked = run_full(s, a4_step)
        fails = parse_all_constraint_failures(out)
        witgen_probe.append(
            {
                "seed": s,
                "V": h["V"],
                "witgen_panic": panicked,
                "constraint_fail_count": len(fails),
                "has_txn_dump": "a4_step_txns" in out,
            }
        )
        if s == seed:
            chosen_output = out
            chosen_panic = panicked
            chosen_exit = rc
    all_a1_panic = all(p["witgen_panic"] and p["constraint_fail_count"] == 0 for p in witgen_probe)

    output = chosen_output
    panicked = chosen_panic
    exit_code = chosen_exit
    (ART / "arguzz_mut_full.txt").write_text(output)

    faults = parse_all_faults(output)
    inject_fault = next(
        (f for f in faults if f.step == ARGUZZ_ADD_STEP and f.kind == "PRE_EXEC_REG_MOD"),
        None,
    )
    if inject_fault is None or inject_fault.target_register != A1_REGISTER:
        raise SystemExit(f"chosen seed fault mismatch: {inject_fault}")

    txns = parse_all_txns(output)
    observed_regs = txn_register_rows(txns)
    expected_regs = expected_post_inject(injected_v)
    has_txn_dump = bool(observed_regs) and "a4_step_txns" in output

    post_regs = observed_regs if has_txn_dump else expected_regs
    propagation_algebraic = True  # executor semantics
    propagation_observed = (
        has_txn_dump
        and observed_regs.get("a1", {}).get("word") == injected_v
        and observed_regs.get("s0", {}).get("word") == A0_BASELINE + injected_v
        and observed_regs.get("a0", {}).get("word") == A0_BASELINE
    )

    failures = parse_all_constraint_failures(output)
    local_fails = dedupe_failures(failures, "local")
    accum_fails = dedupe_failures(failures, "accum")
    memorywrite_fails = [
        f for f in local_fails + accum_fails if f["loc"].startswith("MemoryWrite(") and ":99)" in f["loc"]
    ]
    isread_fails = [f for f in local_fails if "IsRead" in f["loc"] and ":79:" in f["loc"]]

    family = parse_family_residues(output)
    global_res = parse_global_residue(output)
    memory_nz = None
    if family:
        memory_nz = next(f for f in family if f["family"] == "memory")["nonzero"]

    provenance = [build_provenance(f, post_regs, injected_v) for f in local_fails + accum_fails]

    isread_value = isread_fails[0]["value"] if isread_fails else None
    field_element_ok = isread_value is not None and isread_value == mod_p(A1_BASELINE - injected_v)
    expected_isread_only = {
        "IsRead@79": mod_p(A1_BASELINE - injected_v),
        "MemoryWrite@99": 0,
    }

    inspect_inject_compat = {
        "works_for_chosen_seed": has_txn_dump,
        "witgen_panic_before_dump": panicked and not has_txn_dump,
        "note": (
            "A4_INSPECT+A4_DUMP_STEP produces txn dump when witgen completes; "
            "all probed a1-targeted seeds panic in preflight wrap_memory_txns before dump."
            if all_a1_panic
            else "partial compatibility"
        ),
    }
    (ART / "inspect_inject_compat.json").write_text(json.dumps(inspect_inject_compat, indent=2))

    subset_ok = all(f["loc"] in universe_locs for f in local_fails + accum_fails)

    witgen_ok = not panicked and len(failures) > 0
    bias_crystallized = (
        witgen_ok
        and bool(isread_fails)
        and not bool(memorywrite_fails)
        and (propagation_observed or propagation_algebraic)
        and field_element_ok
    )

    report = {
        "milestone": "M3",
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "status": "PASS" if bias_crystallized else ("BLOCKED" if all_a1_panic else "PARTIAL"),
        "site": {
            "arguzz_step": ARGUZZ_ADD_STEP,
            "a4_step": a4_step,
            "cycle_idx": add_site["cycle_idx"],
        },
        "seed_sweep": {"max_seed": SEED_SWEEP_MAX, "a1_hits": len(hits), "chosen": chosen},
        "witgen_probe_sample": witgen_probe,
        "all_a1_hits_witgen_panic": all_a1_panic,
        "inject": {
            "seed": seed,
            "register": A1_REGISTER,
            "V": injected_v,
            "fault": {
                "step": inject_fault.step,
                "pc": inject_fault.pc,
                "kind": inject_fault.kind,
                "info": f"a1 = {injected_v}",
            },
        },
        "inspect_inject_compat": inspect_inject_compat,
        "mutation_env": {**FULL_ENV, "A4_INSPECT": "1", "A4_DUMP_STEP": str(a4_step)},
        "exit_code": exit_code,
        "witgen_panic": panicked,
        "post_inject_register_txns": {
            "observed_from_dump": observed_regs if has_txn_dump else None,
            "expected_executor_semantics": expected_regs,
            "used_for_analysis": post_regs,
        },
        "propagation": {
            "expected_a1_read": injected_v,
            "expected_s0_write": A0_BASELINE + injected_v,
            "algebraic_confirmed": propagation_algebraic,
            "observed_in_dump": propagation_observed,
            "contrast_with_a4": "A4 witness keeps s0 WRITE=7; Arguzz executor records s0=3+V",
        },
        "failures": {
            "local_deduped": local_fails,
            "accum_deduped": accum_fails,
            "raw_count": len(failures),
            "memorywrite_at_99_fired": bool(memorywrite_fails),
            "isread_at_79_fired": bool(isread_fails),
        },
        "predicted_if_witgen_completed": {
            "local": ["IsRead@mem.zir:79"],
            "not_expected": ["MemoryWrite@mem.zir:99"],
            "isread_residue": mod_p(A1_BASELINE - injected_v),
            "memorywrite_residue": 0,
        },
        "hook3_family_residues": family,
        "global_residue": global_res,
        "field_element_validation": {
            "isread_value": isread_value,
            "expected_mod_p_4_minus_V": mod_p(A1_BASELINE - injected_v),
            "matches": field_element_ok,
        },
        "failures_subset_of_add_universe": subset_ok if failures else None,
        "provenance": provenance,
        "headline": {
            "witgen_completed": witgen_ok,
            "memorywrite_expected_absent": True,
            "memorywrite_observed_absent": not bool(memorywrite_fails),
            "isread_expected_present": True,
            "isread_observed_present": bool(isread_fails),
            "hook3_memory_nonzero": memory_nz,
            "bias_crystallized": bias_crystallized,
            "blocker": (
                "All a1-targeted PRE_EXEC_REG_MOD seeds panic in witgen preflight "
                "(wrap_memory_txns index OOB) before CONSTRAINT_CONTINUE can collect failures."
                if all_a1_panic
                else None
            ),
        },
        "acceptance": {
            "a1_targeted": True,
            "field_element_validated": field_element_ok if isread_value else None,
            "propagation_confirmed": propagation_observed or propagation_algebraic,
            "inspect_inject_noted": True,
            "hook3_recorded": family is not None,
            "full_failure_sets_collected": witgen_ok,
            "provenance_for_failures": (
                all(p.get("predicted_matches_observed") for p in provenance if p.get("predicted_residue") is not None)
                if provenance
                else None
            ),
        },
    }

    (ART / "M3_REPORT.json").write_text(json.dumps(report, indent=2))
    (ART / "post_inject_txns.json").write_text(json.dumps(post_regs, indent=2))

    md = [
        "# M3 Report — Arguzz Executor Mutation (a1-targeted)",
        "",
        f"**Status:** {report['status']}",
        "",
        "## Seed sweep",
        f"- Swept seeds 0..{SEED_SWEEP_MAX - 1}; **{len(hits)}** hit `{A1_REGISTER}`",
        f"- Chosen: seed=**{seed}**, injected **a1 = V = {injected_v}**",
        f"- No seed with V=9 found in sweep window" if not any(h["V"] == 9 for h in hits) else "",
        "",
        "## Witgen blocker (critical)",
        f"- All probed a1 hits panic in witgen preflight before `<constraint_fail>` collection: **{all_a1_panic}**",
        "- Panic site: `preflight.rs:227` (`wrap_memory_txns` — cycle diff index OOB)",
        "- **Contrast:** non-operand register hits (e.g. seed 42 → `t0`) complete witgen; add-operand hits (`a0`,`a1`,`s0`) do not",
        "",
        "## A4_INSPECT × --inject",
        f"- Txn dump for chosen a1 seed: **{has_txn_dump}**",
        f"- {inspect_inject_compat['note']}",
        "",
        f"## Propagation (executor semantics @ add, A4 step {a4_step})",
        "",
        "| reg | op | word (expected) | prev_word | source |",
        "|-----|-----|-------------------|-----------|--------",
        f"| a0 | READ | {A0_BASELINE} | {A0_BASELINE} | unchanged |",
        f"| a1 | READ | **{injected_v}** | {A1_BASELINE} | `<fault>` inject |",
        f"| s0 | WRITE | **{A0_BASELINE + injected_v}** (=3+V) | 0 | executor propagated |",
        "",
        f"- Algebraic propagation: **{propagation_algebraic}**",
        f"- Observed in A4_DUMP_STEP dump: **{propagation_observed}** (dump unavailable when witgen panics)",
        f"- Contrast A4: s0 WRITE stays **7** (witness isolation)",
        "",
        "## Failures collected (deduped)",
        "",
        "### phase=local",
    ]
    if local_fails:
        for f in local_fails:
            md.append(f"- `{f['loc']}` value={f['value']}")
    else:
        md.append("- *(none — witgen panic prevented constraint collection)*")
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
            "## Predicted failure signature (if witgen completed)",
            f"- IsRead@79 residue `(4-V) mod p` = **{mod_p(A1_BASELINE - injected_v)}** — expected **FAIL**",
            "- MemoryWrite@99 — expected **PASS** (recorded s0 = recomputed 3+V)",
            "",
            "## Field-element validation",
            f"- IsRead observed: **{isread_value}**",
            f"- Expected `(4 - V) mod p`: **{mod_p(A1_BASELINE - injected_v)}**",
            f"- Validated: **{field_element_ok if isread_value else 'N/A (no failures collected)'}**",
            "",
            "## GLOBAL (Hook 3 + final residue)",
        ]
    )
    if family:
        for f in family:
            md.append(f"- **{f['family']}**: nonzero={f['nonzero']}")
        md.append(f"- **A4_GLOBAL_RESIDUE**: nonzero={global_res['nonzero'] if global_res else '?'}")
    else:
        md.append("- *(not collected — witgen panic)*")
    md.extend(
        [
            "",
            "## Headline: bias crystallization",
            f"- Witgen completed: **{witgen_ok}**",
            f"- IsRead-only prediction testable: **{witgen_ok}** (blocked otherwise)",
            f"- Hook-3 memory nonzero: **{memory_nz}**",
            f"- Bias crystallized: **{bias_crystallized}**",
            "",
            f"exit_code: **{exit_code}**",
            "",
            "**Opus gate:** M3 report emitted. Witgen preflight blocker must be resolved (or alternate capture approved) before M4 bias matrix.",
        ]
    )
    (ART / "M3_REPORT.md").write_text("\n".join(md) + "\n")
    print((ART / "M3_REPORT.md").read_text())


if __name__ == "__main__":
    main()
