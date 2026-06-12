#!/usr/bin/env python3
"""E1 — Arguzz characterization at frozen E0 sites."""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent
E0_ART = ROOT / "artifacts" / "e0"
ART = ROOT / "artifacts" / "e1"
HOST = ROOT / "target/release/thesis-minimal-host"
SITE_CARD = E0_ART / "site_card.json"
PRODUCTION_HOST = Path("/root/arguzz/workspace/output/target/release/risc0-host")

BABYBEAR_P = 2013265921
ADD_INSTR_WORD = 0x00C585B3

sys.path.insert(0, str(ROOT.parent.parent))

from a4.standalone.mutations.instr_word_mod_sur import RiscVInstruction  # noqa: E402
from thesis_side_experiments.bias_campaign.categorize import mem_zir_loc_matches  # noqa: E402
from thesis_side_experiments.bias_campaign.run_arguzz import run_arguzz  # noqa: E402
from thesis_side_experiments.bias_campaign.run_common import (  # noqa: E402
    failure_rows,
    global_failure_rows,
)

TARGETS = [
    {"kind": "LOAD_VAL_MOD", "role": "load_x", "step": 193, "original_value": 3},
    {"kind": "COMP_OUT_MOD", "role": "add", "step": 195, "original_value": 7},
    {"kind": "STORE_OUT_MOD", "role": "store", "step": 196, "original_value": 7},
    {
        "kind": "INSTR_WORD_MOD",
        "role": "add",
        "step": 195,
        "original_value": None,
        "original_word": ADD_INSTR_WORD,
    },
]

VALUE_SEEDS = list(range(5))
INSTR_SEED_SWEEP = list(range(51))


def mod_p(x: int) -> int:
    return x % BABYBEAR_P


def predicted_residue(original: int, mutated: int) -> int:
    return mod_p(original - mutated)


def thesis_layer(loc: str, phase: str) -> str:
    if phase == "accum":
        return "global"
    if phase != "local":
        raise ValueError(f"unexpected phase {phase!r}")
    if mem_zir_loc_matches(loc, "MemoryWrite@mem.zir:99") or mem_zir_loc_matches(
        loc, "MemoryWrite@mem.zir:100"
    ):
        return "intrastep-local"
    if (
        mem_zir_loc_matches(loc, "IsRead@mem.zir:79")
        or mem_zir_loc_matches(loc, "IsRead@mem.zir:80")
        or mem_zir_loc_matches(loc, "IsCycle@mem.zir:61")
        or mem_zir_loc_matches(loc, "IsCycle@mem.zir:62")
    ):
        return "interstep-local"
    return "intrastep-local"


def bucket_failures(rows: List[dict]) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {
        "intrastep-local": [],
        "interstep-local": [],
        "global": [],
    }
    for row in rows:
        layer = thesis_layer(row["full_loc"], row["phase"])
        out[layer].append(row)
    return out


def failure_fingerprint(rows: List[dict]) -> List[Tuple]:
    return sorted(
        (r["full_loc"], r["major"], r["minor"], r["phase"], r["value"]) for r in rows
    )


def verify_provenance(
    failure: dict, original: Optional[int], mutated: Optional[int]
) -> dict:
    if original is None or mutated is None:
        return {"verified": False, "reason": "non-scalar mutation"}
    pred = predicted_residue(original, mutated)
    alt = mod_p(mutated - original)
    obs = failure["value"]
    if obs == pred:
        return {
            "verified": True,
            "predicted": pred,
            "observed": obs,
            "formula": "(original - mutated) mod p",
            "original": original,
            "mutated": mutated,
        }
    if obs == alt:
        return {
            "verified": True,
            "predicted": alt,
            "observed": obs,
            "formula": "(mutated - original) mod p",
            "original": original,
            "mutated": mutated,
        }
    return {
        "verified": False,
        "predicted_primary": pred,
        "predicted_alt": alt,
        "observed": obs,
        "original": original,
        "mutated": mutated,
    }


def random_word_mode(original: int, mutated: int) -> str:
    """Heuristic matching rv32im.rs random_word selectors 0/1/2."""
    diff = original ^ mutated
    bits = [b for b in range(2, 32) if diff & (1 << b)]
    if len(bits) == 1:
        return "single-bit"
    if len(bits) >= 12:
        return "full-random"
    if len(bits) >= 2:
        return "multi-bit"
    return "full-random"


def instr_modes_complete(modes: Dict[str, dict]) -> bool:
    return {"single-bit", "multi-bit", "full-random"}.issubset(modes)


def mutated_from_record(rec) -> Tuple[Optional[int], Optional[int]]:
    fault = rec.outcome.fault or {}
    if fault.get("kind") == "INSTR_WORD_MOD" or "mutated_value" in fault:
        word = fault.get("mutated_value") or fault.get("value")
        if word is not None:
            return None, int(word)
    val = fault.get("mutated_value") or fault.get("value")
    if val is not None:
        return int(val), None
    return None, None


def production_mtime() -> float:
    return PRODUCTION_HOST.stat().st_mtime if PRODUCTION_HOST.exists() else -1.0


def run_config(kind: str, step: int, seed: int) -> Tuple[Any, Any]:
    log_path = ART / f"{kind}_seed{seed}.log"
    r1 = run_arguzz(
        str(HOST), [], kind, step, seed, log_path=log_path, guest="minimal_add"
    )
    r2 = run_arguzz(str(HOST), [], kind, step, seed, guest="minimal_add")
    return r1, r2


def analyze_run(
    rec,
    target: dict,
    seed: int,
    determinism_ok: bool,
) -> dict:
    rows = failure_rows(rec.outcome)
    buckets = bucket_failures(rows)
    global_fams = global_failure_rows(rec.outcome)
    accum_rows = [r for r in rows if r["phase"] == "accum"]
    global_count = len(global_fams) + len(accum_rows)

    val_mut, word_mut = mutated_from_record(rec)
    original_val = target.get("original_value")
    original_word = target.get("original_word")

    decoded = None
    word_mode = None
    if target["kind"] == "INSTR_WORD_MOD" and word_mut is not None:
        insn = RiscVInstruction.from_word(word_mut)
        decoded = {
            "word_hex": f"0x{word_mut:08x}",
            "disassembly": insn.disassemble(),
            "format_name": insn.format_name,
        }
        word_mode = random_word_mode(original_word, word_mut)

    provenance: List[dict] = []
    for layer in ("intrastep-local", "interstep-local"):
        for f in buckets[layer]:
            prov = verify_provenance(f, original_val, val_mut)
            provenance.append(
                {
                    "layer": layer,
                    "loc": f["full_loc"][:120],
                    "value": f["value"],
                    **prov,
                }
            )

    example = None
    for layer in ("interstep-local", "intrastep-local", "global"):
        if layer == "global":
            if global_fams:
                example = f"global family {global_fams[0]['family']} nonzero"
            elif accum_rows:
                example = f"ACCUM {accum_rows[0]['full_loc'][:60]} value={accum_rows[0]['value']}"
            if example:
                break
            continue
        for f, p in zip(buckets[layer], [x for x in provenance if x["layer"] == layer]):
            if p.get("verified"):
                example = f"{layer}: {f['full_loc'][:50]}… residue={f['value']}"
                break
        if example:
            break
    if not example and buckets["intrastep-local"]:
        f = buckets["intrastep-local"][0]
        example = f"intrastep-local: {f['full_loc'][:50]}… value={f['value']}"

    return {
        "kind": target["kind"],
        "role": target["role"],
        "seed": seed,
        "inject_step": target["step"],
        "mutated_value": val_mut,
        "mutated_word": word_mut,
        "mutated_word_hex": f"0x{word_mut:08x}" if word_mut is not None else None,
        "random_word_mode": word_mode,
        "decoded_instruction": decoded,
        "outcome_class": rec.outcome.outcome_class,
        "preflight_crash": rec.outcome.preflight_crash,
        "verifier_success": rec.outcome.verifier_success,
        "soundness_escape": rec.outcome.soundness_escape,
        "determinism_ok": determinism_ok,
        "failure_count": len(rows),
        "layers": {
            "intrastep-local": len(buckets["intrastep-local"]),
            "interstep-local": len(buckets["interstep-local"]),
            "global": global_count,
        },
        "buckets": buckets,
        "global_families": global_fams,
        "provenance": provenance,
        "example_loc_residue": example,
        "log_path": rec.raw_log_path,
    }


def determinism_match(r1, r2, original_val, original_word) -> bool:
    v1, w1 = mutated_from_record(r1)
    v2, w2 = mutated_from_record(r2)
    if v1 != v2 or w1 != w2:
        return False
    return failure_fingerprint(failure_rows(r1.outcome)) == failure_fingerprint(
        failure_rows(r2.outcome)
    )


def main() -> None:
    ART.mkdir(parents=True, exist_ok=True)
    if not HOST.exists():
        raise SystemExit(f"missing host: {HOST} (run E0 ./build.sh first)")
    if not SITE_CARD.exists():
        raise SystemExit(f"missing {SITE_CARD}")

    site = json.loads(SITE_CARD.read_text())
    mtime_before = production_mtime()
    t0 = datetime.now(tz=timezone.utc)

    results: List[dict] = []
    gate_errors: List[str] = []
    instr_modes: Dict[str, dict] = {}

    for target in TARGETS[:3]:
        for seed in VALUE_SEEDS:
            r1, r2 = run_config(target["kind"], target["step"], seed)
            det = determinism_match(r1, r2, target["original_value"], None)
            if not det:
                gate_errors.append(f"{target['kind']} seed={seed} nondeterministic")
            if r1.outcome.preflight_crash or r1.outcome.outcome_class in (
                "PREFLIGHT_CRASH",
                "OTHER_CRASH",
            ):
                gate_errors.append(
                    f"{target['kind']} seed={seed} crashed: {r1.outcome.outcome_class} "
                    f"panic={r1.outcome.panic_loc}"
                )
            rec = analyze_run(r1, target, seed, det)
            path = ART / f"{target['kind']}_seed{seed}.json"
            path.write_text(json.dumps(rec, indent=2))
            results.append(rec)

    instr_target = TARGETS[3]
    for seed in INSTR_SEED_SWEEP:
        if instr_modes_complete(instr_modes):
            break
        r1, r2 = run_config(instr_target["kind"], instr_target["step"], seed)
        det = determinism_match(r1, r2, None, ADD_INSTR_WORD)
        if not det:
            gate_errors.append(f"INSTR_WORD_MOD seed={seed} nondeterministic")
        if r1.outcome.preflight_crash:
            gate_errors.append(
                f"INSTR_WORD_MOD seed={seed} preflight crash: {r1.outcome.panic_loc}"
            )
        rec = analyze_run(r1, instr_target, seed, det)
        mode = rec.get("random_word_mode")
        if mode and mode not in instr_modes:
            instr_modes[mode] = rec
        path = ART / f"INSTR_WORD_MOD_seed{seed}.json"
        path.write_text(json.dumps(rec, indent=2))
        results.append(rec)

    missing_modes = {"single-bit", "multi-bit", "full-random"} - set(instr_modes)
    if missing_modes:
        gate_errors.append(f"INSTR_WORD_MOD missing modes: {sorted(missing_modes)}")

    mtime_after = production_mtime()
    if mtime_before != mtime_after:
        gate_errors.append("production risc0-host mtime changed")

    all_det = all(r["determinism_ok"] for r in results)
    no_crash = all(not r["preflight_crash"] for r in results)
    prov_ok = True
    for r in results:
        cited = [p for p in r["provenance"] if p.get("verified") is False]
        scalar = r["mutated_value"] is not None
        if scalar and r["layers"]["intrastep-local"] + r["layers"]["interstep-local"] > 0:
            if not any(p.get("verified") for p in r["provenance"]):
                prov_ok = False
                gate_errors.append(
                    f"{r['kind']} seed={r['seed']}: no verified provenance for scalar failures"
                )

    acceptance = {
        "all_four_kinds": True,
        "value_seeds_0_4": True,
        "instr_three_modes": len(missing_modes) == 0,
        "instr_modes_captured": {k: v["seed"] for k, v in instr_modes.items()},
        "determinism_all": all_det,
        "provenance_scalar_runs": prov_ok,
        "no_preflight_crash": no_crash,
        "production_host_mtime_unchanged": mtime_before == mtime_after,
        "gate_pass": not gate_errors,
    }

    summary_rows = []
    for r in results:
        mut = (
            r["mutated_word_hex"]
            if r["mutated_word"] is not None
            else str(r["mutated_value"])
        )
        dec = ""
        if r.get("decoded_instruction"):
            dec = r["decoded_instruction"]["disassembly"]
        summary_rows.append(
            "| {kind} | {role} | {seed} | {mut} | {dec} | {oc} | {i} | {j} | {g} | {ex} |".format(
                kind=r["kind"],
                role=r["role"],
                seed=r["seed"],
                mut=mut,
                dec=dec.replace("|", "\\|")[:40],
                oc=r["outcome_class"],
                i=r["layers"]["intrastep-local"],
                j=r["layers"]["interstep-local"],
                g=r["layers"]["global"],
                ex=(r.get("example_loc_residue") or "")[:60],
            )
        )

    md = [
        "# E1 Arguzz summary",
        "",
        "| kind | role | seed | mutated | decoded | outcome | #intrastep | #interstep | #global | example |",
        "|------|------|------|---------|---------|---------|------------|------------|---------|---------|",
        *summary_rows,
        "",
        "## INSTR_WORD_MOD mode coverage",
    ]
    for mode, rec in sorted(instr_modes.items()):
        md.append(
            f"- **{mode}**: seed={rec['seed']} word={rec['mutated_word_hex']} "
            f"`{rec['decoded_instruction']['disassembly']}`"
        )
    (ART / "arguzz_summary.md").write_text("\n".join(md) + "\n")

    report = {
        "milestone": "E1",
        "generated_at": t0.isoformat(),
        "host": str(HOST),
        "site_card": str(SITE_CARD),
        "acceptance": acceptance,
        "gate_errors": gate_errors,
        "instr_modes": instr_modes and {
            k: {
                "seed": v["seed"],
                "word": v["mutated_word_hex"],
                "decoded": v["decoded_instruction"],
                "layers": v["layers"],
            }
            for k, v in instr_modes.items()
        },
        "runs": [
            {k: v for k, v in r.items() if k not in ("buckets", "provenance")}
            for r in results
        ],
    }
    (ART / "E1_REPORT.json").write_text(json.dumps(report, indent=2))

    status = "PASS" if acceptance["gate_pass"] else "FAIL"
    rmd = [
        f"# E1 Report — Arguzz characterization",
        "",
        f"**Status:** {status}",
        "",
        "## Acceptance",
    ]
    for k, v in acceptance.items():
        rmd.append(f"- **{k}**: {v}")
    if gate_errors:
        rmd.append("")
        rmd.append("## Gate errors")
        for e in gate_errors:
            rmd.append(f"- {e}")
    rmd.append("")
    rmd.append("See `arguzz_summary.md` for the full Arguzz column table.")
    (ART / "E1_REPORT.md").write_text("\n".join(rmd) + "\n")

    print((ART / "E1_REPORT.md").read_text())
    if not acceptance["gate_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
