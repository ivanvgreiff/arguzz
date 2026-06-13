#!/usr/bin/env python3
"""Host-free log analyzer — same JSON shape as E1 per-run records."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

BABYBEAR_P = 2013265921
ORIG_WORD = 0x00C585B3
PROVER_FAST_ERROR_RE = re.compile(
    r'"context":"Prover", "status":"error", "time":"[\d.]+ms"'
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from a4.standalone.mutations.instr_word_mod_sur import RiscVInstruction  # noqa: E402
from thesis_side_experiments.bias_campaign.categorize import mem_zir_loc_matches  # noqa: E402
from thesis_side_experiments.bias_campaign.classify import classify_run  # noqa: E402
from thesis_side_experiments.bias_campaign.run_common import (  # noqa: E402
    failure_rows,
    global_failure_rows,
)


def mod_p(x: int) -> int:
    return x % BABYBEAR_P


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
        out[thesis_layer(row["full_loc"], row["phase"])].append(row)
    return out


def failure_fingerprint(log_text: str) -> List[Tuple]:
    outcome = classify_run(log_text, target_step=None)
    rows = failure_rows(outcome)
    return sorted(
        (r["full_loc"], r["major"], r["minor"], r["phase"], r["value"]) for r in rows
    )


def verify_provenance(
    failure: dict, original: Optional[int], mutated: Optional[int]
) -> dict:
    if original is None or mutated is None:
        return {"verified": False, "reason": "non-scalar mutation"}
    pred = mod_p(original - mutated)
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


def is_prove_error(log_text: str) -> bool:
    has_fast = PROVER_FAST_ERROR_RE.search(log_text) is not None
    has_panic = "panicked at host/src/main.rs:106" in log_text
    has_verifier = '"context":"Verifier"' in log_text
    no_fails = "<constraint_fail>" not in log_text
    return has_fast and has_panic and not has_verifier and no_fails


def diff_fields(orig: RiscVInstruction, mut: RiscVInstruction) -> List[str]:
    changed = []
    for name in ("opcode", "rd", "funct3", "rs1", "rs2", "funct7"):
        if getattr(orig, name) != getattr(mut, name):
            changed.append(name)
    return changed


def classify_field_class(
    changed: List[str], mut: RiscVInstruction, outcome: str, seed: int
) -> str:
    if outcome == "PROVE_ERROR":
        return "control_flow"
    op_changed = bool(set(changed) & {"opcode", "funct3", "funct7"})
    rd_changed = "rd" in changed
    src_changed = bool(set(changed) & {"rs1", "rs2"})
    if seed == 24 and rd_changed and mut.rd == 10:
        return "dest_reg_a0"
    if "opcode" in changed and mut.format_name not in ("OP",):
        return "format_change"
    if op_changed and (rd_changed or src_changed):
        return "reg+operation"
    if rd_changed and not op_changed and not src_changed:
        return "dest_reg"
    if src_changed and not rd_changed and not op_changed:
        return "src_reg"
    if op_changed:
        return "operation"
    return "other"


def analyze_log(entry: dict, log_text: str, log_path: str) -> dict:
    run_type = entry["run_type"]
    kind = entry.get("kind") or entry.get("a4_kind", "")
    seed = entry.get("seed", 0)
    arguzz_step = entry.get("arguzz_step")
    variant = entry.get("variant", "FULL")

    if run_type == "arguzz":
        outcome = classify_run(log_text, target_step=arguzz_step)
        inject_step = arguzz_step
    else:
        outcome = classify_run(log_text, target_step=None, injected_override=True)
        inject_step = arguzz_step

    if is_prove_error(log_text):
        outcome_class = "PROVE_ERROR"
        layers = None
        crash_stage = "prove"
        crash_evidence = (
            "Prover status=error @~37ms; host panic main.rs:106; verifier never ran"
        )
    else:
        outcome_class = outcome.outcome_class
        crash_stage = None
        crash_evidence = None

    rows = failure_rows(outcome)
    buckets = bucket_failures(rows)
    global_fams = global_failure_rows(outcome)
    accum_rows = [r for r in rows if r["phase"] == "accum"]
    global_count = len(global_fams) + len(accum_rows)

    if outcome_class != "PROVE_ERROR":
        layers = {
            "intrastep-local": len(buckets["intrastep-local"]),
            "interstep-local": len(buckets["interstep-local"]),
            "global": global_count,
        }

    forced = entry.get("forced_value")
    val_mut = forced if kind not in ("INSTR_WORD_MOD", "INSTR_WORD_MOD_SUR") else None
    word_mut = forced if kind in ("INSTR_WORD_MOD", "INSTR_WORD_MOD_SUR") else None

    decoded = None
    fields_changed = entry.get("fields_changed")
    field_class = entry.get("field_class")
    if kind in ("INSTR_WORD_MOD", "INSTR_WORD_MOD_SUR") and word_mut is not None:
        insn = RiscVInstruction.from_word(int(word_mut))
        decoded = {
            "word_hex": f"{int(word_mut):#010x}",
            "disassembly": insn.disassemble(),
            "format_name": insn.format_name,
        }
        if fields_changed is None:
            orig = RiscVInstruction.from_word(ORIG_WORD)
            mut = RiscVInstruction.from_word(int(word_mut))
            fields_changed = diff_fields(orig, mut)
        if field_class is None:
            field_class = classify_field_class(
                fields_changed or [], insn, outcome_class, seed
            )

    original_val = entry.get("original_value")
    if original_val is None and kind not in (
        "INSTR_WORD_MOD",
        "INSTR_WORD_MOD_SUR",
    ):
        originals = {
            "LOAD_VAL_MOD": 3,
            "COMP_OUT_MOD": 7,
            "STORE_OUT_MOD": 7,
            "MEM_VAL_MOD": None,
        }
        if kind == "MEM_VAL_MOD":
            original_val = entry.get("original_value")
        else:
            original_val = originals.get(kind)

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
                example = (
                    f"ACCUM {accum_rows[0]['full_loc'][:60]} "
                    f"value={accum_rows[0]['value']}"
                )
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

    rec: Dict[str, Any] = {
        "run_id": entry["run_id"],
        "run_type": run_type,
        "part": entry.get("part"),
        "variant": variant,
        "kind": kind,
        "role": entry.get("role"),
        "seed": seed,
        "inject_step": inject_step,
        "mutated_value": val_mut,
        "mutated_word": word_mut,
        "mutated_word_hex": f"{int(word_mut):#010x}" if word_mut is not None else None,
        "decoded_instruction": decoded,
        "outcome_class": outcome_class,
        "preflight_crash": outcome.preflight_crash,
        "verifier_success": outcome.verifier_success,
        "soundness_escape": outcome.soundness_escape,
        "failure_count": len(rows),
        "layers": layers,
        "buckets": buckets,
        "global_families": global_fams,
        "provenance": provenance,
        "example_loc_residue": example,
        "log_path": log_path,
        "fields_changed": fields_changed,
        "field_class": field_class,
    }
    if run_type == "a4":
        rec["config_file"] = entry.get("config_file")
        if entry.get("part") == "A":
            rec["mirror_note"] = (
                f"A4 FULL mirror of E1 {kind} seed {seed} "
                f"value={entry.get('forced_value_hex')}"
            )
        elif entry.get("part") == "B":
            rec["surgical_field"] = entry.get("surgical_field")
        elif entry.get("part") == "C":
            rec["txn_type"] = entry.get("txn_type")
            rec["arguzz_mirror"] = entry.get("arguzz_mirror")
    if crash_stage:
        rec["crash_stage"] = crash_stage
        rec["crash_evidence"] = crash_evidence
    return rec


def load_manifest(path: Path) -> List[dict]:
    data = json.loads(path.read_text())
    if "runs" in data:
        return data["runs"]
    if isinstance(data, list):
        return data
    raise ValueError(f"unrecognized manifest shape: {path}")


def compare_to_e1(rec: dict, e1_dir: Path) -> Optional[str]:
    if rec["run_type"] != "arguzz":
        return None
    kind = rec["kind"]
    seed = rec["seed"]
    e1_path = e1_dir / f"{kind}_seed{seed}.json"
    if not e1_path.exists():
        return f"missing E1 reference {e1_path}"
    e1 = json.loads(e1_path.read_text())
    if e1.get("outcome_class") == "PROVE_ERROR":
        return None
    if rec["outcome_class"] != e1["outcome_class"]:
        return (
            f"{rec['run_id']}: outcome {rec['outcome_class']} != E1 {e1['outcome_class']}"
        )
    for key in ("intrastep-local", "interstep-local", "global"):
        got = (rec.get("layers") or {}).get(key, 0)
        exp = (e1.get("layers") or {}).get(key, 0)
        if got != exp:
            return f"{rec['run_id']}: layer {key} {got} != E1 {exp}"
    return None


def main() -> None:
    ap = argparse.ArgumentParser(description="Analyze thesis run logs (no host)")
    ap.add_argument("--manifest", type=Path, required=True)
    ap.add_argument("--log-dir", type=Path, required=True)
    ap.add_argument("--out-dir", type=Path, required=True)
    ap.add_argument("--e1-dir", type=Path, default=None, help="Compare Arguzz to E1")
    ap.add_argument("--rerun-suffix", default=".rerun", help="Rerun log suffix")
    args = ap.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    entries = load_manifest(args.manifest)
    results: List[dict] = []
    deviations: List[str] = []
    det_failures: List[str] = []

    for entry in entries:
        run_id = entry["run_id"]
        log_path = args.log_dir / f"{run_id}.log"
        if not log_path.exists():
            deviations.append(f"missing log {log_path}")
            continue
        log_text = log_path.read_text()
        rec = analyze_log(entry, log_text, str(log_path))
        out_path = args.out_dir / f"{run_id}.json"
        out_path.write_text(json.dumps(rec, indent=2))
        results.append(rec)

        rerun_path = args.log_dir / f"{run_id}{args.rerun_suffix}.log"
        if rerun_path.exists():
            fp1 = failure_fingerprint(log_text)
            fp2 = failure_fingerprint(rerun_path.read_text())
            det_ok = fp1 == fp2
            rec["determinism_ok"] = det_ok
            if not det_ok:
                det_failures.append(run_id)
        else:
            rec["determinism_ok"] = None

        if args.e1_dir:
            err = compare_to_e1(rec, args.e1_dir)
            if err:
                deviations.append(err)

    report = {
        "manifest": str(args.manifest),
        "log_dir": str(args.log_dir),
        "run_count": len(results),
        "determinism_failures": det_failures,
        "deviations": deviations,
        "runs": [
            {
                "run_id": r["run_id"],
                "run_type": r["run_type"],
                "outcome_class": r["outcome_class"],
                "layers": r.get("layers"),
                "determinism_ok": r.get("determinism_ok"),
            }
            for r in results
        ],
    }
    (args.out_dir / "analysis_report.json").write_text(json.dumps(report, indent=2))

    print(json.dumps(report, indent=2))
    if deviations or det_failures:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
