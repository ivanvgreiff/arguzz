#!/usr/bin/env python3
"""Bake E2-FULL configs: Part A FULL mirrors + Part B SUR + Part C MEM_VAL."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent
E0_ART = ROOT / "artifacts" / "e0"
E1_ART = ROOT / "artifacts" / "e1"
CFG_DIR = ROOT / "artifacts" / "e2" / "configs"
HOST = ROOT / "frozen_host" / "thesis-minimal-host.e0frozen"
SITE_CARD = E0_ART / "site_card.json"
PROVE_ERROR_SEEDS = {1, 7, 9, 17, 25, 27, 29}
ORIG_WORD = 0x00C585B3

sys.path.insert(0, str(ROOT.parent.parent))

from a4.core.inspection_data import InspectionData  # noqa: E402
from a4.standalone.mutations.instr_word_mod_sur import (  # noqa: E402
    RiscVInstruction,
    SurgicalField,
)
from thesis_side_experiments.bias_campaign.a4_config import (  # noqa: E402
    build_a4_config,
    build_a4_mem_val_config,
    build_a4_sur_config,
    pick_mutated_value,
)
from a4.standalone.mutations.mem_val_mod import get_targets_at_step as get_mem_targets  # noqa: E402
from thesis_side_experiments.minimal_add.host_guard import assert_frozen_host  # noqa: E402

ROLE_FOR_KIND = {
    "LOAD_VAL_MOD": "load_x",
    "COMP_OUT_MOD": "add",
    "STORE_OUT_MOD": "store",
    "INSTR_WORD_MOD": "add",
}

A4_KIND_FOR_ARGUZZ = {
    "LOAD_VAL_MOD": "LOAD_VAL_MOD",
    "COMP_OUT_MOD": "COMP_OUT_MOD",
    "STORE_OUT_MOD": "STORE_OUT_MOD",
    "INSTR_WORD_MOD": "INSTR_WORD_MOD_FULL",
}

SUR_VARIANTS = [
    ("funct3_xor", SurgicalField.FUNCT3, 4),
    ("funct3_slt", SurgicalField.FUNCT3, 2),
    ("funct7_sub", SurgicalField.FUNCT7, 0x20),
    ("rd", SurgicalField.RD, 10),
    ("rs1", SurgicalField.RS1, 10),
    ("rs2", SurgicalField.RS2, 10),
]

MEM_VAL_TARGETS = [
    ("load_x", "load_mem_read", 193),
    ("load_y", "load_mem_read", 194),
    ("read_back", "load_mem_read", 197),
    ("store", "store_rmw_read", 196),
]

MEM_VAL_SEEDS = (0, 1)


def load_e1_runs() -> List[dict]:
    runs: List[dict] = []
    for kind in ("LOAD_VAL_MOD", "COMP_OUT_MOD", "STORE_OUT_MOD"):
        for seed in range(5):
            path = E1_ART / f"{kind}_seed{seed}.json"
            if not path.exists():
                raise SystemExit(f"missing {path}")
            rec = json.loads(path.read_text())
            if rec.get("outcome_class") == "PROVE_ERROR":
                continue
            runs.append(rec)
    for seed in range(31):
        path = E1_ART / f"INSTR_WORD_MOD_seed{seed}.json"
        if not path.exists():
            continue
        rec = json.loads(path.read_text())
        if seed in PROVE_ERROR_SEEDS or rec.get("outcome_class") == "PROVE_ERROR":
            continue
        runs.append(rec)
    return runs


def forced_value_for(rec: dict) -> int:
    if rec["kind"] == "INSTR_WORD_MOD":
        word = rec.get("mutated_word")
        if word is None:
            raise ValueError(f"INSTR seed {rec['seed']} missing mutated_word")
        return int(word)
    val = rec.get("mutated_value")
    if val is None:
        raise ValueError(f"{rec['kind']} seed {rec['seed']} missing mutated_value")
    return int(val)


def e1_field_labels(rec: dict) -> tuple[Optional[List[str]], Optional[str]]:
    return rec.get("fields_changed"), rec.get("field_class")


def validate_config(path: Path, expected_a4_step: int) -> None:
    cfg = json.loads(path.read_text())
    step = cfg.get("step")
    if step != expected_a4_step:
        raise ValueError(f"{path.name}: step={step} expected {expected_a4_step}")


def bake_part_a(
    data: InspectionData,
    site: dict,
    offset: int,
    manifest: List[dict],
) -> None:
    roles = site["roles"]
    for rec in load_e1_runs():
        kind = rec["kind"]
        seed = rec["seed"]
        role = ROLE_FOR_KIND[kind]
        arguzz_step = int(rec["inject_step"])
        a4_step = arguzz_step + offset
        expected_a4 = int(roles[role]["a4_step"])
        if a4_step != expected_a4:
            raise SystemExit(
                f"{kind} seed {seed}: a4_step {a4_step} != site_card {expected_a4}"
            )

        forced = forced_value_for(rec)
        run_id = f"a4_full_{kind}_s{seed}"
        cfg_name = f"{run_id}.json"
        cfg_path = CFG_DIR / cfg_name
        a4_kind = A4_KIND_FOR_ARGUZZ[kind]
        fields_changed, field_class = e1_field_labels(rec)

        built = build_a4_config(
            a4_kind,
            arguzz_step,
            seed,
            data,
            cfg_path,
            step_offset=offset,
            forced_value=forced,
        )
        if built is None:
            raise SystemExit(f"build_a4_config returned None for {run_id}")
        validate_config(cfg_path, expected_a4)

        entry: Dict[str, Any] = {
            "run_id": run_id,
            "run_type": "a4",
            "part": "A",
            "variant": "FULL",
            "kind": kind,
            "a4_kind": a4_kind,
            "role": role,
            "arguzz_step": arguzz_step,
            "a4_step": a4_step,
            "seed": seed,
            "source_e1_seed": seed,
            "forced_value": forced,
            "forced_value_hex": f"0x{forced:08x}",
            "config_file": f"configs/{cfg_name}",
            "target_desc": built[1],
            "fields_changed": fields_changed,
            "field_class": field_class,
        }
        if kind == "INSTR_WORD_MOD":
            entry["original_word"] = ORIG_WORD
            entry["original_word_hex"] = f"0x{ORIG_WORD:08x}"
        manifest.append(entry)


def bake_part_b(
    data: InspectionData,
    site: dict,
    offset: int,
    manifest: List[dict],
) -> None:
    role = "add"
    arguzz_step = int(site["roles"][role]["arguzz_step"])
    a4_step = int(site["roles"][role]["a4_step"])
    orig = RiscVInstruction.from_word(ORIG_WORD)

    for sur_id, field, new_val in SUR_VARIANTS:
        run_id = f"a4_sur_{sur_id}"
        cfg_name = f"{run_id}.json"
        cfg_path = CFG_DIR / cfg_name
        built = build_a4_sur_config(
            field, new_val, arguzz_step, data, cfg_path, step_offset=offset
        )
        if built is None:
            raise SystemExit(f"SUR build failed for {sur_id}")
        _, desc, mutated_word = built
        validate_config(cfg_path, a4_step)
        mut_insn = RiscVInstruction.from_word(mutated_word)
        changed = [
            n
            for n in ("opcode", "rd", "funct3", "rs1", "rs2", "funct7")
            if getattr(orig, n) != getattr(mut_insn, n)
        ]
        manifest.append(
            {
                "run_id": run_id,
                "run_type": "a4",
                "part": "B",
                "variant": "SUR",
                "kind": "INSTR_WORD_MOD_SUR",
                "a4_kind": "INSTR_WORD_MOD_SUR",
                "role": role,
                "arguzz_step": arguzz_step,
                "a4_step": a4_step,
                "seed": 0,
                "surgical_field": field.value,
                "surgical_new_value": new_val,
                "forced_value": mutated_word,
                "forced_value_hex": f"0x{mutated_word:08x}",
                "original_word": ORIG_WORD,
                "original_word_hex": f"0x{ORIG_WORD:08x}",
                "fields_changed": changed,
                "field_class": sur_id,
                "config_file": f"configs/{cfg_name}",
                "target_desc": desc,
            }
        )


def bake_part_c(
    data: InspectionData,
    site: dict,
    offset: int,
    manifest: List[dict],
) -> None:
    roles = site["roles"]
    for role, txn_type, arguzz_step in MEM_VAL_TARGETS:
        expected_a4 = int(roles[role]["a4_step"])
        targets = [t for t in get_mem_targets(expected_a4, data) if t.txn_type == txn_type]
        if not targets:
            raise SystemExit(f"no MEM_VAL {txn_type} at {role} a4_step={expected_a4}")
        original = targets[0].original_value
        for seed in MEM_VAL_SEEDS:
            forced = pick_mutated_value(original, seed)
            run_id = f"a4_memval_{role}_s{seed}"
            cfg_name = f"{run_id}.json"
            cfg_path = CFG_DIR / cfg_name
            built = build_a4_mem_val_config(
                arguzz_step,
                data,
                cfg_path,
                seed,
                step_offset=offset,
                txn_type=txn_type,
                forced_value=forced,
            )
            if built is None:
                raise SystemExit(f"MEM_VAL build failed for {run_id}")
            validate_config(cfg_path, expected_a4)
            manifest.append(
                {
                    "run_id": run_id,
                    "run_type": "a4",
                    "part": "C",
                    "variant": "MEM_VAL",
                    "kind": "MEM_VAL_MOD",
                    "a4_kind": "MEM_VAL_MOD",
                    "role": role,
                    "arguzz_step": arguzz_step,
                    "a4_step": expected_a4,
                    "seed": seed,
                    "txn_type": txn_type,
                    "original_value": original,
                    "forced_value": forced,
                    "forced_value_hex": f"0x{forced:08x}",
                    "config_file": f"configs/{cfg_name}",
                    "target_desc": built[1],
                    "arguzz_mirror": "n/a — no in-place memory-read mutation",
                }
            )


def main() -> None:
    if not SITE_CARD.exists():
        raise SystemExit(f"missing {SITE_CARD}")
    host_sha = assert_frozen_host(HOST)
    site = json.loads(SITE_CARD.read_text())
    offset = int(site["offset"])

    print("Loading InspectionData from frozen host…", flush=True)
    data = InspectionData.from_inspection(str(HOST), [])

    CFG_DIR.mkdir(parents=True, exist_ok=True)
    for old in CFG_DIR.glob("a4_*.json"):
        old.unlink()

    manifest: List[dict] = []
    bake_part_a(data, site, offset, manifest)
    bake_part_b(data, site, offset, manifest)
    bake_part_c(data, site, offset, manifest)

    parts = {"A": 0, "B": 0, "C": 0}
    for e in manifest:
        parts[e["part"]] += 1

    out = {
        "generated_from": "E2_FULL_SPEC — Part A+B+C",
        "host_sha256": host_sha,
        "offset": offset,
        "prove_error_seeds_excluded": sorted(PROVE_ERROR_SEEDS),
        "part_counts": parts,
        "run_count": len(manifest),
        "runs": manifest,
    }
    manifest_path = CFG_DIR / "manifest_e2.json"
    manifest_path.write_text(json.dumps(out, indent=2))
    print(f"baked {len(manifest)} configs: A={parts['A']} B={parts['B']} C={parts['C']}")
    print(f"wrote {manifest_path}")


if __name__ == "__main__":
    main()
