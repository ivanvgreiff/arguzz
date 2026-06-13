#!/usr/bin/env python3
"""Bake E2 A4 mirror configs from E0 inspection + E1 Arguzz values."""

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

SMOKE_RUN_IDS = [
    "arguzz_LOAD_VAL_MOD_s0",
    "arguzz_COMP_OUT_MOD_s0",
    "arguzz_STORE_OUT_MOD_s0",
    "arguzz_INSTR_WORD_MOD_s0",
    "arguzz_INSTR_WORD_MOD_s2",
    "arguzz_INSTR_WORD_MOD_s8",
    "a4_LOAD_VAL_MOD_s0",
    "a4_COMP_OUT_MOD_s0",
    "a4_STORE_OUT_MOD_s0",
    "a4_INSTR_WORD_MOD_s0",
    "a4_INSTR_WORD_MOD_s2",
    "a4_INSTR_WORD_MOD_s8",
]

sys.path.insert(0, str(ROOT.parent.parent))

from a4.core.inspection_data import InspectionData  # noqa: E402
from thesis_side_experiments.bias_campaign.a4_config import build_a4_config  # noqa: E402
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


def validate_config(path: Path, expected_a4_step: int) -> None:
    cfg = json.loads(path.read_text())
    step = cfg.get("step")
    if step != expected_a4_step:
        raise ValueError(f"{path.name}: step={step} expected {expected_a4_step}")


def main() -> None:
    if not SITE_CARD.exists():
        raise SystemExit(f"missing {SITE_CARD}")
    assert_frozen_host(HOST)

    site = json.loads(SITE_CARD.read_text())
    offset = int(site["offset"])
    roles = site["roles"]

    print("Loading InspectionData from frozen host (inspection only)…", flush=True)
    data = InspectionData.from_inspection(str(HOST), [])

    CFG_DIR.mkdir(parents=True, exist_ok=True)
    manifest: List[dict] = []

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
        run_id = f"a4_{kind}_s{seed}"
        cfg_name = f"{run_id}.json"
        cfg_path = CFG_DIR / cfg_name
        a4_kind = A4_KIND_FOR_ARGUZZ[kind]

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

        manifest.append(
            {
                "run_id": run_id,
                "run_type": "a4",
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
            }
        )

        arguzz_run_id = f"arguzz_{kind}_s{seed}"
        arguzz_kind = "INSTR_WORD_MOD" if kind == "INSTR_WORD_MOD" else kind
        manifest.append(
            {
                "run_id": arguzz_run_id,
                "run_type": "arguzz",
                "kind": kind,
                "role": role,
                "arguzz_step": arguzz_step,
                "a4_step": a4_step,
                "seed": seed,
                "source_e1_seed": seed,
                "forced_value": forced,
                "forced_value_hex": f"0x{forced:08x}",
                "inject_kind": arguzz_kind,
                "original_value": rec.get("mutated_value")
                if kind != "INSTR_WORD_MOD"
                else None,
                "original_word": 0x00C585B3 if kind == "INSTR_WORD_MOD" else None,
            }
        )

    smoke = [r for r in manifest if r["run_id"] in SMOKE_RUN_IDS]
    if len(smoke) != len(SMOKE_RUN_IDS):
        missing = set(SMOKE_RUN_IDS) - {r["run_id"] for r in smoke}
        raise SystemExit(f"smoke manifest incomplete, missing: {missing}")

    out = {
        "generated_from": "E1 artifacts + E0 site_card",
        "host_sha256": assert_frozen_host(HOST),
        "offset": offset,
        "prove_error_seeds_excluded": sorted(PROVE_ERROR_SEEDS),
        "a4_config_count": len([r for r in manifest if r["run_type"] == "a4"]),
        "arguzz_entry_count": len([r for r in manifest if r["run_type"] == "arguzz"]),
        "runs": manifest,
    }
    (CFG_DIR / "manifest.json").write_text(json.dumps(out, indent=2))

    smoke_out = {
        "description": "P1/P2 smoke (6 Arguzz + 6 A4 mirrors)",
        "run_ids": SMOKE_RUN_IDS,
        "runs": smoke,
    }
    (CFG_DIR / "manifest_smoke.json").write_text(json.dumps(smoke_out, indent=2))

    print(f"baked {out['a4_config_count']} A4 configs")
    print(f"manifest entries: {len(manifest)} ({len(smoke)} smoke)")
    print(f"wrote {CFG_DIR / 'manifest.json'}")


if __name__ == "__main__":
    main()
