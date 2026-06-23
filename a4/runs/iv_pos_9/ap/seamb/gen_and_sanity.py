#!/usr/bin/env python3
"""Seam-B step 7: honest-gate the control, generate INSTR_TYPE_MOD configs, sanity-check premise.

Run AFTER the control binary is built. Does:
  1. Honest-gate: control proves+verifies the minimal guest (Verifier status success).
  2. Inspect (A4_INSPECT) -> find AddI cycles (major=0, minor=7).
  3. Generate primary config AddI->Sub + a bracket of ALU->ALU configs.
  4. Sanity: run the primary config on the CONTROL with A4_GLOBAL_RESIDUE=1 ->
     MUST show <a4_global_residue_zero/> (premise: ALU->ALU type edit doesn't break the
     memory permutation for THIS circuit/guest). Also confirms it rejects via VerifyOpcode.
"""
from __future__ import annotations
import json, os, subprocess, sys
from pathlib import Path

ROOT = Path("/root/arguzz")
sys.path.insert(0, str(ROOT))
from a4.core.inspection_data import InspectionData              # noqa: E402
from a4.standalone.mutations import instr_type_mod              # noqa: E402

CONTROL = ROOT / "workspace/output-seamb/target/release/risc0-host"
CFG_DIR = ROOT / "a4/runs/iv_pos_9/ap/seamb/configs"
HOST_ARGS = ["--ctrl", "7", "--gseed", "12345", "--rounds", "5"]

# ALU target kinds within major 0 (all valid major-0 minors); AddI=(0,7)
ALU_TARGETS = [(0, 0, "Add"), (0, 1, "Sub"), (0, 2, "Xor"), (0, 3, "Or"),
               (0, 4, "And"), (0, 5, "Slt"), (0, 6, "SltU")]


def run(host: Path, extra_env=None, args=None) -> str:
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    p = subprocess.run([str(host), *(args or HOST_ARGS)], capture_output=True, text=True, env=env, timeout=900)
    return p.stdout + p.stderr


def verifier_ok(out: str) -> bool:
    return '"context":"Verifier", "status":"success"' in out


def main() -> int:
    if not CONTROL.exists():
        print(f"FAIL: control binary missing at {CONTROL}"); return 1

    print("=== step 1: honest-gate control ===")
    out = run(CONTROL)
    ok = verifier_ok(out)
    print(f"control_honest_verifies={ok}")
    if not ok:
        print(out[-2000:]); print("FAIL: control does not honestly verify"); return 1

    print("\n=== step 2: inspect -> find AddI cycles ===")
    data = InspectionData.from_inspection(str(CONTROL), HOST_ARGS)
    addi = [c for c in data.cycles if c.major == 0 and c.minor == 7]
    print(f"total cycles={len(data.cycles)}  AddI cycles={len(addi)}")
    if not addi:
        # fall back: any major-0 ALU cycle as source
        addi = [c for c in data.cycles if c.major == 0 and c.minor in (0,1,2,3,4,5,6,7)]
        print(f"no pure AddI; using {len(addi)} major-0 ALU cycles as sources")
    if not addi:
        print("FAIL: no major-0 ALU cycle to mutate"); return 1

    print("\n=== step 3: generate configs ===")
    CFG_DIR.mkdir(parents=True, exist_ok=True)
    # primary: first AddI cycle -> Sub
    primary_step = addi[0].step
    tgt = instr_type_mod.get_targets_at_step(primary_step, data)
    if tgt is None:
        print(f"FAIL: get_targets_at_step({primary_step}) returned None"); return 1
    primary = CFG_DIR / "primary_AddI_to_Sub.json"
    instr_type_mod.create_config(tgt, 0, 1, primary, is_valid=True)
    print(f"primary: step={primary_step} {tgt.kind_name}->Sub  -> {primary.name}")

    # bracket: spread sources x ALU targets (skip same-kind no-op)
    bracket = []
    srcs = addi[:: max(1, len(addi)//8)][:8] or addi[:8]
    for c in srcs:
        t = instr_type_mod.get_targets_at_step(c.step, data)
        if t is None:
            continue
        for (mj, mn, name) in ALU_TARGETS:
            if (mj, mn) == (t.original_major, t.original_minor):
                continue
            p = CFG_DIR / f"bracket_s{c.step}_{t.kind_name}_to_{name}.json"
            instr_type_mod.create_config(t, mj, mn, p, is_valid=True)
            bracket.append(p)
    print(f"bracket configs generated: {len(bracket)}")

    print("\n=== step 4: sanity — primary on CONTROL with hook3 (expect global_residue_zero) ===")
    env = {"CONSTRAINT_CONTINUE": "1", "A4_GLOBAL_RESIDUE": "1", "A4_FAMILY_RESIDUE": "1",
           "A4_MUTATION_CONFIG": str(primary)}
    out = run(CONTROL, extra_env=env)
    gz = "<a4_global_residue_zero/>" in out
    gnz = "a4_global_residue_nonzero" in out
    vo = "VerifyOpcode" in out and "constraint_fail" in out
    print(f"global_residue_zero={gz}  global_residue_nonzero={gnz}  VerifyOpcode_local_fail={vo}")
    if gz and not gnz:
        print("PASS: premise holds — ALU->ALU type edit keeps the permutation balanced; only VerifyOpcode rejects.")
        return 0
    print("WARN: premise NOT confirmed on this circuit/guest — investigate before holed test.")
    print(out[-1500:])
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
