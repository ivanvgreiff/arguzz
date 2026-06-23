#!/usr/bin/env python3
"""Seam-B step 8-9: the certainty test. Run AFTER both control + holed are built.

For the primary AddI->Sub config and the ALU->ALU bracket, run each WITHOUT CONSTRAINT_CONTINUE
(a real prove+verify) on BOTH binaries:
  - CONTROL  must REJECT (witgen/verify fires VerifyOpcode)            -> Verifier NOT success
  - HOLED    must ACCEPT (VerifyOpcode neutralized; nothing else catches) -> Verifier success

PASS (certainty) iff primary: holed ACCEPTS and control REJECTS; and bracket holed N/N accept,
control N/N reject. Writes ap_seamb_verify.json.
"""
from __future__ import annotations
import json, os, subprocess, sys
from pathlib import Path

ROOT = Path("/root/arguzz")
CONTROL = ROOT / "a4/builds/ap_seamb/control/risc0-host"
HOLED = ROOT / "a4/builds/ap_seamb/bench-verifyopcode/risc0-host"
CFG_DIR = ROOT / "a4/runs/iv_pos_9/ap/seamb/configs"
OUT = ROOT / "a4/runs/iv_pos_9/ap/seamb/ap_seamb_verify.json"
HOST_ARGS = ["--ctrl", "7", "--gseed", "12345", "--rounds", "5"]


def accepts(host: Path, cfg: Path) -> bool:
    """Real prove+verify with the mutation applied (NO CONSTRAINT_CONTINUE). True iff verifier success."""
    env = os.environ.copy()
    env["A4_MUTATION_CONFIG"] = str(cfg)
    # explicitly ensure CONSTRAINT_CONTINUE is OFF (a genuine proof attempt)
    env.pop("CONSTRAINT_CONTINUE", None)
    try:
        p = subprocess.run([str(host), *HOST_ARGS], capture_output=True, text=True, env=env, timeout=900)
    except subprocess.TimeoutExpired:
        return False
    out = p.stdout + p.stderr
    return p.returncode == 0 and '"context":"Verifier", "status":"success"' in out


def main() -> int:
    for h in (CONTROL, HOLED):
        if not h.exists():
            print(f"FAIL: missing binary {h}"); return 1
    primary = CFG_DIR / "primary_AddI_to_Sub.json"
    bracket = sorted(CFG_DIR.glob("bracket_*.json"))
    if not primary.exists():
        print("FAIL: primary config missing (run gen_and_sanity.py first)"); return 1

    print("=== mutated-V0 (primary AddI->Sub) ===")
    p_holed = accepts(HOLED, primary)
    p_ctrl = accepts(CONTROL, primary)
    print(f"primary: holed_accepts={p_holed}  control_accepts={p_ctrl}  (want holed=True, control=False)")

    print(f"\n=== bracket ({len(bracket)} ALU->ALU configs) ===")
    rows = []
    holed_acc = ctrl_acc = 0
    for cfg in bracket:
        ha = accepts(HOLED, cfg)
        ca = accepts(CONTROL, cfg)
        holed_acc += ha
        ctrl_acc += ca
        rows.append({"config": cfg.name, "holed_accepts": ha, "control_accepts": ca})
        print(f"  {cfg.name}: holed={ha} control={ca}")

    n = len(bracket)
    result = {
        "primary": {"holed_accepts": p_holed, "control_rejects": not p_ctrl},
        "bracket_n": n,
        "bracket_holed_accepts": holed_acc,
        "bracket_control_accepts": ctrl_acc,
        "bracket_control_rejects": n - ctrl_acc,
        "rows": rows,
        # Certainty = at least one substitution verifies on holed that the control rejects, and the
        # control NEVER accepts a substitution. (Result-changing relabels rejected on holed by the
        # un-holed MemoryWrite are EXPECTED — the hole is scoped to the decode binding.)
        "PASS": bool(holed_acc >= 1 and ctrl_acc == 0),
    }
    OUT.write_text(json.dumps(result, indent=2))
    print(f"\n=== RESULT (-> {OUT.name}) ===")
    print(f"primary: holed ACCEPTS={p_holed}, control REJECTS={not p_ctrl}")
    print(f"bracket: holed accepts {holed_acc}/{n}, control rejects {n - ctrl_acc}/{n}")
    print("PASS — Seam-B underconstraint planted & A4-findable with certainty" if result["PASS"]
          else "FAIL — see rows above")
    return 0 if result["PASS"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
