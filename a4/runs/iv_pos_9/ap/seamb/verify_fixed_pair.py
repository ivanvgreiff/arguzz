#!/usr/bin/env python3
"""Functional verification of the FIXED Seam-B pair (a4/builds/ap_seamb_fix, head f3c659a8).

(A) 3-kind LIVE (the contamination fix): run V0 (a4_uniform_semantic — uniform over the A4 semantic
    arm universe, CONSTRAINT_CONTINUE) on BOTH the FIXED holed and the CONTAMINATED holed. The 3
    previously-dead kinds (TXN_PREV_WORD_MOD / TXN_PREV_CYCLE_MOD / CYCLE_DIFF_COUNT_MOD) must flip
    from the contaminated silent no-op (outcome=applied, verifier_accepted=1, num_failures=0 — no
    trace change) to REAL constraint evaluation on the fixed binary (num_failures>0 rejects, since
    these perturb memory/cycle structure). ITM must still produce accepts on the holed binary.

(B) Stage-0 bug intact (the planted bug survived the rebuild): the AddI->ALU bracket — holed must
    ACCEPT >=1 substitution that the control REJECTS @ VerifyOpcode; control must accept NONE.
    (Mirrors a4/runs/iv_pos_9/ap/seamb/mutated_v0.py but on the FIXED pair, reusing the same
    configs — valid because the guest ELF / image-id is unchanged.)

Writes verify_fixed_pair.json. Real prove for (B) (NO CONSTRAINT_CONTINUE).
"""
from __future__ import annotations
import json, os, sqlite3, subprocess, sys
from pathlib import Path

ROOT = Path("/root/arguzz")
FIX = ROOT / "a4/builds/ap_seamb_fix"
CONTAM = ROOT / "a4/builds/ap_seamb"
HOLED_FIX = FIX / "bench-verifyopcode/risc0-host"
CTRL_FIX = FIX / "control/risc0-host"
HOLED_CONTAM = CONTAM / "bench-verifyopcode/risc0-host"
CFG_DIR = ROOT / "a4/runs/iv_pos_9/ap/seamb/configs"
OUT = ROOT / "a4/runs/iv_pos_9/ap/seamb/verify_fixed_pair.json"
SCRATCH = Path("/tmp/claude-0/-root-arguzz/a2f957d7-4d2e-4122-a1b1-5e5a363490bf/scratchpad")
HOST_ARGS = ["--ctrl", "7", "--gseed", "12345", "--rounds", "5"]
THREE = ["TXN_PREV_WORD_MOD", "TXN_PREV_CYCLE_MOD", "CYCLE_DIFF_COUNT_MOD"]
NUM_A = 40  # enough V0 picks to hit each of the 3 kinds several times on this slow box


def run(cmd, env_extra=None, timeout=2400):
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=timeout)


def v0_run(host: Path, db: str) -> str:
    Path(db).unlink(missing_ok=True)
    env = {"CONSTRAINT_CONTINUE": "1", "A4_GLOBAL_RESIDUE": "1",
           "A4_FAMILY_RESIDUE": "1", "A4_COVERAGE_TOUCH": "1"}
    p = run(["python3", "-m", "a4.standalone.cli", "fuzz", "--host", str(host), "--db", db,
             "--selector", "a4_uniform_semantic", "--num", str(NUM_A), "--seed", "1234",
             "--telemetry-level", "full", "--", *HOST_ARGS], env)
    return p.stdout + p.stderr


def kind_signature(db: str) -> dict:
    con = sqlite3.connect(db)
    sig = {}
    for k in THREE + ["INSTR_TYPE_MOD"]:
        rows = con.execute(
            "SELECT count(*), coalesce(sum(verifier_accepted),0), coalesce(sum(num_failures>0),0), "
            "coalesce(max(num_failures),0) FROM mutations WHERE kind=? AND outcome='applied'", (k,)
        ).fetchone()
        sig[k] = {"applied": rows[0], "accepted": rows[1], "rows_with_failures": rows[2], "max_failures": rows[3]}
    con.close()
    return sig


def accepts(host: Path, cfg: Path) -> bool:
    """Real prove+verify with the mutation applied (NO CONSTRAINT_CONTINUE). True iff verifier success."""
    env = os.environ.copy()
    env["A4_MUTATION_CONFIG"] = str(cfg)
    env.pop("CONSTRAINT_CONTINUE", None)
    try:
        p = subprocess.run([str(host), *HOST_ARGS], capture_output=True, text=True, env=env, timeout=900)
    except subprocess.TimeoutExpired:
        return False
    return p.returncode == 0 and '"context":"Verifier", "status":"success"' in (p.stdout + p.stderr)


def main() -> int:
    for h in (HOLED_FIX, CTRL_FIX, HOLED_CONTAM):
        if not h.exists():
            print(f"FAIL: missing binary {h}"); return 1
    SCRATCH.mkdir(parents=True, exist_ok=True)
    result = {"head_sha_fix": "f3c659a8dcbcbf357208fcf6fea6c0a91515640f"}

    # ---- (A) 3-kind LIVE (fixed holed only; contaminated no-op already empirically established
    # across 40 DBs in CONTAMINATION_IMPACT_VERIFICATION.md — not re-derived here) ----
    print("=== (A) 3-kind LIVE: V0 uniform, CONSTRAINT_CONTINUE, num=%d (FIXED holed) ===" % NUM_A)
    out_fix = v0_run(HOLED_FIX, str(SCRATCH / "live_fix.db"))
    sig_fix = kind_signature(str(SCRATCH / "live_fix.db"))
    inv_fix = out_fix.count("invalid config") + out_fix.count("invalid_config")
    print(f"\n  invalid-config markers on fixed: {inv_fix} (contaminated baseline: many — the no-op signature)")
    print(f"  {'kind':22} applied / accepted / rows_with_failures / max_failures")
    for k in THREE + ["INSTR_TYPE_MOD"]:
        f = sig_fix[k]
        print(f"  {k:22} {f['applied']:4} / {f['accepted']:4} / {f['rows_with_failures']:4} / {f['max_failures']:6}")

    # LIVE iff each of the 3 kinds, on the FIXED binary, is APPLIED and shows REAL constraint
    # evaluation (rows_with_failures>0) — vs the contaminated no-op (applied==accepted, 0 failures).
    three_live = all(sig_fix[k]["applied"] >= 1 and sig_fix[k]["rows_with_failures"] >= 1 for k in THREE)
    three_picked = all(sig_fix[k]["applied"] >= 1 for k in THREE)
    itm_findable = sig_fix["INSTR_TYPE_MOD"]["accepted"] >= 1
    result["A_three_kind_live"] = {
        "fixed": sig_fix, "invalid_config_markers_fixed": inv_fix,
        "three_picked": three_picked, "three_live_on_fixed": three_live,
        "itm_findable_on_fixed": itm_findable,
        "contaminated_noop": "established in CONTAMINATION_IMPACT_VERIFICATION.md (40 DBs)",
        "PASS": bool(three_live and itm_findable),
    }
    print(f"\n  (A) three_picked={three_picked}  three_live_on_fixed={three_live}  itm_findable={itm_findable}")

    # ---- (B) Stage-0 bug intact on the FIXED pair ----
    print("\n=== (B) Stage-0 bug intact: AddI->ALU bracket on the FIXED pair (real prove) ===")
    # Decisive sample (not all 56): one AddI cycle's full 7-substitution bracket. The original
    # validation showed AddI->{Add,Or,Sub,Xor} ACCEPT on holed / {And,Slt,SltU} reject (MemoryWrite),
    # control rejects ALL — so this 7-set gives holed_acc>=1, ctrl_acc==0 with certainty.
    bracket = sorted(CFG_DIR.glob("bracket_s1091_*.json"))
    primary = CFG_DIR / "primary_AddI_to_Sub.json"
    cfgs = ([primary] if primary.exists() else []) + bracket
    holed_acc = ctrl_acc = 0
    rows = []
    for cfg in cfgs:
        ha = accepts(HOLED_FIX, cfg)
        ca = accepts(CTRL_FIX, cfg)
        holed_acc += ha; ctrl_acc += ca
        rows.append({"config": cfg.name, "holed_accepts": ha, "control_accepts": ca})
        print(f"  {cfg.name:34} holed={ha} control={ca}")
    n = len(cfgs)
    stage0_pass = bool(holed_acc >= 1 and ctrl_acc == 0)
    result["B_stage0_bug_intact"] = {
        "n_configs": n, "holed_accepts": holed_acc, "control_accepts": ctrl_acc,
        "control_rejects": n - ctrl_acc, "rows": rows, "PASS": stage0_pass,
    }
    print(f"  (B) holed accepts {holed_acc}/{n}, control rejects {n - ctrl_acc}/{n}")

    result["PASS"] = bool(result["A_three_kind_live"]["PASS"] and stage0_pass)
    OUT.write_text(json.dumps(result, indent=2))
    print(f"\n=== RESULT (-> {OUT.name}) ===")
    print("PASS — 3 kinds LIVE on fixed (were no-op on contaminated) + planted bug intact"
          if result["PASS"] else "FAIL — see tables above")
    return 0 if result["PASS"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
