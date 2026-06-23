#!/usr/bin/env python3
"""A3.S0 — deterministic ground-truth gate (IV_POS_9_A3_SEAMB_RACE_SPEC §5/§6 test 13).

Validates the FULL oracle->markers pipeline on the REAL binaries with known-answer
data, BEFORE any POS spend (the certainty gate Seam A lacked):
  - guard both binaries (holed=verifyopcode, control=none)  [G-FP / G-CTRL]
  - the 12 certified bracket finds (+ live AddI->OrI) -> all classified planted_bug_find
    (control rejects @ VerifyOpcode, LOCUS-parsed)
  - a no-op (CYCLE_DIFF_COUNT_MOD accept) -> NON_PLANTED (control does NOT reject @ VerifyOpcode)
  - a result-changer (verifier_accepted=0) -> never extracted (not an accept)
  - negative control [G-NEG]: an ITM mutation on the CONTROL binary REJECTS (=> a control
    campaign yields 0 finds)
Run: python a4/runs/iv_pos_9/race/run_stage0.py
"""
from __future__ import annotations

import glob
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path("/root/arguzz")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from a4.runs.iv_pos_9.race import oracle, markers  # noqa: E402

HOLED = ROOT / "a4/builds/ap_seamb/bench-verifyopcode/risc0-host"
CONTROL = ROOT / "a4/builds/ap_seamb/control/risc0-host"
CFG_DIR = ROOT / "a4/runs/iv_pos_9/ap/seamb/configs"
HEAD = "93bda33b4f95f29acc9ddce1e225cdf949c83874"
ARGS = ["--ctrl", "7", "--gseed", "12345", "--rounds", "5"]
# the 12 certified accepters (ap_seamb_verify.json)
CERTIFIED = [f"bracket_s{s}_AddI_to_{t}" for s in (1091, 1829, 2418) for t in ("Add", "Or", "Sub", "Xor")]


def _mk_db(path, rows):
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE mutations (id INTEGER PRIMARY KEY, kind TEXT, step INTEGER, "
                "config_json TEXT, verifier_accepted INTEGER, outcome TEXT)")
    for mid, kind, va, outcome, cfg in rows:
        con.execute("INSERT INTO mutations VALUES (?,?,?,?,?,?)",
                    (mid, kind, 0, json.dumps(cfg), va, outcome))
    con.commit(); con.close()


def _control_accepts(host, cfg):
    """Real prove+verify (no CONSTRAINT_CONTINUE): does the host's verifier succeed?"""
    env = {k: v for k, v in os.environ.items() if k != "CONSTRAINT_CONTINUE"}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(cfg, fh); p = fh.name
    env["A4_MUTATION_CONFIG"] = p
    try:
        out = subprocess.run([str(host), *ARGS], env=env, capture_output=True, text=True, timeout=600)
        return '"context":"Verifier", "status":"success"' in (out.stdout + out.stderr)
    finally:
        os.unlink(p)


def main() -> int:
    fails = []
    print("=== A3.S0: guard both binaries ===")
    oracle.guard_control(str(CONTROL), HEAD, None)
    from a4.pos.fingerprint_guard import assert_fingerprint
    okh, msgh, _ = assert_fingerprint(str(HOLED), expect_load_rs2=1, expect_planted_bug="verifyopcode", expect_head_sha=HEAD)
    print(f"  holed guard: {okh} ({msgh}); control guard: OK")
    if not okh:
        fails.append("holed fingerprint")

    # build a synthetic DB: 12 certified ITM accepts + 1 no-op accept + 1 result-changer reject
    cfgs = {}
    for name in CERTIFIED:
        f = CFG_DIR / f"{name}.json"
        if f.exists():
            cfgs[name] = json.loads(f.read_text())
    print(f"=== loaded {len(cfgs)}/12 certified find configs ===")
    rows = []
    for i, (name, cfg) in enumerate(cfgs.items(), start=1):
        rows.append((i, "INSTR_TYPE_MOD", 1, "applied", cfg))
    noop_cfg = {"mutation_type": "CYCLE_DIFF_COUNT_MOD", "step": 454, "index": 0, "diff_count": 1, "_info": {"original_value": 0, "index": 0}}
    rows.append((100, "CYCLE_DIFF_COUNT_MOD", 1, "applied", noop_cfg))
    rc = CFG_DIR / "bracket_s1091_AddI_to_And.json"
    if rc.exists():
        rows.append((101, "INSTR_TYPE_MOD", 0, "applied", json.loads(rc.read_text())))  # result-changer: holed-reject

    db = tempfile.mktemp(suffix=".db")
    _mk_db(db, rows)

    print("=== classify via oracle with the REAL control checker (LOCUS @ VerifyOpcode) ===")
    checker = oracle.make_control_checker(str(CONTROL))
    res = oracle.classify_run(db, checker, confirm_itm=True)
    finds = [r for r in res if r["verdict"] == oracle.FIND]
    nonp = [r for r in res if r["verdict"] == oracle.NON_PLANTED]
    unexp = [r for r in res if r["verdict"] == oracle.UNEXPECTED]
    print(f"  finds={len(finds)} non_planted={len(nonp)} unexpected={len(unexp)} (of {len(res)} accepts)")
    if len(finds) != len(cfgs):
        fails.append(f"expected {len(cfgs)} planted finds, got {len(finds)}")
    if unexp:
        fails.append(f"{len(unexp)} ITM accepts NOT rejected@VerifyOpcode on control")
    # the no-op (CYCLE_DIFF_COUNT_MOD) must be NON_PLANTED, and the result-changer (va=0) not extracted
    if not any(r["kind"] == "CYCLE_DIFF_COUNT_MOD" and r["verdict"] == oracle.NON_PLANTED for r in res):
        fails.append("no-op not classified NON_PLANTED")
    if any(r["id"] == 101 for r in res):
        fails.append("result-changer (verifier_accepted=0) was extracted as an accept")

    print("=== markers on the find DB ===")
    find_ids = [r["id"] for r in finds]
    m = markers.per_run_markers(db, find_ids, n_planned=200)
    print(f"  found={m['found']} first_find_idx={m['first_find_idx']} n_finds={m['n_finds']} "
          f"cond_density={m['conditional_find_density']}")
    if not (m["found"] and m["n_finds"] == len(cfgs)):
        fails.append("markers n_finds mismatch")
    os.unlink(db)

    print("=== G-NEG: an ITM mutation on the CONTROL binary REJECTS (control campaign -> 0 finds) ===")
    itm_cfg = next(iter(cfgs.values()))
    ctrl_accepts = _control_accepts(str(CONTROL), itm_cfg)
    print(f"  control accepts the ITM mutation: {ctrl_accepts} (must be False)")
    if ctrl_accepts:
        fails.append("control ACCEPTED an ITM mutation (negative control breached)")

    print()
    if fails:
        print("A3.S0 FAIL:"); [print("  -", f) for f in fails]
        return 1
    print("A3.S0 PASS — oracle+markers validated on known-answer data; ready for A3.2 (POS smoke).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
