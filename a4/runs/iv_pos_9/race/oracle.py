#!/usr/bin/env python3
"""Seam-B race bug oracle (IV_POS_9_A3_SEAMB_RACE_SPEC §2).

Classifies a campaign run-DB's accepts as `planted_bug_find` / `non_planted_accept`
(+ the control-confirmation locus check). Two correctness rules baked in:

  - F10: the A4 (cli) accept signal is the `mutations.verifier_accepted` COLUMN, NOT
    `config_json.soundness_signal` (Arguzz-only). Reusing D2.H `extract_accepts`
    verbatim would report A4=0. We query the column.
  - §2.3: a confirmed planted find requires the CONTROL to reject the *identical*
    mutation specifically at `VerifyOpcode*` (LOCUS parsed via CONSTRAINT_CONTINUE=1),
    not merely "control rejected".

The control-check is pluggable (`control_check_fn`) so the classification LOGIC is
unit-testable without running any binary. The control binary is fingerprint-guarded
(G-CTRL) before its rejects are trusted.
"""
from __future__ import annotations

import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Callable, Dict, List, Optional

ROOT = Path("/root/arguzz")
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from a4.core.constraint_parser import parse_all_constraint_failures  # noqa: E402
from a4.pos.fingerprint_guard import assert_fingerprint  # noqa: E402

VERIFYOPCODE = "VerifyOpcode"
DEFAULT_HOST_ARGS = ["--ctrl", "7", "--gseed", "12345", "--rounds", "5"]

# verdicts
FIND = "planted_bug_find"           # ITM decode-divergent, holed-accept, control reject @ VerifyOpcode
NON_PLANTED = "non_planted_accept"  # holed-accept but not the planted decode bug (benign/no-op or other)
UNEXPECTED = "unexpected_itm_unrejected"  # ITM decode-divergent accept that control did NOT reject @ VerifyOpcode


# ---------------------------------------------------------------------------
# Pure logic (unit-testable, no binary)
# ---------------------------------------------------------------------------
def extract_accepts(db_path: str) -> List[Dict]:
    """Accepts = applied mutations with verifier_accepted COLUMN = 1 (F10).

    Generalizes D2.H propagation_triage.extract_accepts (which filters on the
    Arguzz-only config_json.soundness_signal) to the universal column.
    """
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute(
            "SELECT id, kind, config_json FROM mutations "
            "WHERE outcome='applied' AND verifier_accepted=1 ORDER BY id"
        ).fetchall()
    finally:
        con.close()
    out = []
    for mid, kind, cfg_json in rows:
        try:
            cfg = json.loads(cfg_json) if cfg_json else {}
        except json.JSONDecodeError:
            cfg = {}
        out.append({"id": mid, "kind": kind, "config": cfg})
    return out


def is_decode_divergent_itm(accept: Dict) -> bool:
    """True iff an INSTR_TYPE_MOD whose claimed (major,minor) differs from the word's
    original decode — i.e. a genuine decode violation (the planted-bug surface)."""
    if accept.get("kind") != "INSTR_TYPE_MOD":
        return False
    cfg = accept.get("config", {})
    info = cfg.get("_info", {})
    mutated = (cfg.get("major"), cfg.get("minor"))
    original = (info.get("original_major"), info.get("original_minor"))
    if None in mutated or None in original:
        return False
    return mutated != original


def loc_is_verifyopcode(control_output: str) -> bool:
    """LOCUS check (§2.3): did the control fail at VerifyOpcode* specifically?"""
    fails = parse_all_constraint_failures(control_output)
    return any(VERIFYOPCODE in (f.loc or "") for f in fails)


# ---------------------------------------------------------------------------
# Control execution (the real checker; mockable)
# ---------------------------------------------------------------------------
def run_control_replay(
    control_host: str, config: Dict, host_args: Optional[List[str]] = None, timeout: float = 600.0
) -> str:
    """Replay the exact mutation on the control with CONSTRAINT_CONTINUE=1; return combined output."""
    cfg = {k: v for k, v in config.items() if k != "soundness_signal"}
    env = dict(os.environ)
    env["CONSTRAINT_CONTINUE"] = "1"
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump(cfg, fh)
        cfg_path = fh.name
    env["A4_MUTATION_CONFIG"] = cfg_path
    try:
        proc = subprocess.run(
            [str(control_host), *(host_args or DEFAULT_HOST_ARGS)],
            env=env, capture_output=True, text=True, timeout=timeout,
        )
        return proc.stdout + proc.stderr
    finally:
        os.unlink(cfg_path)


def make_control_checker(control_host: str, host_args: Optional[List[str]] = None) -> Callable[[Dict], bool]:
    """Returns control_check_fn(config) -> (control rejects this mutation at VerifyOpcode*)."""
    def _check(config: Dict) -> bool:
        return loc_is_verifyopcode(run_control_replay(control_host, config, host_args))
    return _check


def guard_control(control_host: str, head_sha: Optional[str], guest_id: Optional[List[int]]) -> None:
    """G-CTRL: the control's rejects are ground truth -> assert its provenance first."""
    ok, msg, _ = assert_fingerprint(
        control_host, expect_load_rs2=1, expect_planted_bug="none",
        expect_head_sha=head_sha, expect_guest_id=guest_id,
    )
    if not ok:
        raise RuntimeError(f"CONTROL binary fingerprint guard FAILED (G-CTRL): {msg}")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def classify_run(
    db_path: str,
    control_check_fn: Callable[[Dict], bool],
    *,
    confirm_itm: bool = True,
) -> List[Dict]:
    """Classify every accept. Returns [{id, kind, verdict}, ...] ordered by mutation id.

    - ITM decode-divergent accept -> control-confirm @ VerifyOpcode (FIND) else UNEXPECTED.
      (Fast-path: control-reject is guaranteed for these by construction — F8 — so
       confirm_itm=False trusts the construction and skips the re-run for speed.)
    - any other accept -> NON_PLANTED (benign/no-op; a sample SHOULD be spot-checked
      separately to catch surprise soundness signals, but it is not a planted find).
    """
    results = []
    for a in extract_accepts(db_path):
        if is_decode_divergent_itm(a):
            if confirm_itm:
                verdict = FIND if control_check_fn(a["config"]) else UNEXPECTED
            else:
                verdict = FIND  # by construction (F8)
        else:
            verdict = NON_PLANTED
        results.append({"id": a["id"], "kind": a["kind"], "verdict": verdict})
    return results


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("db", help="campaign run DB (run on the bug binary)")
    p.add_argument("--control", required=True, help="control risc0-host (planted_bug=none)")
    p.add_argument("--head-sha", default=None)
    p.add_argument("--guest-id", default=None, help="comma-separated expected guest_image_id")
    p.add_argument("--no-confirm", action="store_true", help="trust F8 construction; skip control re-runs")
    p.add_argument("--out", default=None, help="write classification JSON here")
    a = p.parse_args()
    gid = [int(x) for x in a.guest_id.split(",")] if a.guest_id else None
    guard_control(a.control, a.head_sha, gid)
    checker = make_control_checker(a.control)
    res = classify_run(a.db, checker, confirm_itm=not a.no_confirm)
    n_find = sum(1 for r in res if r["verdict"] == FIND)
    n_unexp = sum(1 for r in res if r["verdict"] == UNEXPECTED)
    summary = {"db": a.db, "n_accepts": len(res), "n_planted_find": n_find,
               "n_unexpected": n_unexp, "rows": res}
    if a.out:
        Path(a.out).write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("n_accepts", "n_planted_find", "n_unexpected")}))
    if n_unexp:
        print(f"WARNING: {n_unexp} ITM accepts not rejected@VerifyOpcode on control — investigate", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
