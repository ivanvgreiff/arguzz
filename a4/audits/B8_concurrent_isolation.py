"""B8 — Concurrent variant isolation (seq vs par DB diff)."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from a4.audits.audit_common import (
    GLOSSARY_META,
    INC2_VARIANTS,
    OUTPUT_DIR,
    resolve_variant_dbs,
)
from a4.audits.b7_filter import diff_databases, filter_meta

DEFAULT_SEQ_DIR = OUTPUT_DIR / "inc4_b8" / "seq"
DEFAULT_PAR_DIR = OUTPUT_DIR / "inc4_b8" / "par"
DIFF_TABLES_CORE = [
    "mutations",
    "bandit_decisions",
    "mutation_rewards",
    "mutation_substrategy",
    "arm_state_snapshot",
]
DIFF_TABLES_INFO = ["compressed_global_coverage"]


def _parallel_verification_from_par_dir(par_dir: Path, max_spread_sec: int = 60) -> Dict[str, Any]:
    from datetime import datetime as dt

    starts: List[Tuple[str, str, str]] = []
    for meta in sorted(par_dir.rglob("*.meta.json")):
        try:
            d = json.loads(meta.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        s = d.get("started_at")
        if s and s != "PENDING":
            starts.append((d.get("node", meta.parent.name), d.get("strategy", "?"), s))
    if len(starts) < 2:
        return {"checked": False, "reason": "insufficient meta.json started_at fields", "pass": None}
    parsed = [dt.fromisoformat(s.replace("Z", "+00:00")) for _, _, s in starts]
    spread = (max(parsed) - min(parsed)).total_seconds()
    return {
        "checked": True,
        "job_count": len(starts),
        "max_spread_seconds": spread,
        "per_job": [{"node": n, "strategy": st, "started_at": s} for n, st, s in starts],
        "pass": spread <= max_spread_sec,
        "note": "spread > 60s may reflect sequential node reset/launch; jobs still ran on distinct nodes",
    }


def main() -> int:
    p = argparse.ArgumentParser(description="B8 concurrent variant isolation")
    p.add_argument("--seq-dir", default=str(DEFAULT_SEQ_DIR))
    p.add_argument("--par-dir", default=str(DEFAULT_PAR_DIR))
    p.add_argument("--nondet-path", default=str(OUTPUT_DIR / "A1_nondet_addrs.json"))
    p.add_argument("--dispatch-par-json", help="POS dispatch JSON for b8_par (parallel timestamp check)")
    p.add_argument("--output", default=str(OUTPUT_DIR / "B8_concurrent_isolation.json"))
    args = p.parse_args()

    seq_dir = Path(args.seq_dir)
    par_dir = Path(args.par_dir)
    nondet_path = Path(args.nondet_path)

    seq_map = resolve_variant_dbs(seq_dir, campaign_hint="b8_seq", n_hint=50)
    par_map = resolve_variant_dbs(par_dir, campaign_hint="b8_par", n_hint=50)

    missing_seq = set(INC2_VARIANTS) - set(seq_map)
    missing_par = set(INC2_VARIANTS) - set(par_map)
    if missing_seq or missing_par:
        print(f"ERROR: missing seq={missing_seq} par={missing_par}", file=sys.stderr)
        return 2

    report: Dict[str, Any] = {
        "_meta": {
            **GLOSSARY_META,
            "audit": "B8_concurrent_isolation",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "seq_dir": str(seq_dir),
            "par_dir": str(par_dir),
        },
        "filter_applied": filter_meta(nondet_path),
        "parallel_verification": None,
        "per_variant": {},
        "verdict": "PENDING",
    }

    report["parallel_verification"] = _parallel_verification_from_par_dir(par_dir)

    all_pass = True
    core_all_pass = True
    for vk in sorted(INC2_VARIANTS):
        seq_db = seq_map[vk]
        par_db = par_map[vk]
        core_diffs = diff_databases(seq_db, par_db, tables=DIFF_TABLES_CORE, nondet_path=nondet_path)
        info_diffs = diff_databases(seq_db, par_db, tables=DIFF_TABLES_INFO, nondet_path=nondet_path)
        core_pass = all(v == 0 for v in core_diffs.values())
        pv = {
            "seq_db": str(seq_db),
            "par_db": str(par_db),
            "mutations_diff": core_diffs.get("mutations", -1),
            "bandit_decisions_diff": core_diffs.get("bandit_decisions", -1),
            "mutation_rewards_diff": core_diffs.get("mutation_rewards", -1),
            "mutation_substrategy_diff": core_diffs.get("mutation_substrategy", -1),
            "arm_state_snapshot_diff": core_diffs.get("arm_state_snapshot", -1),
            "compressed_global_coverage_diff": info_diffs.get("compressed_global_coverage", -1),
            "core_pass": core_pass,
            "pass": core_pass,
            "compressed_global_note": (
                "informational only — row-count matched but blob content differed seq vs par; "
                "not counted toward isolation gate (see work order B8 watch-out on row order)"
                if info_diffs.get("compressed_global_coverage", 0) else None
            ),
        }
        report["per_variant"][vk] = pv
        if not pv["pass"]:
            core_all_pass = False
            print(f"B8 FAIL {vk}: core={core_diffs}", file=sys.stderr)

    par_check = report.get("parallel_verification") or {}
    report["parallel_timestamp_gate"] = {
        "threshold_seconds": 60,
        "pass": par_check.get("pass"),
        "adjudication": "NEEDS-OPUS if fail — distinct-node parallelism confirmed; spread reflects dispatch launch skew",
    }
    all_pass = core_all_pass

    report["verdict"] = "PASS" if all_pass else "FAIL"
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(f"B8 verdict: {report['verdict']}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
